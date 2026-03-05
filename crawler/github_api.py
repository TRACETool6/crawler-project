"""
GitHub API client with caching (ETag + SQLite), rate limiting, and snapshot resolution.
"""
import json
import logging
import time
import random
import requests
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

try:
    from config import save_crawler_state, load_crawler_state, GITHUB_TOKEN, CRAWLED_DB_PATH
except ImportError:
    GITHUB_TOKEN = None
    CRAWLED_DB_PATH = "crawler_db.sqlite"
    def save_crawler_state(*args, **kwargs): pass
    def load_crawler_state(): return None, None

from time_window import select_closest_commit

REQUEST_TIMEOUT = 30
MAX_RETRIES = 4
BACKOFF_BASE = 2
RATE_LIMIT_JITTER = 5

def _headers():
    h = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"token {GITHUB_TOKEN}"
    return h


def _get_api_cache(key: str) -> Optional[Tuple[str, str]]:
    """Return (etag, response_json) or None."""
    try:
        import sqlite3
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT etag, response_json FROM ApiCache WHERE key = ?", (key,))
        row = c.fetchone()
        conn.close()
        if row:
            return (row[0] or "", row[1])
    except Exception as e:
        logging.debug(f"ApiCache get error: {e}")
    return None


def _set_api_cache(key: str, etag: Optional[str], response_json: str):
    try:
        import sqlite3
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO ApiCache (key, etag, response_json, fetched_at) VALUES (?, ?, ?, ?)",
            (key, etag or "", response_json, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.debug(f"ApiCache set error: {e}")


def _get_commit_cache(repo_key: str, branch: str, start_date: str, end_date: str) -> Optional[List[Dict]]:
    try:
        import sqlite3
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute(
            "SELECT commits_json FROM CommitCache WHERE repo_owner_repo = ? AND branch = ? AND start_date = ? AND end_date = ?",
            (repo_key, branch, start_date, end_date)
        )
        row = c.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception as e:
        logging.debug(f"CommitCache get error: {e}")
    return None


def _set_commit_cache(repo_key: str, branch: str, start_date: str, end_date: str, commits: List[Dict]):
    try:
        import sqlite3
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute(
            """INSERT OR REPLACE INTO CommitCache (repo_owner_repo, branch, start_date, end_date, commits_json, fetched_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (repo_key, branch, start_date, end_date, json.dumps(commits), datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.debug(f"CommitCache set error: {e}")


def _handle_rate_limit(resp: requests.Response) -> bool:
    """If rate limited, sleep until reset and return True. Otherwise return False."""
    remaining = resp.headers.get("X-RateLimit-Remaining")
    reset = resp.headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset:
        try:
            reset_ts = int(reset)
            sleep_sec = max(1, reset_ts - int(time.time()) + random.randint(0, RATE_LIMIT_JITTER))
            logging.warning(f"GitHub rate limit hit; sleeping until reset ({sleep_sec}s)")
            time.sleep(sleep_sec)
            return True
        except (ValueError, TypeError):
            time.sleep(60)
            return True
    return False


def _api_get(url: str, cache_key: Optional[str] = None, use_etag: bool = True) -> Optional[Dict]:
    """
    GET with optional cache (ETag). Returns parsed JSON or None.
    Uses cache_key for ApiCache; if use_etag, sends If-None-Match and stores 200 response.
    """
    etag = None
    if cache_key and use_etag:
        cached = _get_api_cache(cache_key)
        if cached:
            etag, stored = cached
            if stored:
                # We always return fresh if we need to; caller can pass use_etag=False to skip cache
                pass
    headers = _headers()
    if etag:
        headers["If-None-Match"] = etag
    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if r.status_code == 304 and cache_key and use_etag:
                cached = _get_api_cache(cache_key)
                if cached and cached[1]:
                    return json.loads(cached[1])
            if r.status_code == 403 and _handle_rate_limit(r):
                continue
            if r.status_code in (502, 503, 504):
                time.sleep(BACKOFF_BASE ** attempt + random.uniform(0, 2))
                continue
            r.raise_for_status()
            data = r.json()
            if cache_key and use_etag and r.status_code == 200:
                _set_api_cache(cache_key, r.headers.get("ETag"), r.text)
            return data
        except requests.exceptions.Timeout:
            logging.warning(f"Timeout on {url} (attempt {attempt + 1})")
            time.sleep(BACKOFF_BASE ** attempt)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403 and _handle_rate_limit(e.response):
                continue
            if e.response.status_code == 404:
                return None
            logging.error(f"GitHub API HTTP error {e.response.status_code}: {url}")
            raise
        except (json.JSONDecodeError, requests.exceptions.RequestException) as e:
            logging.warning(f"Request error {url}: {e}")
            time.sleep(BACKOFF_BASE ** attempt)
    return None


def fetch_repo_metadata(owner: str, repo: str) -> Optional[Dict]:
    """Fetch repo metadata (GET /repos/{owner}/{repo}) with cache."""
    url = f"https://api.github.com/repos/{owner}/{repo}"
    return _api_get(url, cache_key=f"repo:{owner}/{repo}")


def fetch_repo_topics(owner: str, repo: str) -> List[str]:
    url = f"https://api.github.com/repos/{owner}/{repo}/topics"
    h = _headers()
    h["Accept"] = "application/vnd.github.mercy-preview+json"
    try:
        r = requests.get(url, headers=h, timeout=REQUEST_TIMEOUT)
        if r.status_code == 403:
            _handle_rate_limit(r)
        r.raise_for_status()
        return r.json().get("names", [])
    except Exception as e:
        logging.debug(f"Topics fetch error: {e}")
    return []


def fetch_all_metadata(owner: str, repo: str) -> Optional[Dict]:
    logging.info(f"Fetching repository metadata for {owner}/{repo}")
    data = fetch_repo_metadata(owner, repo)
    if data:
        data["topics"] = fetch_repo_topics(owner, repo)
    return data


def fetch_commits_in_window(
    owner: str,
    repo: str,
    sha: str,
    since: str,
    until: str,
    use_commit_cache: bool = True,
) -> List[Dict]:
    """Fetch commits on branch sha between since and until (ISO date). Paginates and optionally caches."""
    repo_key = f"{owner}/{repo}"
    if use_commit_cache:
        cached = _get_commit_cache(repo_key, sha, since, until)
        if cached is not None:
            return cached
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    all_commits = []
    page = 1
    per_page = 100
    while True:
        from urllib.parse import urlencode
        params = {"sha": sha, "since": since, "until": until, "per_page": per_page, "page": page}
        full_url = f"{url}?{urlencode(params)}"
        data = _api_get(full_url, cache_key=None, use_etag=False)
        if not data:
            break
        items = data if isinstance(data, list) else data.get("items", [])
        if not items:
            break
        all_commits.extend(items)
        if len(items) < per_page:
            break
        page += 1
        time.sleep(0.5)
    if use_commit_cache and all_commits:
        _set_commit_cache(repo_key, sha, since, until, all_commits)
    return all_commits


def resolve_snapshot_sha(
    owner: str,
    repo: str,
    target_date: datetime,
    start_date: datetime,
    end_date: datetime,
    is_seed: bool = False,
) -> Tuple[Optional[str], Optional[str], str]:
    """
    Resolve the best snapshot SHA for a repo in the time window.
    Returns (sha, commit_date_iso, reason).
    reason: 'commit_in_window', 'default_branch', 'seed_fallback'.
    """
    meta = fetch_repo_metadata(owner, repo)
    if not meta:
        return None, None, "default_branch"
    default_branch = meta.get("default_branch") or "main"
    since_str = start_date.strftime("%Y-%m-%dT00:00:00Z")
    until_str = end_date.strftime("%Y-%m-%dT23:59:59Z")
    commits = fetch_commits_in_window(owner, repo, default_branch, since_str, until_str)
    if commits:
        closest = select_closest_commit(commits, target_date)
        if closest:
            sha = closest.get("sha")
            commit = closest.get("commit", {})
            committer = commit.get("committer", {})
            date_str = committer.get("date")
            return sha, date_str, "commit_in_window"
    if is_seed:
        ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{default_branch}"
        ref_data = _api_get(ref_url, cache_key=None)
        if ref_data and ref_data.get("object", {}).get("sha"):
            return ref_data["object"]["sha"], None, "seed_fallback"
    ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{default_branch}"
    ref_data = _api_get(ref_url, cache_key=None)
    if ref_data and ref_data.get("object", {}).get("sha"):
        return ref_data["object"]["sha"], None, "default_branch"
    return None, None, "default_branch"


SEARCH_API = "https://api.github.com/search/repositories"
SUPPORTED_LANGUAGES = ['Python', 'JavaScript', 'Go', 'TypeScript', 'Java', 'C', 'C++', 'Ruby', 'PHP', 'Rust']


def get_repo_batch(seen_repos, limit, languages=None):
    """
    Fetches a batch of repositories from GitHub, excluding those already seen.
    Uses time-based search and saves state for resumption.
    """
    if languages is None:
        languages = SUPPORTED_LANGUAGES
    logging.info(f"API Fetcher: Attempting to fetch a batch of up to {limit} new repositories.")
    repos = []
    last_crawled_date, last_crawled_page = load_crawler_state()
    if last_crawled_date:
        current_date = last_crawled_date
        initial_page = last_crawled_page
    else:
        current_date = datetime.now()
        initial_page = 1
    time_slice_days = 30
    historical_limit_date = datetime(current_date.year - 5, current_date.month, current_date.day)

    while len(repos) < limit and current_date > historical_limit_date:
        end_date_str = current_date.strftime('%Y-%m-%d')
        start_date = current_date - __import__("datetime").timedelta(days=time_slice_days)
        start_date_str = start_date.strftime('%Y-%m-%d')
        time_query = f"created:{start_date_str}..{end_date_str}"
        language_query = " ".join([f"language:{lang}" for lang in languages])
        full_query = f"{time_query} {language_query}"
        page = initial_page
        per_page = 100
        while True:
            params = {"q": full_query, "sort": "updated", "order": "desc", "per_page": per_page, "page": page}
            try:
                r = requests.get(SEARCH_API, headers=_headers(), params=params, timeout=REQUEST_TIMEOUT)
                if r.status_code == 403 and _handle_rate_limit(r):
                    continue
                r.raise_for_status()
                items = r.json().get("items", [])
                if not items:
                    save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                    break
                for item in items:
                    full_name = item.get("full_name")
                    if full_name and full_name not in seen_repos:
                        repos.append(full_name)
                    if len(repos) >= limit:
                        save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                        return repos[:limit]
                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                if len(items) < per_page:
                    break
                page += 1
            except Exception as e:
                logging.error(f"API Fetcher error: {e}")
                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                break
        initial_page = 1
        current_date = start_date - __import__("datetime").timedelta(days=1)
        save_crawler_state(current_date.strftime('%Y-%m-%d'), initial_page)
    return repos[:limit]


def search_repos_time_window(
    keywords: List[str],
    start_date: str,
    end_date: str,
    seen_repos: set,
    limit: int,
    strict_time_filter: bool,
) -> List[str]:
    """
    Search repos by keywords with created date in [start_date, end_date].
    Returns list of full_name. strict_time_filter: if True, only include repos in window (we still need to verify with qualifies_in_window when we have metadata).
    """
    repos = []
    query = " OR ".join(keywords) if keywords else "0day exploit"
    time_query = f"created:{start_date}..{end_date}"
    full_query = f"{query} {time_query}"
    page = 1
    per_page = 100
    while len(repos) < limit:
        params = {"q": full_query, "sort": "updated", "order": "desc", "per_page": per_page, "page": page}
        try:
            r = requests.get(SEARCH_API, headers=_headers(), params=params, timeout=REQUEST_TIMEOUT)
            if r.status_code == 403:
                _handle_rate_limit(r)
                continue
            r.raise_for_status()
            items = r.json().get("items", [])
            if not items:
                break
            for item in items:
                full_name = item.get("full_name")
                if full_name and full_name not in seen_repos:
                    repos.append(full_name)
                if len(repos) >= limit:
                    return repos[:limit]
            page += 1
            time.sleep(0.3)
        except Exception as e:
            logging.error(f"Search error: {e}")
            break
    return repos[:limit]

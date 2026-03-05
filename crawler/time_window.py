"""
Time-window and seed helpers for the crawler.
Unit-testable: parse_seeds, qualifies_in_window, select_closest_commit.
"""
import os
import logging
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)


def parse_seeds(seed_file_path: Optional[str] = None, seed_repos_str: Optional[str] = None) -> List[str]:
    """
    Parse seed repos from a file and/or comma-separated string.
    Returns a list of normalized 'owner/repo' strings (no duplicates, no empty).
    """
    seen = set()
    result = []
    if seed_file_path and os.path.isfile(seed_file_path):
        try:
            with open(seed_file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    full = line.strip().split("#")[0].strip()
                    if full and "/" in full:
                        full = _normalize_repo(full)
                        if full and full not in seen:
                            seen.add(full)
                            result.append(full)
        except OSError as e:
            logging.warning(f"Could not read seed file {seed_file_path}: {e}")
    if seed_repos_str:
        for part in seed_repos_str.split(","):
            full = part.strip()
            if full and "/" in full:
                full = _normalize_repo(full)
                if full and full not in seen:
                    seen.add(full)
                    result.append(full)
    return result


def _normalize_repo(full_name: str) -> str:
    """Normalize to owner/repo (lowercase, no extra slashes)."""
    parts = full_name.strip().strip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[0].strip()}/{parts[1].strip()}"
    return full_name.strip()


def qualifies_in_window(
    repo_metadata: Dict[str, Any],
    start_date: datetime,
    end_date: datetime,
    commits_in_window: Optional[List[Dict]] = None,
) -> Tuple[bool, str]:
    """
    Determine if a repo qualifies for the time window.
    repo_metadata: dict with created_at, pushed_at (GitHub API format).
    commits_in_window: optional list of commits already fetched for the window.
    Returns (qualified, reason) where reason is one of:
    'created_at', 'pushed_at', 'commit_in_window', 'none'.
    """
    if not repo_metadata:
        return False, "none"
    created = repo_metadata.get("created_at")
    pushed = repo_metadata.get("pushed_at")
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            dt_naive = dt.replace(tzinfo=None) if dt.tzinfo else dt
            if start_date <= dt_naive <= end_date:
                return True, "created_at"
        except (ValueError, TypeError):
            pass
    if pushed:
        try:
            dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
            dt_naive = dt.replace(tzinfo=None) if dt.tzinfo else dt
            if start_date <= dt_naive <= end_date:
                return True, "pushed_at"
        except (ValueError, TypeError):
            pass
    if commits_in_window and len(commits_in_window) > 0:
        return True, "commit_in_window"
    return False, "none"


def select_closest_commit(
    commits: List[Dict],
    target_date: datetime,
) -> Optional[Dict]:
    """
    From a list of commits (each with 'commit' or top-level 'commit' and 'sha'),
    return the commit whose commit date is closest to target_date.
    commits: list of GitHub API commit objects (e.g. from /repos/.../commits).
    """
    if not commits:
        return None
    best = None
    best_delta = None
    for c in commits:
        commit = c.get("commit") if isinstance(c.get("commit"), dict) else c
        if not commit:
            continue
        committer = commit.get("committer") or {}
        date_str = committer.get("date")
        if not date_str:
            continue
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            dt_naive = dt.replace(tzinfo=None) if dt.tzinfo else dt
            delta = abs((target_date - dt_naive).total_seconds())
            if best_delta is None or delta < best_delta:
                best_delta = delta
                best = c
        except (ValueError, TypeError):
            continue
    return best

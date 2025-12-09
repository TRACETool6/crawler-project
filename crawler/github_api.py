import requests
import logging
import json
from datetime import datetime, timedelta

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

try:
    from config import save_crawler_state, load_crawler_state, GITHUB_TOKEN
except ImportError:
    logging.error("Could not import save_crawler_state or load_crawler_state from config.py.")
    def save_crawler_state(date_str, page):
        logging.warning("Dummy save_crawler_state called. State will not be persisted.")
    def load_crawler_state():
        logging.warning("Dummy load_crawler_state called. No state will be loaded.")
        return None, None

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

SEARCH_API = "https://api.github.com/search/repositories"

SUPPORTED_LANGUAGES = ['Python', 'JavaScript', 'Go', 'TypeScript', 'Java', 'C', 'C++', 'Ruby', 'PHP', 'Rust']

def get_repo_batch(seen_repos, limit, languages=None):
    """
    Fetches a batch of repositories from GitHub, excluding those already seen.
    It iterates through time periods and pages within each period, saving its state
    to allow for resumption. This function acts as the 'API Fetcher' component.

    Args:
        seen_repos (set): A set of full repository names (e.g., 'owner/repo')
                          that have already been crawled.
        limit (int): The maximum number of new repositories to fetch in this batch.
        languages (list): Optional list of programming languages to filter by.

    Returns:
        list: A list of full repository names (strings) up to the specified limit.
    """
    if languages is None:
        languages = SUPPORTED_LANGUAGES
    logging.info(f"API Fetcher: Attempting to fetch a batch of up to {limit} new repositories by iterating through time.")
    logging.info(f"API Fetcher: Filtering for languages: {', '.join(languages)}")
    repos = []
    
    last_crawled_date, last_crawled_page = load_crawler_state()

    if last_crawled_date:
        current_date = last_crawled_date
        initial_page = last_crawled_page
        logging.info(f"API Fetcher: Resuming crawl from date: {current_date.strftime('%Y-%m-%d')}, page: {initial_page}")
    else:
        current_date = datetime.now()
        initial_page = 1
        logging.info("API Fetcher: Starting new crawl from current date and page 1.")

    time_slice_days = 30
    historical_limit_date = datetime(current_date.year - 5, current_date.month, current_date.day)

    while len(repos) < limit and current_date > historical_limit_date:
        end_date_str = current_date.strftime('%Y-%m-%d')
        start_date = current_date - timedelta(days=time_slice_days)
        start_date_str = start_date.strftime('%Y-%m-%d')

        time_query = f"created:{start_date_str}..{end_date_str}"
        language_query = " ".join([f"language:{lang}" for lang in languages])
        full_query = f"{time_query} {language_query}"
        
        logging.info(f"API Fetcher: Querying GitHub for repos created between {start_date_str} and {end_date_str}. Current found: {len(repos)}")

        page = initial_page 
        per_page = 100 

        while True:
            params = {
                "q": full_query, 
                "sort": "updated", 
                "order": "desc",
                "per_page": per_page,
                "page": page
            }
            try:
                res = requests.get(SEARCH_API, headers=HEADERS, params=params, timeout=15) 
                res.raise_for_status() 
                items = res.json().get("items", [])

                if not items:
                    logging.info(f"API Fetcher: No more items found on page {page} for time slice {time_query}. Moving to next time slice.")
                    save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                    break 

                new_found_on_page = 0
                for item in items:
                    full_name = item.get("full_name")
                    if full_name and full_name not in seen_repos:
                        repos.append(full_name)
                        new_found_on_page += 1
                    if len(repos) >= limit:
                        logging.info(f"API Fetcher: Reached desired limit of {limit} repositories. Stopping time iteration.")
                        save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                        return repos[:limit] 

                logging.info(f"API Fetcher: Found {new_found_on_page} new repos on page {page} for {time_query}. Total new found: {len(repos)}")

                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)

                if len(items) < per_page:
                    logging.info(f"API Fetcher: Less than {per_page} items on page {page} for {time_query}, likely end of results for this slice.")
                    break

                page += 1

            except requests.exceptions.HTTPError as e:
                logging.error(f"API Fetcher: GitHub API HTTP error (status {e.response.status_code}) for {time_query} page {page}: {e.response.text}")
                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                break 
            except requests.exceptions.ConnectionError as e:
                logging.error(f"API Fetcher: Connection error to GitHub API for {time_query} page {page}: {e}")
                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                break
            except requests.exceptions.Timeout as e:
                logging.error(f"API Fetcher: Timeout connecting to GitHub API for {time_query} page {page}: {e}")
                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                break
            except requests.exceptions.RequestException as e:
                logging.error(f"API Fetcher: An unexpected request error occurred with GitHub API for {time_query} page {page}: {e}")
                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                break
            except json.JSONDecodeError as e:
                logging.error(f"API Fetcher: Error decoding JSON response from GitHub API for {time_query} page {page}: {e}. Response text: {res.text if res else 'N/A'}")
                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                break
            except Exception as e:
                logging.error(f"API Fetcher: An unexpected error occurred in get_repo_batch inner loop for {time_query} page {page}: {e}")
                save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
                break

        initial_page = 1
        current_date = start_date - timedelta(days=1) 
        save_crawler_state(current_date.strftime('%Y-%m-%d'), initial_page)

    logging.info(f"API Fetcher: Finished iterating through time periods or reached historical limit. Returning {len(repos)} repositories.")
    save_crawler_state(current_date.strftime('%Y-%m-%d'), page)
    return repos[:limit] 

def fetch_repo_metadata(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}"
    r = requests.get(url, headers=HEADERS)
    return r.json() if r.status_code == 200 else {}

def fetch_repo_topics(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}/topics"
    logging.info(f"Fetching topics for {owner}/{repo}")
    h = HEADERS.copy()
    h["Accept"] = "application/vnd.github.mercy-preview+json"
    r = requests.get(url, headers=h)
    return r.json().get("names", []) if r.status_code == 200 else []

def fetch_all_metadata(owner, repo):
    logging.info(f"Fetching repository metadata for {owner}/{repo}")
    data = fetch_repo_metadata(owner, repo)
    data["topics"] = fetch_repo_topics(owner, repo)
    return data

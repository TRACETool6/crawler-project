import os
import logging
import time
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from clone import clone_repo
from github_api import get_repo_batch, fetch_all_metadata
from extract import extract_commits, extract_file_index
from storage import save_repo_data, mark_as_crawled
from config import BASE_PATH, CRAWLED_DB_PATH, BATCH_SIZE, GROUP_NAME, ensure_dirs, load_crawled_repos

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

TARGET_REPOS = 100000
MAX_CLONE_THREADS = 10
MAX_PROCESS_WORKERS = os.cpu_count() or 4
MAX_RETRIES = 3


def retry_clone_repo(full_name, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        try:
            repo_path, repo_name = clone_repo(full_name)
            if repo_path and repo_name:
                return repo_path, repo_name
            logging.warning(f"Clone failed for {full_name} (attempt {attempt})")
        except Exception as e:
            logging.error(f"Clone error for {full_name} (attempt {attempt}): {e}")
        time.sleep(2 * attempt)  
    logging.error(f"Failed to clone {full_name} after {retries} attempts")
    return None, None


def process_repo_data(full_name, repo_path, repo_name):
    try:
        logging.info(f"Processing data for {full_name} at {repo_path}")
        owner, repo_name_part = full_name.split("/")

        commits = extract_commits(repo_path)
        if not commits:
            logging.warning(f"No commits for {full_name}")

        file_index = extract_file_index(repo_path)
        if not file_index:
            logging.warning(f"No file index for {full_name}")

        repo_metadata = fetch_all_metadata(owner, repo_name_part)
        if not repo_metadata:
            logging.warning(f"No metadata for {full_name}")

        save_repo_data(GROUP_NAME, repo_name, repo_metadata, commits, file_index, repo_path)
        mark_as_crawled(full_name)

        logging.info(f"Successfully processed {full_name}")
    except Exception as e:
        logging.error(f"Error processing {full_name}: {e}")


def crawl_loop():
    logging.info(f"Starting crawl for {TARGET_REPOS} repos")
    ensure_dirs()

    while True:
        seen_repos = load_crawled_repos()
        current_count = len(seen_repos)
        if current_count >= TARGET_REPOS:
            logging.info("Target reached. Stopping crawl.")
            break

        to_fetch = min(BATCH_SIZE, TARGET_REPOS - current_count)
        if to_fetch <= 0:
            break

        repos_to_process = get_repo_batch(seen_repos, to_fetch)
        if not repos_to_process:
            logging.warning("No new repos. Waiting.")
            time.sleep(60)
            continue

        logging.info(f"Cloning {len(repos_to_process)} repos...")
        cloned_repos = []
        with ThreadPoolExecutor(max_workers=MAX_CLONE_THREADS) as executor:
            future_to_repo = {
                executor.submit(retry_clone_repo, repo): repo for repo in repos_to_process
            }
            for future in as_completed(future_to_repo):
                repo = future_to_repo[future]
                try:
                    repo_path, repo_name = future.result()
                    if repo_path and repo_name:
                        cloned_repos.append((repo, repo_path, repo_name))
                except Exception as e:
                    logging.error(f"Error cloning {repo}: {e}")

        if not cloned_repos:
            logging.info("No successful clones. Waiting.")
            time.sleep(10)
            continue

        logging.info(f"Processing {len(cloned_repos)} cloned repos...")
        with ProcessPoolExecutor(max_workers=MAX_PROCESS_WORKERS) as executor:
            futures = [executor.submit(process_repo_data, full_name, path, name)
                       for full_name, path, name in cloned_repos]
            for future in as_completed(futures):
                future.result()  

        logging.info("Batch done. Pausing before next.")
        time.sleep(5)

    logging.info("Crawling complete.")


if __name__ == "__main__":
    crawl_loop()

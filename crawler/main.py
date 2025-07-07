import os
import shutil
import logging
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from clone import clone_repo
from github_api import get_repo_batch, fetch_all_metadata
from extract import extract_commits
from storage import save_repo_data, mark_as_crawled
from config import BASE_PATH, CRAWLED_DB_PATH, BATCH_SIZE, GROUP_NAME, ensure_dirs, load_crawled_repos

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

TARGET_REPOS = 1000
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

def remove_repo_folder(path):
    logging.info(f"Removing data from {path}")
    if os.path.exists(path):
        shutil.rmtree(path,ignore_errors=True)

def process_repo_data(full_name):
    try:
        logging.info(f"Starting process data for {full_name}")
        repo_path, repo_name = retry_clone_repo(full_name)
        owner, repo_name_part = full_name.split("/")

        commits = extract_commits(repo_path)
        if not commits:
            logging.warning(f"No commits for {full_name}")

        

        repo_metadata = fetch_all_metadata(owner, repo_name_part)
        if not repo_metadata:
            logging.warning(f"No metadata for {full_name}")

        save_repo_data(GROUP_NAME, repo_name, repo_metadata, commits, {}, repo_path)
        mark_as_crawled(full_name)
        remove_repo_folder(repo_path)

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

        
        with ProcessPoolExecutor(max_workers=MAX_PROCESS_WORKERS) as executor:
            futures = [executor.submit(process_repo_data, full_name)
                       for full_name in repos_to_process]
            for future in as_completed(futures):
                future.result()  

        logging.info("Batch done. Pausing before next.")
        time.sleep(5)

    logging.info("Crawling complete.")

def process_current_dataset():
    current_path = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(current_path, "dataset")
    repos = os.listdir(dataset_path)
    cloned_repos = []

    for repo in repos:
        full_name = repo.replace("_","/")
        cloned_repos.append((full_name, f"{dataset_path}/{repo}", repo))
    
    with ProcessPoolExecutor(max_workers=MAX_PROCESS_WORKERS) as executor:
            futures = [executor.submit(process_repo_data, full_name, path, name)
                       for full_name, path, name in cloned_repos]
            for future in as_completed(futures):
                future.result()

if __name__ == "__main__":
    crawl_loop()

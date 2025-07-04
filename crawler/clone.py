import os
import logging
import time
import git
from config import BASE_PATH

MAX_RETRIES = 3

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

def clone_repo(full_name):
    owner, repo_name_part = full_name.split("/")
    folder_name = f"{owner}_{repo_name_part}"
    path = os.path.join(BASE_PATH, folder_name)

    if os.path.exists(path) and os.path.exists(os.path.join(path, ".git")):
        logging.info(f"Repository {full_name} already exists at {path}. Skipping clone.")
        return path, folder_name

    logging.info(f"Attempting to clone {full_name} to {path}")
    git.Repo.clone_from(f"https://github.com/{full_name}.git", path)
    logging.info(f"Successfully cloned {full_name} to {path}")
    return path, folder_name
    '''repo_name = full_name.split("/")[-1]
    repo_path = os.path.join(BASE_PATH, repo_name)

    if os.path.exists(repo_path):
        logging.info(f"Repo already exists: {repo_name}")
        return repo_path, repo_name

    url = f"https://github.com/{full_name}.git"
    try:
        subprocess.run(["git", "clone", "--depth=1", url, repo_path], check=True)
        return repo_path, repo_name
    except subprocess.CalledProcessError as e:
        logging.warning(f"Failed to clone {full_name}: {e}")
        return None, None'''


def retry_clone_repo(full_name, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        repo_path, repo_name = clone_repo(full_name)
        if repo_path and repo_name:
            return repo_path, repo_name
        logging.warning(f"Retry {attempt} failed for {full_name}")
        time.sleep(2 * attempt)
    logging.error(f"Failed to clone {full_name} after {retries} retries")
    return None, None

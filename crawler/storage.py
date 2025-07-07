import os
import json
import sqlite3
import logging

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

try:
    from config import BASE_PATH, CRAWLED_DB_PATH
except ImportError:
    logging.error("Could not import BASE_PATH or CRAWLED_DB_PATH from config.py. Please ensure config.py exists and contains these variables.")
    BASE_PATH = "dataset"
    CRAWLED_DB_PATH = "crawler_db.sqlite"




def save_repo_data(group_name, repo_name, repo_info, commits, file_index, repo_path):
    """
    Saves the extracted repository data (info, commits, file index) to JSON files.

    Args:
        group_name (str): The name of the group/category for the repository.
        repo_name (str): The name of the repository (e.g., 'owner_repo').
        repo_info (dict): General information about the repository.
        commits (list): A list of dictionaries, each representing a commit.
        file_index (list): A list of dictionaries, each representing a file in the repository.
        repo_path (str): The local path where the repository was cloned.
                         This is used to determine the base directory for saving data.
    """
    try:
        logs = {}
        logs["commitLog"] = commits
        logs["metadataLog"] = repo_info
        repo_data_dir = os.path.join(BASE_PATH, group_name, repo_name)
        os.makedirs(repo_data_dir, exist_ok=True)
        logging.info(f"Ensured data directory exists: {repo_data_dir}")

        
        commits_path = os.path.join(repo_data_dir, "repo_data.json")
        with open(commits_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)
        logging.info(f"Saved logs to {commits_path}")

        
        logging.info(f"Successfully saved all data for {repo_name}")

    except Exception as e:
        logging.error(f"Error saving data for {repo_name}: {e}")


def mark_as_crawled(full_name):
    """
    Marks a repository as crawled by adding its full name to the SQLite database.

    Args:
        full_name (str): The full name of the repository (e.g., 'owner/repo').
    """
    conn = None
    try:
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO Crawled (RepoName) VALUES (?)", (full_name,))
        conn.commit()
        logging.info(f"Marked {full_name} as crawled.")
    except sqlite3.Error as e:
        logging.error(f"SQLite error marking {full_name} as crawled: {e}")
    except Exception as e:
        logging.error(f"Unexpected error marking {full_name} as crawled: {e}")
    finally:
        if conn:
            conn.close()
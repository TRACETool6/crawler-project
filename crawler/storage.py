import os
import json
import sqlite3
import logging
import shutil

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


def copy_repo_files(repo_path, destination_path):
    """
    Copies all repository files to the destination directory, excluding .git folder.
    
    Args:
        repo_path (str): The source repository path.
        destination_path (str): The destination directory path.
    """
    try:
        os.makedirs(destination_path, exist_ok=True)
        
        for root, dirs, files in os.walk(repo_path):
            if ".git" in dirs:
                dirs.remove(".git")
            
            rel_root = os.path.relpath(root, repo_path)
            if rel_root == '.':
                dest_root = destination_path
            else:
                dest_root = os.path.join(destination_path, rel_root)
            
            os.makedirs(dest_root, exist_ok=True)
            
            for file in files:
                src_file = os.path.join(root, file)
                dest_file = os.path.join(dest_root, file)
                try:
                    shutil.copy2(src_file, dest_file)
                except (OSError, IOError) as e:
                    logging.warning(f"Could not copy file {src_file} to {dest_file}: {e}")
        
        logging.info(f"Successfully copied repository files from {repo_path} to {destination_path}")
        
    except Exception as e:
        logging.error(f"Error copying repository files from {repo_path} to {destination_path}: {e}")


def save_repo_data(group_name, repo_name, repo_info, commits, file_index, repo_path):
    """
    Saves the extracted repository data (info, commits, file index) to JSON files
    and copies all repository files to the storage directory.

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
        logs["fileIndex"] = file_index
        
        repo_data_dir = os.path.join(BASE_PATH, group_name, repo_name)
        os.makedirs(repo_data_dir, exist_ok=True)
        logging.info(f"Ensured data directory exists: {repo_data_dir}")

        repo_data_path = os.path.join(repo_data_dir, "repo_data.json")
        with open(repo_data_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)
        logging.info(f"Saved repository data to {repo_data_path}")

        # Copy all repository files to the storage directory
        repo_files_dir = os.path.join(repo_data_dir, "files")
        copy_repo_files(repo_path, repo_files_dir)
        
        logging.info(f"Successfully saved all data and files for {repo_name}")

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
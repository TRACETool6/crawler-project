import os
import json
import sqlite3
import logging
import h5py
import numpy as np
from datetime import datetime

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




def save_repo_data(group_name, repo_name, repo_info, commits, file_index, repo_path, base_path=None):
    """
    Saves the extracted repository data (info, commits, file index) to HDF5 format.
    Also stores the actual code files and logs in the same HDF5 file.

    Args:
        group_name (str): The name of the group/category for the repository.
        repo_name (str): The name of the repository (e.g., 'owner_repo').
        repo_info (dict): General information about the repository.
        commits (list): A list of dictionaries, each representing a commit.
        file_index (list): A list of dictionaries, each representing a file in the repository.
        repo_path (str): The local path where the repository was cloned.
        base_path (str, optional): Override the default BASE_PATH for output location.
    """
    try:
        # Use provided base_path or fall back to imported BASE_PATH
        output_base_path = base_path if base_path is not None else BASE_PATH
        
        repo_data_dir = os.path.join(output_base_path, group_name, repo_name)
        os.makedirs(repo_data_dir, exist_ok=True)
        logging.info(f"Ensured data directory exists: {repo_data_dir}")

        # Create HDF5 file path
        hdf5_path = os.path.join(repo_data_dir, f"{repo_name}.h5")
        
        with h5py.File(hdf5_path, "w") as h5file:
            # Create main groups
            metadata_group = h5file.create_group("metadata")
            commits_group = h5file.create_group("commits")
            codebase_group = h5file.create_group("codebase")
            logs_group = h5file.create_group("logs")
            
            # Store repository metadata
            _store_metadata(metadata_group, repo_info)
            
            # Store commits information
            _store_commits(commits_group, commits)
            
            # Store code files from the repository
            _store_codebase(codebase_group, repo_path)
            

            
            # Add creation timestamp
            h5file.attrs["created_at"] = datetime.now().isoformat()
            h5file.attrs["repository_name"] = repo_name
            h5file.attrs["group_name"] = group_name
        
        logging.info(f"Successfully saved all data for {repo_name} to HDF5 format at {hdf5_path}")

    except Exception as e:
        logging.error(f"Error saving data for {repo_name}: {e}")


def _store_metadata(group, repo_info):
    """Store repository metadata in HDF5 group."""
    if not repo_info:
        return
    
    # Convert metadata to string format for storage
    metadata_json = json.dumps(repo_info, indent=2)
    
    # Store as string dataset
    group.create_dataset("repo_info", data=metadata_json, dtype=h5py.string_dtype())
    
    # Store key metrics as separate datasets for easy access
    if isinstance(repo_info, dict):
        for key in ["stars", "forks", "size", "language", "created_at", "updated_at"]:
            if key in repo_info:
                value = repo_info[key]
                if isinstance(value, (int, float)):
                    group.create_dataset(key, data=value)
                elif isinstance(value, str):
                    group.create_dataset(key, data=value, dtype=h5py.string_dtype())


def _store_commits(group, commits):
    """Store commits information in HDF5 group."""
    if not commits:
        return
    
    # Store full commits data as JSON
    commits_json = json.dumps(commits, indent=2)
    group.create_dataset("commits_data", data=commits_json, dtype=h5py.string_dtype())
    
    
    

def _store_codebase(group, repo_path):
    """Store code files from the repository in HDF5 group."""
    if not repo_path or not os.path.exists(repo_path):
        return
    
    # Define file extensions to include (common code file types)
    code_extensions = {
        '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp', '.cs', '.go',
        '.rs', '.php', '.rb', '.swift', '.kt', '.scala', '.clj', '.hs', '.ml',
        '.r', '.m', '.sh', '.bash', '.zsh', '.ps1', '.sql', '.html', '.css',
        '.xml', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
        '.md', '.txt', '.rst', '.tex', '.dockerfile', '.makefile', '.cmake'
    }
    
    files_stored = 0
    files_group = group.create_group("files")
    
    try:
        for root, dirs, files in os.walk(repo_path):
            # Skip .git directory
            if ".git" in dirs:
                dirs.remove(".git")
            
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                
                # Get file extension
                _, ext = os.path.splitext(file.lower())
                
                # Only store code files and common text files
                if ext in code_extensions or file.lower() in ['readme', 'license', 'changelog', 'makefile', 'dockerfile']:
                    try:
                        # Read file content
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Create a safe name for HDF5 dataset (replace special characters)
                        safe_name = rel_path.replace('/', '_').replace('\\', '_').replace('.', '_dot_')
                        
                        # Store file content and metadata
                        file_group = files_group.create_group(safe_name)
                        file_group.create_dataset("content", data=content, dtype=h5py.string_dtype())
                        file_group.create_dataset("path", data=rel_path, dtype=h5py.string_dtype())
                        file_group.create_dataset("extension", data=ext, dtype=h5py.string_dtype())
                        file_group.create_dataset("size", data=len(content))
                        
                        files_stored += 1
                        
                        
                            
                    except (UnicodeDecodeError, IOError, OSError) as e:
                        logging.warning(f"Could not read file {file_path}: {e}")
                        continue
            
            
    
    except Exception as e:
        logging.error(f"Error storing codebase from {repo_path}: {e}")
    
    # Store summary statistics
    group.create_dataset("total_files_stored", data=files_stored)
    logging.info(f"Stored {files_stored} code files from {repo_path}")


def _store_repository_logs(group, repo_name):
    """Store crawler logs specific to this repository."""
    try:
        # Read the main crawler log file and extract entries for this repository
        log_file_path = "crawler.log"
        if os.path.exists(log_file_path):
            repo_logs = []
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Check if log line contains references to this repository
                    if repo_name in line or repo_name.replace('_', '/') in line:
                        repo_logs.append(line.strip())
            
            if repo_logs:
                # Store repository-specific logs
                logs_content = '\n'.join(repo_logs)
                group.create_dataset("crawler_logs", data=logs_content, dtype=h5py.string_dtype())
                group.create_dataset("log_entries_count", data=len(repo_logs))
                logging.info(f"Stored {len(repo_logs)} log entries for {repo_name}")
            else:
                group.create_dataset("crawler_logs", data="No specific logs found", dtype=h5py.string_dtype())
                group.create_dataset("log_entries_count", data=0)
        else:
            group.create_dataset("crawler_logs", data="Log file not found", dtype=h5py.string_dtype())
            group.create_dataset("log_entries_count", data=0)
    
    except Exception as e:
        logging.error(f"Error storing logs for {repo_name}: {e}")
        group.create_dataset("crawler_logs", data=f"Error reading logs: {e}", dtype=h5py.string_dtype())


def read_repo_hdf5(hdf5_path):
    """
    Utility function to read and display information from an HDF5 repository file.
    
    Args:
        hdf5_path (str): Path to the HDF5 file.
    
    Returns:
        dict: Dictionary containing the repository data.
    """
    try:
        with h5py.File(hdf5_path, 'r') as h5file:
            data = {}
            
            # Read metadata
            if 'metadata' in h5file:
                metadata_group = h5file['metadata']
                if 'repo_info' in metadata_group:
                    repo_info_json = metadata_group['repo_info'][()].decode('utf-8')
                    data['metadata'] = json.loads(repo_info_json)
            
            # Read commits
            if 'commits' in h5file:
                commits_group = h5file['commits']
                if 'commits_data' in commits_group:
                    commits_json = commits_group['commits_data'][()].decode('utf-8')
                    data['commits'] = json.loads(commits_json)
                
                if 'statistics' in commits_group:
                    stats = {}
                    for key in commits_group['statistics'].keys():
                        stats[key] = commits_group['statistics'][key][()]
                    data['commit_statistics'] = stats
            
            # Read file information (not content, just metadata)
            if 'codebase' in h5file and 'files' in h5file['codebase']:
                files_info = {}
                files_group = h5file['codebase']['files']
                for file_key in files_group.keys():
                    file_group = files_group[file_key]
                    files_info[file_key] = {
                        'path': file_group['path'][()].decode('utf-8'),
                        'extension': file_group['extension'][()].decode('utf-8'),
                        'size': file_group['size'][()]
                    }
                data['files'] = files_info
                
                if 'total_files_stored' in h5file['codebase']:
                    data['total_files_stored'] = h5file['codebase']['total_files_stored'][()]
            
            # Read logs summary
            if 'logs' in h5file:
                logs_group = h5file['logs']
                if 'log_entries_count' in logs_group:
                    data['log_entries_count'] = logs_group['log_entries_count'][()]
            
            # Read file attributes
            data['attributes'] = dict(h5file.attrs)
            
            return data
    
    except Exception as e:
        logging.error(f"Error reading HDF5 file {hdf5_path}: {e}")
        return None


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
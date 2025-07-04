import os
import git
import logging

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

def extract_commits(repo_path):
    """
    Extracts commit information from a Git repository.

    Args:
        repo_path (str): The local path to the cloned Git repository.

    Returns:
        list: A list of dictionaries, each representing a commit with detailed information.
    """
    logging.info(f"Extracting commits from {repo_path}")
    commits = []
    seen_shas = set() 
    try:
        repo = git.Repo(repo_path)
        for ref in repo.refs:
            if isinstance(ref, git.Head) or isinstance(ref, git.TagReference):
                for commit in repo.iter_commits(ref):
                    if commit.hexsha in seen_shas:
                        continue 
                    seen_shas.add(commit.hexsha)

                    stats = commit.stats
                    files_changed_list = []
                    for file_path, file_stats in stats.files.items():
                        files_changed_list.append({
                            "path": file_path,
                            "insertions": file_stats.get("insertions", 0),
                            "deletions": file_stats.get("deletions", 0),
                            "lines_changed": file_stats.get("lines", 0)
                        })

                    commits.append({
                        "sha": commit.hexsha,
                        "branch_or_tag": ref.name, 
                        "author": {"name": commit.author.name, "email": commit.author.email},
                        "committer": {"name": commit.committer.name, "email": commit.committer.email},
                        "author_date": commit.authored_datetime.isoformat(),
                        "commit_date": commit.committed_datetime.isoformat(),
                        "message": commit.message.strip(),
                        "parents": [p.hexsha for p in commit.parents],
                        "files_changed": files_changed_list,
                        "total_lines_added": stats.total.get("insertions", 0),
                        "total_lines_deleted": stats.total.get("deletions", 0),
                        "total_files_changed": stats.total.get("files", 0)
                    })
        logging.info(f"Finished extracting {len(commits)} commits from {repo_path}")
    except git.InvalidGitRepositoryError:
        logging.error(f"Path {repo_path} is not a valid Git repository.")
    except Exception as e:
        logging.error(f"Error extracting commits from {repo_path}: {e}")
    return commits

def extract_file_index(repo_path):
    """
    Extracts a file index (path and size) for all files in a repository,
    excluding the .git directory.

    Args:
        repo_path (str): The local path to the cloned repository.

    Returns:
        list: A list of dictionaries, each with 'path' and 'size' of a file.
    """
    logging.info(f"Extracting file index from {repo_path}")
    index = []
    try:
        for root, dirs, files in os.walk(repo_path):
            if ".git" in dirs:
                dirs.remove(".git") 

            for f in files:
                abs_path = os.path.join(root, f)
                rel_path = os.path.relpath(abs_path, repo_path)
                try:
                    size = os.path.getsize(abs_path)
                    index.append({"path": rel_path, "size": size})
                except OSError as e:
                    logging.warning(f"Could not get size for {abs_path}: {e}")
        logging.info(f"Finished extracting {len(index)} files for index from {repo_path}")
    except Exception as e:
        logging.error(f"Error extracting file index from {repo_path}: {e}")
    return index
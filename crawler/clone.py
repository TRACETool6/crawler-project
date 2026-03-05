import os
import logging
import shutil
import subprocess
import time
import json
import git
from config import BASE_PATH, SNAPSHOTS_PATH

MAX_RETRIES = 3
CLONE_TIMEOUT = 300

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


def clone_and_export_at_sha(
    full_name: str,
    sha: str,
    dest_snapshot_dir: str,
    metadata: dict,
) -> bool:
    """
    Clone repo with --filter=blob:none --no-checkout, checkout SHA, export working tree to dest_snapshot_dir.
    Idempotent: if dest_snapshot_dir exists and metadata.json has same chosen_sha, skip and return True.
    Returns True if export succeeded or was skipped (already done), False on failure.
    """
    metadata_path = os.path.join(dest_snapshot_dir, "metadata.json")
    if os.path.isdir(dest_snapshot_dir):
        if os.path.isfile(metadata_path):
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
                if existing.get("chosen_sha") == sha:
                    logging.info(f"Snapshot already exists for {full_name} at {sha}, skipping.")
                    return True
            except (json.JSONDecodeError, OSError):
                pass
    owner, repo_name_part = full_name.split("/", 1)
    folder_name = f"{owner}_{repo_name_part}"
    url = f"https://github.com/{full_name}.git"
    staging = os.path.join(BASE_PATH, f"_staging_{folder_name}_{sha[:8]}")
    try:
        os.makedirs(os.path.dirname(dest_snapshot_dir), exist_ok=True)
        if os.path.exists(staging):
            shutil.rmtree(staging, ignore_errors=True)
        logging.info(f"Cloning {full_name} (blob:none, no-checkout) for SHA {sha[:8]}...")
        r = subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", "--single-branch", url, staging],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT,
            cwd=os.path.dirname(staging) or ".",
        )
        if r.returncode != 0:
            logging.error(f"git clone failed: {r.stderr}")
            return False
        fetch_r = subprocess.run(
            ["git", "fetch", "origin", sha],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=staging,
        )
        if fetch_r.returncode != 0:
            logging.warning(f"git fetch {sha} failed, trying checkout anyway: {fetch_r.stderr}")
        checkout_r = subprocess.run(
            ["git", "checkout", "--force", sha],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=staging,
        )
        if checkout_r.returncode != 0:
            logging.error(f"git checkout {sha} failed: {checkout_r.stderr}")
            return False
        if os.path.exists(dest_snapshot_dir):
            shutil.rmtree(dest_snapshot_dir, ignore_errors=True)
        os.makedirs(dest_snapshot_dir, exist_ok=True)
        for name in os.listdir(staging):
            if name == ".git":
                continue
            src = os.path.join(staging, name)
            dst = os.path.join(dest_snapshot_dir, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst, symlinks=False, ignore=lambda d, names: [n for n in names if n == ".git"])
            else:
                shutil.copy2(src, dst)
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)
        logging.info(f"Exported {full_name} at {sha[:8]} to {dest_snapshot_dir}")
        return True
    except subprocess.TimeoutExpired:
        logging.error(f"Clone/export timeout for {full_name}")
        return False
    except Exception as e:
        logging.error(f"Clone/export error for {full_name}: {e}")
        return False
    finally:
        if os.path.exists(staging):
            shutil.rmtree(staging, ignore_errors=True)


def retry_clone_repo(full_name, retries=MAX_RETRIES):
    for attempt in range(1, retries + 1):
        repo_path, repo_name = clone_repo(full_name)
        if repo_path and repo_name:
            return repo_path, repo_name
        logging.warning(f"Retry {attempt} failed for {full_name}")
        time.sleep(2 * attempt)
    logging.error(f"Failed to clone {full_name} after {retries} retries")
    return None, None

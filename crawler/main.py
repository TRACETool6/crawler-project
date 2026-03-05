"""
Crawler entrypoint: seed ingestion, time-window search, snapshot export.
Usage:
  - Crawl seeds only:        python main.py --seed-file malware_repos.txt --seeds-only
  - Crawl search + window:  python main.py --seed-file malware_repos.txt --start-date 2021-10-01 --end-date 2022-12-31
  - Force tmetz repo:       python main.py --force-repo tmetz/python-for-cybersecurity-py2
"""
import os
import sys
import json
import logging
import argparse
from datetime import datetime

# Ensure crawler package imports work when run from project root or crawler/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    ensure_dirs,
    GITHUB_TOKEN,
    SNAPSHOTS_PATH,
    MANIFEST_PATH,
    DEFAULT_START_DATE,
    DEFAULT_END_DATE,
    DEFAULT_TARGET_DATE,
)
from time_window import parse_seeds, qualifies_in_window
from github_api import (
    fetch_repo_metadata,
    resolve_snapshot_sha,
    search_repos_time_window,
    fetch_commits_in_window,
)
from clone import clone_and_export_at_sha
from storage import save_snapshot_manifest_row, mark_as_crawled

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)


def run_snapshot_crawl(
    seed_file: str = None,
    seed_repos: str = None,
    start_date: str = DEFAULT_START_DATE,
    end_date: str = DEFAULT_END_DATE,
    target_date: str = DEFAULT_TARGET_DATE,
    strict_time_filter: bool = True,
    force_repo: str = None,
    search_keywords: list = None,
    seeds_only: bool = False,
    max_repos: int = None,
):
    if not GITHUB_TOKEN:
        logging.error("GITHUB_TOKEN (or GPAT) not set. Set env GITHUB_TOKEN.")
        return
    ensure_dirs()
    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    target_dt = datetime.strptime(target_date, "%Y-%m-%d")

    seeds = parse_seeds(seed_file, seed_repos)
    if force_repo:
        force_repo = force_repo.strip()
        if "/" in force_repo and force_repo not in seeds:
            seeds.append(force_repo)
    repo_list = list(dict.fromkeys(seeds))
    logging.info(f"Seeds (including force-repo): {len(repo_list)}")

    if not seeds_only:
        seen = set(repo_list)
        keywords = search_keywords or ["0day", "exploit", "malware"]
        discovered = search_repos_time_window(
            keywords, start_date, end_date, seen, limit=max_repos or 500, strict_time_filter=strict_time_filter
        )
        for r in discovered:
            if r not in seen:
                repo_list.append(r)
                seen.add(r)
        logging.info(f"After search: {len(repo_list)} repos to process")

    if max_repos and len(repo_list) > max_repos:
        repo_list = repo_list[:max_repos]

    for i, full_name in enumerate(repo_list):
        if "/" not in full_name:
            continue
        owner, repo = full_name.split("/", 1)
        is_seed = full_name in seeds or full_name == force_repo
        logging.info(f"[{i+1}/{len(repo_list)}] Processing {full_name} (seed={is_seed})")
        try:
            meta = fetch_repo_metadata(owner, repo)
            if not meta:
                logging.warning(f"No metadata for {full_name}, skipping.")
                continue
            default_branch = meta.get("default_branch") or "main"
            html_url = meta.get("html_url") or f"https://github.com/{full_name}"
            license_info = ""
            if meta.get("license") and isinstance(meta["license"], dict):
                license_info = meta["license"].get("spdx_id") or meta["license"].get("key") or ""
            elif meta.get("license"):
                license_info = str(meta["license"])

            sha, chosen_date, reason = resolve_snapshot_sha(
                owner, repo, target_dt, start_dt, end_dt, is_seed=is_seed
            )
            if not sha:
                logging.warning(f"Could not resolve SHA for {full_name}, skipping.")
                continue
            if not is_seed and strict_time_filter:
                commits_in_window = []
                since_str = start_dt.strftime("%Y-%m-%dT00:00:00Z")
                until_str = end_dt.strftime("%Y-%m-%dT23:59:59Z")
                commits_in_window = fetch_commits_in_window(owner, repo, default_branch, since_str, until_str, use_commit_cache=True)
                qual, qreason = qualifies_in_window(meta, start_dt, end_dt, commits_in_window)
                if not qual:
                    logging.info(f"{full_name} does not qualify in window ({qreason}), skipping.")
                    continue

            folder_name = full_name.replace("/", "__")
            snapshot_sha_dir = os.path.join(SNAPSHOTS_PATH, folder_name, sha)
            metadata = {
                "owner": owner,
                "repo": repo,
                "full_name": full_name,
                "html_url": html_url,
                "chosen_sha": sha,
                "chosen_snapshot_date": chosen_date,
                "selection_reason": reason,
                "default_branch": default_branch,
                "license": license_info,
            }
            ok = clone_and_export_at_sha(full_name, sha, snapshot_sha_dir, metadata)
            if not ok:
                continue
            manifest_line = json.dumps({
                "owner/name": full_name,
                "html_url": html_url,
                "chosen_snapshot_sha": sha,
                "chosen_snapshot_date": chosen_date,
                "selection_reason": reason,
                "default_branch": default_branch,
                "license": license_info,
            })
            save_snapshot_manifest_row(
                full_name, sha, chosen_date or "", reason, default_branch, html_url, license_info, manifest_line
            )
            mark_as_crawled(full_name)
        except Exception as e:
            logging.error(f"Error processing {full_name}: {e}")
            continue

    logging.info(f"Snapshot crawl done. Manifest: {MANIFEST_PATH}")


def main():
    p = argparse.ArgumentParser(description="Crawl GitHub repos with seed list and time-window snapshot.")
    p.add_argument("--seed-file", default=None, help="Path to seed file (one owner/repo per line).")
    p.add_argument("--seed-repos", default=None, help="Comma-separated owner/repo list.")
    p.add_argument("--start-date", default=DEFAULT_START_DATE, help=f"Window start (default {DEFAULT_START_DATE}).")
    p.add_argument("--end-date", default=DEFAULT_END_DATE, help=f"Window end (default {DEFAULT_END_DATE}).")
    p.add_argument("--target-date", default=DEFAULT_TARGET_DATE, help=f"Target date for closest commit (default {DEFAULT_TARGET_DATE}).")
    p.add_argument("--strict-time-filter", action="store_true", default=True, help="Only include repos that qualify in window (default True).")
    p.add_argument("--no-strict-time-filter", action="store_false", dest="strict_time_filter", help="Allow repos outside window.")
    p.add_argument("--force-repo", default=None, help="Force include repo (e.g. tmetz/python-for-cybersecurity-py2).")
    p.add_argument("--search-keywords", default=None, nargs="*", help="Search keywords (default: 0day exploit malware).")
    p.add_argument("--seeds-only", action="store_true", help="Only crawl seed repos (no search).")
    p.add_argument("--max-repos", type=int, default=None, help="Max repos to process (default no limit).")
    args = p.parse_args()

    run_snapshot_crawl(
        seed_file=args.seed_file,
        seed_repos=args.seed_repos,
        start_date=args.start_date,
        end_date=args.end_date,
        target_date=args.target_date,
        strict_time_filter=args.strict_time_filter,
        force_repo=args.force_repo,
        search_keywords=args.search_keywords,
        seeds_only=args.seeds_only,
        max_repos=args.max_repos,
    )


if __name__ == "__main__":
    main()

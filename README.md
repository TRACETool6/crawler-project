# crawler-project

## Crawler: seed list + time-window snapshots

The crawler can headstart malicious-repo collection using a seed list and optionally discover repos via search, then export source snapshots at a commit chosen for a target time window (e.g. 2022).

**Requirements:** `GITHUB_TOKEN` (or `GPAT`) environment variable set. No hard-coded secrets.

### Run examples

**Crawl seeds only** (from `malware_repos.txt`; snapshots at 2022-ish commit when available, else default branch):

```bash
cd crawler
export GITHUB_TOKEN=your_token
python main.py --seed-file ../malware_repos.txt --seeds-only
```

**Crawl search + time window** (seeds plus repos discovered by keyword with `created` in 2021-10-01..2022-12-31):

```bash
python main.py --seed-file ../malware_repos.txt --start-date 2021-10-01 --end-date 2022-12-31 --target-date 2022-06-30
```

**Force a specific repo** (e.g. `tmetz/python-for-cybersecurity-py2` around 2022):

```bash
python main.py --force-repo tmetz/python-for-cybersecurity-py2 --target-date 2022-06-30
```

**Seeds + force-repo together:**

```bash
python main.py --seed-file ../malware_repos.txt --force-repo tmetz/python-for-cybersecurity-py2 --seeds-only
```

### Outputs

- **Manifest:** `dataset/manifest.jsonl` (one JSON object per line: owner/name, html_url, chosen_snapshot_sha, chosen_snapshot_date, selection_reason, default_branch, license).
- **Snapshots:** `dataset/snapshots/owner__repo/<sha>/` with repo files and `metadata.json`.
- **Cache:** SQLite `crawler_db.sqlite` (ApiCache, CommitCache, SnapshotManifest, Crawled).
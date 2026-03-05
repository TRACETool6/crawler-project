# Summary of Changes and How to Use

This document summarizes the changes made to the crawler and how to run it.

---

## Summary of Changes

### Crawler: Headstart Malicious-Repo Collection + Time-Window Snapshots

The GitHub repo crawler was extended to:

1. **Seed ingestion**
   - **`--seed-file <path>`** – Read a list of known/suspected malicious repos (one `owner/repo` per line; lines starting with `#` are comments).
   - **`--seed-repos owner/repo,owner/repo`** – Comma-separated list of repos.
   - Seeds are **always** included and get a snapshot (commit in window or default-branch HEAD).

2. **Time-window filtering (for discovered repos)**
   - Configurable window: **`--start-date`** (default `2021-10-01`), **`--end-date`** (default `2022-12-31`), **`--target-date`** (default `2022-06-30`).
   - A repo qualifies if:
     - `created_at` is in the window, or
     - `pushed_at` is in the window, or
     - It has at least one commit in the window on the default branch.
   - **`--strict-time-filter`** (default) / **`--no-strict-time-filter`** – Whether to skip repos that do not qualify.

3. **Snapshot resolution (not “HEAD today”)**
   - For each repo we resolve a **snapshot SHA**:
     - If there is a commit in the window: choose the commit **closest to `--target-date`**.
     - Otherwise (or for seeds when no commit in window): use default branch HEAD.
   - Source is exported **at that SHA** (not latest main).

4. **Robust git export**
   - **`git clone --filter=blob:none --no-checkout`** then **`git fetch`** the chosen SHA and **`git checkout`** that SHA.
   - Working tree is copied into `dataset/snapshots/owner__repo/<sha>/` (no `.git`).
   - **Idempotent:** if the snapshot directory already exists and `metadata.json` has the same `chosen_sha`, the repo is skipped.

5. **GitHub API caching and rate limiting**
   - **ApiCache** (SQLite): ETag + response body; conditional requests with `If-None-Match`.
   - **CommitCache** (SQLite): Cached commit lists per repo/branch/window to avoid repeated API calls.
   - **Rate limit:** When `X-RateLimit-Remaining == 0`, the crawler sleeps until `X-RateLimit-Reset` + jitter.
   - Retries with exponential backoff on 502/503/504; timeouts on all requests.

6. **Force a specific repo**
   - **`--force-repo owner/repo`** – Ensures that repo is in the list and gets a snapshot (e.g. `tmetz/python-for-cybersecurity-py2` for a 2022 snapshot).

7. **Outputs**
   - **Manifest:** `dataset/manifest.jsonl` – One JSON object per line (`owner/name`, `html_url`, `chosen_snapshot_sha`, `chosen_snapshot_date`, `selection_reason`, `default_branch`, `license`).
   - **Snapshots:** `dataset/snapshots/owner__repo/<sha>/` – Repo files plus `metadata.json`.
   - **SQLite:** `crawler_db.sqlite` – Tables: `ApiCache`, `CommitCache`, `SnapshotManifest`, `Crawled`.

8. **Configuration**
   - **Token:** Use **`GITHUB_TOKEN`** (or **`GPAT`**) in the environment; no hard-coded secrets.
   - Paths and defaults can be overridden via env: `CRAWLER_DATASET_PATH`, `CRAWLER_DB_PATH`, etc.

---

## How to Use the Crawler

### 1. Set your GitHub token

```bash
export GITHUB_TOKEN=your_github_personal_access_token
```

(or use `GPAT` if you already have it set). The crawler does not use hard-coded tokens.

### 2. Run from the `crawler` directory

Commands below assume you are in the project root; adjust paths if you run from elsewhere.

---

### Crawl seeds only

Uses **`malware_repos.txt`** (or your own seed file). Each repo gets a snapshot at a 2022-window commit when available, otherwise at default branch HEAD.

```bash
cd crawler
python main.py --seed-file ../malware_repos.txt --seeds-only
```

---

### Crawl seeds + search in time window

Seeds are always included. Additional repos are discovered by keyword search with **created** date in the window (default 2021-10-01 to 2022-12-31). Only repos that qualify in the window are kept when `--strict-time-filter` is on (default).

```bash
cd crawler
python main.py --seed-file ../malware_repos.txt --start-date 2021-10-01 --end-date 2022-12-31 --target-date 2022-06-30
```

Optional: limit how many repos to process:

```bash
python main.py --seed-file ../malware_repos.txt --max-repos 100
```

---

### Force a specific repo (e.g. tmetz/python-for-cybersecurity-py2)

Ensures that repo is in the list and resolves a snapshot (by default around 2022-06-30 when there is a commit in the window).

```bash
cd crawler
python main.py --force-repo tmetz/python-for-cybersecurity-py2 --target-date 2022-06-30
```

You can combine with seeds:

```bash
python main.py --seed-file ../malware_repos.txt --force-repo tmetz/python-for-cybersecurity-py2 --seeds-only
```

---

### All CLI options

| Option | Description |
|--------|-------------|
| `--seed-file PATH` | Text file with one `owner/repo` per line (e.g. `../malware_repos.txt`). |
| `--seed-repos A/B,C/D` | Comma-separated list of repos. |
| `--start-date YYYY-MM-DD` | Window start (default: 2021-10-01). |
| `--end-date YYYY-MM-DD` | Window end (default: 2022-12-31). |
| `--target-date YYYY-MM-DD` | Target date for “closest commit” (default: 2022-06-30). |
| `--strict-time-filter` | Only include discovered repos that qualify in the window (default). |
| `--no-strict-time-filter` | Allow repos outside the window. |
| `--force-repo owner/repo` | Always include this repo and resolve its snapshot. |
| `--search-keywords w1 w2 ...` | Keywords for search (default: 0day exploit malware). |
| `--seeds-only` | Do not run search; only process seed (and force-repo) list. |
| `--max-repos N` | Process at most N repos. |

---

### Where output goes

| Output | Location |
|--------|----------|
| Manifest (one JSON per line) | `dataset/manifest.jsonl` |
| Snapshot for each repo | `dataset/snapshots/owner__repo/<chosen_sha>/` (files + `metadata.json`) |
| Cache DB | `crawler_db.sqlite` (in current working directory when you run `main.py`) |

Re-running is safe: existing snapshots with the same `chosen_sha` are skipped; cache and manifest are reused or appended.

---

### Seed file format (`malware_repos.txt`)

- One repo per line: `owner/repo`.
- Lines starting with `#` are comments and ignored.
- Example:

```
# Known/suspected malicious repos
M4xSec/exploitbuffer
tmetz/python-for-cybersecurity-py2
```

Use **`--seed-file ../malware_repos.txt`** when you run from inside the `crawler` directory.

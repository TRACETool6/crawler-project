import os
import sqlite3
import logging
from datetime import datetime

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

BASE_PATH = "dataset"
CRAWLED_DB_PATH = "crawler_db.sqlite"
GROUP_NAME = "all_repos"
GITHUB_TOKEN = os.environ.get("GPAT")
BATCH_SIZE = 5000 

def ensure_dirs():
    """
    Ensures that the necessary directories and the SQLite database exist.
    Also creates the 'Crawled' table and 'CrawlerState' table if they don't exist.
    """
    os.makedirs(BASE_PATH, exist_ok=True)
    logging.info(f"Ensured base path exists: {BASE_PATH}")
    group_path = os.path.join(BASE_PATH, GROUP_NAME)
    os.makedirs(group_path, exist_ok=True)
    logging.info(f"Ensured group path exists: {group_path}")

    conn = None
    try:
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS Crawled (RepoName TEXT PRIMARY KEY)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS CrawlerState (
                id INTEGER PRIMARY KEY,
                last_crawled_date TEXT,
                last_crawled_page INTEGER
            )
        """)
        conn.commit()
        logging.info(f"Ensured CRAWLED_DB_PATH and tables exist: {CRAWLED_DB_PATH}")
    except sqlite3.Error as e:
        logging.error(f"SQLite error during initial DB setup: {e}")
    finally:
        if conn:
            conn.close()

def load_crawled_repos():
    """Loads the set of already crawled repository names from the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT RepoName FROM Crawled")
        rows = c.fetchall()
        logging.info(f"Loaded {len(rows)} crawled repos from {CRAWLED_DB_PATH}")
        return set(r[0] for r in rows)
    except sqlite3.Error as e:
        logging.error(f"SQLite error loading crawled repos: {e}")
        return set()
    finally:
        if conn:
            conn.close()

def save_crawler_state(last_crawled_date_str, last_crawled_page):
    """
    Saves the current state of the crawler (last date queried and page number)
    to the CrawlerState table.
    """
    conn = None
    try:
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO CrawlerState (id, last_crawled_date, last_crawled_page)
            VALUES (1, ?, ?)
        """, (last_crawled_date_str, last_crawled_page))
        conn.commit()
        logging.debug(f"Saved crawler state: Date={last_crawled_date_str}, Page={last_crawled_page}")
    except sqlite3.Error as e:
        logging.error(f"SQLite error saving crawler state: {e}")
    except Exception as e:
        logging.error(f"Unexpected error saving crawler state: {e}")
    finally:
        if conn:
            conn.close()

def load_crawler_state():
    """
    Loads the last saved state of the crawler (last date queried and page number)
    from the CrawlerState table.
    """
    conn = None
    try:
        conn = sqlite3.connect(CRAWLED_DB_PATH)
        c = conn.cursor()
        c.execute("SELECT last_crawled_date, last_crawled_page FROM CrawlerState WHERE id = 1")
        row = c.fetchone()
        if row:
            last_date_str, last_page = row
            logging.info(f"Loaded crawler state: Date={last_date_str}, Page={last_page}")
            return datetime.strptime(last_date_str, '%Y-%m-%d'), last_page
        else:
            logging.info("No previous crawler state found. Starting from current date and page 1.")
            return None, None
    except sqlite3.Error as e:
        logging.error(f"SQLite error loading crawler state: {e}")
        return None, None
    except Exception as e:
        logging.error(f"Unexpected error loading crawler state: {e}")
        return None, None
    finally:
        if conn:
            conn.close()
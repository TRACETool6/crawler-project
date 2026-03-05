import os
import json
import h5py
import tempfile
import hashlib
import shutil
import logging
import time
import requests
import re
import random
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Callable
from threading import Lock, Semaphore
import sqlite3
from keyword_analyzer import KeywordAnalyzer, KeywordDatabase
from behavioral_analyzer import BehavioralAnalysisPipeline

logging.basicConfig(
    filename="labeling_pipeline.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

LABELING_DB_PATH = "labeling_db.sqlite"
VT_API_URL_FILES = "https://www.virustotal.com/api/v3/files"
VT_API_URL_ANALYSES = "https://www.virustotal.com/api/v3/analyses/{}"
VT_API_URL_FILE_HASH = "https://www.virustotal.com/api/v3/files/{}"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

MALICIOUS_THRESHOLD = 3
SUSPICIOUS_THRESHOLD = 2

# --- Pipeline configuration (concurrency & rate limiting) ---
TOP_N_FILES = 10
HASHCACHE_TTL_DAYS = 30
VT_SUBMIT_WORKERS = 4
VT_POLL_WORKERS = 6
VT_HASH_LOOKUP_WORKERS = 8
BEHAVIORAL_WORKERS = 1
# VT rate limit: requests per minute per key (VT free tier ~4/min)
VT_REQUESTS_PER_MINUTE = 4
VT_429_COOLDOWN_SECONDS = 60
VT_401_INVALIDATE_AFTER = 2
# LLM: only run on "gray zone" repos
LLM_SKIP_BELOW_SCORE = 1.0
LLM_SKIP_ABOVE_SCORE = 8.0
LLM_CONSENSUS_BOUNDARY_LOW = 3.5
LLM_CONSENSUS_BOUNDARY_HIGH = 6.5
# Micro-behavior trigger threshold for behavioral escalation
MICRO_BEHAVIOR_THRESHOLD = 1
# Polling backoff
VT_POLL_INITIAL_DELAY = 15
VT_POLL_MAX_DELAY = 120
VT_POLL_MAX_WAIT = 300

SUSPICIOUS_FILE_PATTERNS = [
    'exploit', 'payload', 'backdoor', 'shell', 'reverse', 'keylog',
    'inject', 'bypass', 'crack', 'hack', 'malware', 'trojan', 'virus'
]

# Lightweight content regex signals for static heuristic (no LLM)
STATIC_SUSPICIOUS_REGEX = re.compile(
    r'\b(curl|wget|powershell|Invoke-Expression|base64|exec\s*\(|subprocess\.|eval\s*\(|os\.system)\b',
    re.IGNORECASE
)

EXECUTABLE_EXTENSIONS = {
    # Python & JavaScript
    '.py', '.js', '.jsx', '.ts', '.tsx',
    
    # Shell scripts
    '.sh', '.bash', '.zsh', '.fish',
    
    # Windows scripts & executables
    '.ps1', '.bat', '.cmd', '.vbs', '.exe', '.dll',
    
    # Unix/Linux executables & libraries
    '.so', '.dylib', '.bin', '.elf',
    
    # Java
    '.java', '.class', '.jar', '.war', '.ear',
    
    # C/C++
    '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx',
    
    # PHP
    '.php', '.php3', '.php4', '.php5', '.phtml',
    
    # Ruby
    '.rb', '.rbw',
    
    # Go
    '.go',
    
    # Rust
    '.rs',
    
    # Web technologies (can contain malicious scripts)
    '.html', '.htm', '.asp', '.aspx', '.jsp',
    
    # Configuration files (can contain malicious commands)
    '.xml', '.json', '.yaml', '.yml', '.conf', '.config',
    
    # SQL files
    '.sql',
    
    # Other scripting languages
    '.pl', '.cgi', '.lua', '.tcl'
}


def static_heuristic_score(file_path: str, content_snippet: Optional[str] = None) -> float:
    """Lightweight static score for a file (path + optional content). No LLM. Unit-testable."""
    score = 0.0
    file_name = os.path.basename(file_path).lower()
    ext = os.path.splitext(file_path)[1].lower()
    if ext in EXECUTABLE_EXTENSIONS:
        score += 1.0
    for pattern in SUSPICIOUS_FILE_PATTERNS:
        if pattern in file_name:
            score += 2.0
            break
    if content_snippet and STATIC_SUSPICIOUS_REGEX.search(content_snippet):
        score += 1.5
    return score


def select_top_n_files(
    candidates: List[Tuple[str, str]],
    file_scores_from_db: Optional[List[Dict]] = None,
    content_getter: Optional[Callable[[str], Optional[str]]] = None,
    n: int = TOP_N_FILES,
) -> List[Tuple[str, str]]:
    """Select top N most suspicious files. file_scores_from_db: list of dicts with file_path, total_score, is_malicious. Unit-testable."""
    if not candidates:
        return []
    score_by_path = {}
    if file_scores_from_db:
        for fs in file_scores_from_db:
            path = fs.get("file_path")
            if path is None:
                continue
            total = float(fs.get("total_score") or 0)
            if fs.get("is_malicious"):
                total += 10.0
            score_by_path[path] = score_by_path.get(path, 0) + total
    for rel_path, full_path in candidates:
        static = static_heuristic_score(
            rel_path,
            content_getter(rel_path) if content_getter else None
        )
        score_by_path[rel_path] = score_by_path.get(rel_path, 0) + static
    sorted_paths = sorted(score_by_path.items(), key=lambda x: -x[1])
    top_paths = set(p[0] for p in sorted_paths[:n])
    return [(rel, full) for rel, full in candidates if rel in top_paths]


def parse_package_json_scripts(repo_path: str) -> Tuple[int, List[str]]:
    """Parse package.json scripts for suspicious keywords. Returns (score, list of matching script names). Unit-testable."""
    p = Path(repo_path) / "package.json"
    if not p.exists():
        return 0, []
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return 0, []
    scripts = data.get("scripts") or {}
    score = 0
    matched = []
    for name, cmd in scripts.items():
        if not isinstance(cmd, str):
            continue
        if STATIC_SUSPICIOUS_REGEX.search(cmd):
            score += 2
            matched.append(name)
    return score, matched


def parse_setup_py_pyproject(repo_path: str) -> Tuple[int, List[str]]:
    """Parse setup.py and pyproject.toml for suspicious install/build hooks. Returns (score, list of matched file:desc). Unit-testable."""
    score = 0
    matched = []
    for fname in ["setup.py", "pyproject.toml"]:
        p = Path(repo_path) / fname
        if not p.exists():
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if STATIC_SUSPICIOUS_REGEX.search(content):
            score += 2
            matched.append(f"{fname}:suspicious_pattern")
    return score, matched


def compute_micro_behavior_score(repo_path: str) -> float:
    """Aggregate micro-behavior trigger score (static parse only, no execution). Unit-testable."""
    s1, _ = parse_package_json_scripts(repo_path)
    s2, _ = parse_setup_py_pyproject(repo_path)
    return float(s1 + s2)


class APIKeyRotator:
    def __init__(self, vt_keys: List[str], groq_keys: List[str] = None):
        self.vt_keys = vt_keys
        self.groq_keys = groq_keys or []
        self.vt_index = 0
        self.groq_index = 0
        self.vt_key_usage = {key: {"calls": 0, "last_reset": time.time()} for key in vt_keys}
        self.groq_key_usage = {key: {"calls": 0, "last_reset": time.time()} for key in self.groq_keys}
        
    def get_vt_key(self) -> str:
        key = self.vt_keys[self.vt_index]
        self.vt_index = (self.vt_index + 1) % len(self.vt_keys)
        self.vt_key_usage[key]["calls"] += 1
        logging.debug(f"Using VT key index {self.vt_index - 1 if self.vt_index > 0 else len(self.vt_keys) - 1}, length: {len(key)}, first 8 chars: {key[:8]}...")
        return key
    
    def get_groq_key(self) -> str:
        if not self.groq_keys:
            return None
        key = self.groq_keys[self.groq_index]
        self.groq_index = (self.groq_index + 1) % len(self.groq_keys)
        self.groq_key_usage[key]["calls"] += 1
        return key
    
    def report_usage(self):
        logging.info("API Key Usage Report")
        for i, key in enumerate(self.vt_keys):
            logging.info(f"VT Key {i}: {self.vt_key_usage[key]['calls']} calls")
        for i, key in enumerate(self.groq_keys):
            logging.info(f"Groq Key {i}: {self.groq_key_usage[key]['calls']} calls")


def _select_vt_key_for_limiter(keys: List[str], key_states: Dict) -> Optional[str]:
    """Unit-testable: pick an available VT key (not invalid, not in cooldown)."""
    now = time.time()
    for key in keys:
        state = key_states.get(key, {})
        if state.get("invalid"):
            continue
        cooldown_until = state.get("cooldown_until", 0)
        if cooldown_until and now < cooldown_until:
            continue
        return key
    return None


class VTRateLimiter:
    """Per-key token bucket style throttling; 429 -> cooldown; 401 -> invalidate after N."""
    
    def __init__(self, vt_keys: List[str], requests_per_minute: int = VT_REQUESTS_PER_MINUTE,
                 cooldown_seconds: int = VT_429_COOLDOWN_SECONDS,
                 invalidate_after_401: int = VT_401_INVALIDATE_AFTER):
        self.vt_keys = [k for k in vt_keys if k]
        self.rpm = requests_per_minute
        self.cooldown_seconds = cooldown_seconds
        self.invalidate_after_401 = invalidate_after_401
        self._lock = Lock()
        # Per-key: tokens (calls left this minute), minute_start, cooldown_until, 401_count, invalid
        self._state = {}
        for k in self.vt_keys:
            self._state[k] = {
                "tokens": requests_per_minute,
                "minute_start": time.time(),
                "cooldown_until": 0.0,
                "401_count": 0,
                "invalid": False,
            }
    
    def _refill(self, key: str):
        now = time.time()
        s = self._state[key]
        if now - s["minute_start"] >= 60:
            s["tokens"] = self.rpm
            s["minute_start"] = now
    
    def acquire(self, timeout: float = 300) -> Optional[str]:
        """Block until a key is available (or timeout). Returns key or None."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                key = _select_vt_key_for_limiter(self.vt_keys, self._state)
                if key is None:
                    # All in cooldown or invalid; wait for shortest cooldown
                    wait = None
                    for k, s in self._state.items():
                        if s.get("invalid"):
                            continue
                        cu = s.get("cooldown_until", 0)
                        if cu and cu > time.time():
                            if wait is None or cu < wait:
                                wait = cu
                    if wait is not None:
                        sleep_time = min(5, max(0.5, wait - time.time()))
                    else:
                        sleep_time = 5
                else:
                    self._refill(key)
                    if self._state[key]["tokens"] <= 0:
                        sleep_time = 1
                    else:
                        self._state[key]["tokens"] -= 1
                        return key
            time.sleep(sleep_time if sleep_time else 1)
        logging.warning("VTRateLimiter: acquire timeout")
        return None
    
    def record_429(self, key: str):
        with self._lock:
            self._state[key]["cooldown_until"] = time.time() + self.cooldown_seconds
            logging.warning(f"VT rate limit 429: key on cooldown for {self.cooldown_seconds}s")
    
    def record_401(self, key: str):
        with self._lock:
            self._state[key]["401_count"] = self._state[key].get("401_count", 0) + 1
            if self._state[key]["401_count"] >= self.invalidate_after_401:
                self._state[key]["invalid"] = True
                logging.warning("VT key marked invalid after repeated 401")
    
    def record_success(self, key: str):
        pass  # tokens already decremented in acquire


class LabelingDatabase:
    def __init__(self, db_path: str = LABELING_DB_PATH):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS FileLabels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT,
                file_path TEXT,
                file_hash TEXT,
                is_malicious BOOLEAN,
                vt_malicious_count INTEGER,
                vt_suspicious_count INTEGER,
                vt_harmless_count INTEGER,
                vt_undetected_count INTEGER,
                total_engines INTEGER,
                detection_names TEXT,
                scan_date TEXT,
                UNIQUE(repo_name, file_path)
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS KeywordPreScreen (
                repo_name TEXT PRIMARY KEY,
                keyword_score REAL,
                pattern_score REAL,
                combined_score REAL,
                malicious_keywords_count INTEGER,
                suspicious_patterns_count INTEGER,
                is_suspicious BOOLEAN,
                prescreen_date TEXT
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS RepositoryLabels (
                repo_name TEXT PRIMARY KEY,
                total_files INTEGER,
                malicious_files INTEGER,
                suspicious_files INTEGER,
                clean_files INTEGER,
                file_level_score REAL,
                keyword_based_score REAL,
                passed_keyword_filter BOOLEAN,
                llm_agent1_score REAL,
                llm_agent1_reasoning TEXT,
                llm_agent2_score REAL,
                llm_agent2_reasoning TEXT,
                final_consensus_score REAL,
                final_consensus_reasoning TEXT,
                behavioral_analysis_result TEXT,
                behavioral_analysis_triggered BOOLEAN,
                is_malicious BOOLEAN,
                malicious_reason TEXT,
                labeling_date TEXT,
                processing_time_seconds REAL
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS ProcessingStatus (
                repo_name TEXT PRIMARY KEY,
                status TEXT,
                last_updated TEXT,
                error_message TEXT
            )
        """)
        # Hash cache: dedupe VT hash lookups across repos (additive schema)
        c.execute("""
            CREATE TABLE IF NOT EXISTS HashCache (
                sha256 TEXT PRIMARY KEY,
                found INTEGER NOT NULL,
                vt_json TEXT,
                last_checked TEXT NOT NULL
            )
        """)
        # Pending VT analyses for resumability
        c.execute("""
            CREATE TABLE IF NOT EXISTS PendingAnalyses (
                analysis_id TEXT PRIMARY KEY,
                sha256 TEXT,
                repo_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                last_polled_at TEXT,
                status TEXT NOT NULL,
                api_key_id TEXT
            )
        """)
        conn.commit()
        conn.close()
        logging.info(f"Database initialized at {self.db_path}")
    
    def save_file_label(self, repo_name: str, file_path: str, label_data: Dict):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                INSERT OR REPLACE INTO FileLabels 
                (repo_name, file_path, file_hash, is_malicious, vt_malicious_count, 
                 vt_suspicious_count, vt_harmless_count, vt_undetected_count,
                 total_engines, detection_names, scan_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_name,
                file_path,
                label_data.get('file_hash'),
                label_data.get('is_malicious'),
                label_data.get('vt_malicious_count'),
                label_data.get('vt_suspicious_count'),
                label_data.get('vt_harmless_count'),
                label_data.get('vt_undetected_count'),
                label_data.get('total_engines'),
                json.dumps(label_data.get('detection_names', [])),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            logging.error(f"Error saving file label for {repo_name}/{file_path}: {e}")
        finally:
            conn.close()
    
    def save_repo_label(self, repo_name: str, label_data: Dict):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            behavioral_analysis_result = label_data.get('behavioral_analysis')
            behavioral_analysis_json = json.dumps(behavioral_analysis_result) if behavioral_analysis_result else None
            behavioral_analysis_triggered = behavioral_analysis_result is not None
            
            c.execute("""
                INSERT OR REPLACE INTO RepositoryLabels 
                (repo_name, total_files, malicious_files, suspicious_files, clean_files,
                 file_level_score, keyword_based_score, passed_keyword_filter,
                 llm_agent1_score, llm_agent1_reasoning,
                 llm_agent2_score, llm_agent2_reasoning, final_consensus_score,
                 final_consensus_reasoning, behavioral_analysis_result, behavioral_analysis_triggered,
                 is_malicious, malicious_reason, labeling_date, processing_time_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_name,
                label_data.get('total_files'),
                label_data.get('malicious_files'),
                label_data.get('suspicious_files'),
                label_data.get('clean_files'),
                label_data.get('file_level_score'),
                label_data.get('keyword_based_score'),
                label_data.get('passed_keyword_filter'),
                label_data.get('llm_agent1_score'),
                label_data.get('llm_agent1_reasoning'),
                label_data.get('llm_agent2_score'),
                label_data.get('llm_agent2_reasoning'),
                label_data.get('final_consensus_score'),
                label_data.get('final_consensus_reasoning'),
                behavioral_analysis_json,
                behavioral_analysis_triggered,
                label_data.get('is_malicious'),
                label_data.get('malicious_reason'),
                datetime.now().isoformat(),
                label_data.get('processing_time')
            ))
            conn.commit()
            logging.info(f"Saved repo label for {repo_name}")
        except Exception as e:
            logging.error(f"Error saving repo label for {repo_name}: {e}")
        finally:
            conn.close()
    
    def save_keyword_prescreen(self, repo_name: str, keyword_data: Dict):
        """Save keyword pre-screening results"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                INSERT OR REPLACE INTO KeywordPreScreen 
                (repo_name, keyword_score, pattern_score, combined_score,
                 malicious_keywords_count, suspicious_patterns_count,
                 is_suspicious, prescreen_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_name,
                keyword_data.get('keyword_score'),
                keyword_data.get('pattern_score'),
                keyword_data.get('combined_score'),
                keyword_data.get('malicious_keywords_count'),
                keyword_data.get('suspicious_patterns_count'),
                keyword_data.get('is_suspicious'),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            logging.error(f"Error saving keyword prescreen for {repo_name}: {e}")
        finally:
            conn.close()
    
    def get_file_labels(self, repo_name: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                SELECT file_path, file_hash, is_malicious, vt_malicious_count,
                       vt_suspicious_count, detection_names
                FROM FileLabels WHERE repo_name = ?
            """, (repo_name,))
            
            results = []
            for row in c.fetchall():
                results.append({
                    'file_path': row[0],
                    'file_hash': row[1],
                    'is_malicious': row[2],
                    'vt_malicious_count': row[3],
                    'vt_suspicious_count': row[4],
                    'detection_names': json.loads(row[5]) if row[5] else []
                })
            return results
        finally:
            conn.close()
    
    def update_status(self, repo_name: str, status: str, error_message: str = None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                INSERT OR REPLACE INTO ProcessingStatus 
                (repo_name, status, last_updated, error_message)
                VALUES (?, ?, ?, ?)
            """, (repo_name, status, datetime.now().isoformat(), error_message))
            conn.commit()
        except Exception as e:
            logging.error(f"Error updating status for {repo_name}: {e}")
        finally:
            conn.close()
    
    def get_hash_cache(self, sha256: str, ttl_days: int = HASHCACHE_TTL_DAYS) -> Optional[Dict]:
        """Return cached VT result if present and within TTL. Keys: found, vt_json."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute(
                "SELECT found, vt_json, last_checked FROM HashCache WHERE sha256 = ?",
                (sha256,)
            )
            row = c.fetchone()
            if not row:
                return None
            found, vt_json, last_checked = row
            cutoff = (datetime.now() - timedelta(days=ttl_days)).isoformat()
            if last_checked < cutoff:
                return None
            return {"found": bool(found), "vt_json": vt_json}
        finally:
            conn.close()
    
    def set_hash_cache(self, sha256: str, found: bool, vt_json: Optional[str] = None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("""
                INSERT OR REPLACE INTO HashCache (sha256, found, vt_json, last_checked)
                VALUES (?, ?, ?, ?)
            """, (sha256, 1 if found else 0, vt_json, datetime.now().isoformat()))
            conn.commit()
        except Exception as e:
            logging.error(f"Error setting hash cache for {sha256[:8]}: {e}")
        finally:
            conn.close()
    
    def get_pending_analyses(self, repo_name: Optional[str] = None) -> List[Dict]:
        """Return pending analyses, optionally filtered by repo_name."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            if repo_name:
                c.execute("""
                    SELECT analysis_id, sha256, repo_name, file_path, submitted_at, last_polled_at, status, api_key_id
                    FROM PendingAnalyses WHERE repo_name = ? AND status = 'pending'
                """, (repo_name,))
            else:
                c.execute("""
                    SELECT analysis_id, sha256, repo_name, file_path, submitted_at, last_polled_at, status, api_key_id
                    FROM PendingAnalyses WHERE status = 'pending'
                """)
            rows = c.fetchall()
            return [
                {
                    "analysis_id": r[0], "sha256": r[1], "repo_name": r[2], "file_path": r[3],
                    "submitted_at": r[4], "last_polled_at": r[5], "status": r[6], "api_key_id": r[7]
                }
                for r in rows
            ]
        finally:
            conn.close()
    
    def add_pending_analysis(self, analysis_id: str, sha256: str, repo_name: str, file_path: str, api_key_id: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("""
                INSERT OR REPLACE INTO PendingAnalyses
                (analysis_id, sha256, repo_name, file_path, submitted_at, last_polled_at, status, api_key_id)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """, (analysis_id, sha256, repo_name, file_path, datetime.now().isoformat(), None, api_key_id))
            conn.commit()
        except Exception as e:
            logging.error(f"Error adding pending analysis {analysis_id}: {e}")
        finally:
            conn.close()
    
    def update_pending_analysis_polled(self, analysis_id: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute(
                "UPDATE PendingAnalyses SET last_polled_at = ? WHERE analysis_id = ?",
                (datetime.now().isoformat(), analysis_id)
            )
            conn.commit()
        finally:
            conn.close()
    
    def remove_pending_analysis(self, analysis_id: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.execute("DELETE FROM PendingAnalyses WHERE analysis_id = ?", (analysis_id,))
            conn.commit()
        finally:
            conn.close()
    
    def is_labeled(self, repo_name: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("SELECT 1 FROM RepositoryLabels WHERE repo_name = ?", (repo_name,))
            return c.fetchone() is not None
        finally:
            conn.close()


class HDF5CodebaseExtractor:
    @staticmethod
    def extract_files_from_hdf5(hdf5_path: str, output_dir: str) -> List[Tuple[str, str]]:
        logging.info(f"Extracting files from {hdf5_path}")
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            extracted_files = []
            
            with h5py.File(hdf5_path, 'r') as h5file:
                if 'codebase' not in h5file or 'files' not in h5file['codebase']:
                    logging.warning(f"No codebase found in {hdf5_path}")
                    return []
                
                files_group = h5file['codebase']['files']
                
                for file_key in files_group.keys():
                    file_group = files_group[file_key]
                    
                    file_path = file_group['path'][()].decode('utf-8')
                    content_type = file_group['content_type'][()].decode('utf-8')
                    
                    if content_type == 'text':
                        content = file_group['content'][()].decode('utf-8')
                        
                        full_path = os.path.join(output_dir, file_path)
                        os.makedirs(os.path.dirname(full_path), exist_ok=True)
                        
                        with open(full_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                        
                        extracted_files.append((file_path, full_path))
                
                logging.info(f"Extracted {len(extracted_files)} files from {hdf5_path}")
                return extracted_files
                
        except Exception as e:
            logging.error(f"Error extracting from {hdf5_path}: {e}")
            return []
    
    @staticmethod
    def should_scan_file(file_path: str) -> bool:
        file_name = os.path.basename(file_path).lower()
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext in EXECUTABLE_EXTENSIONS:
            return True
        
        for pattern in SUSPICIOUS_FILE_PATTERNS:
            if pattern in file_name:
                return True
        
        return False
    
    @staticmethod
    def calculate_file_hash(file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def _backoff_with_jitter(attempt: int, base: float, cap: float) -> float:
    delay = min(cap, base * (2 ** attempt))
    return delay * (0.5 + 0.5 * random.random())


class VirusTotalAnalyzer:
    def __init__(self, key_rotator: APIKeyRotator, rate_limiter: Optional[VTRateLimiter] = None):
        self.key_rotator = key_rotator
        self.rate_limiter = rate_limiter
    
    def _get_key(self):
        if self.rate_limiter:
            key = self.rate_limiter.acquire(timeout=VT_429_COOLDOWN_SECONDS + 30)
            return key
        return self.key_rotator.get_vt_key()
    
    def _record_429(self, key: str):
        if self.rate_limiter:
            self.rate_limiter.record_429(key)
    
    def _record_401(self, key: str):
        if self.rate_limiter:
            self.rate_limiter.record_401(key)
    
    def check_hash_exists(self, file_hash: str) -> Optional[Dict]:
        max_retries = 3
        for attempt in range(max_retries):
            key = self._get_key()
            if not key:
                return None
            try:
                headers = {"x-apikey": key}
                url = VT_API_URL_FILE_HASH.format(file_hash)
                response = requests.get(url, headers=headers, timeout=30)
                if response.status_code == 200:
                    if self.rate_limiter:
                        self.rate_limiter.record_success(key)
                    return response.json()
                elif response.status_code == 404:
                    if self.rate_limiter:
                        self.rate_limiter.record_success(key)
                    return None
                elif response.status_code == 429:
                    self._record_429(key)
                    time.sleep(_backoff_with_jitter(attempt, 2, 20))
                    continue
                elif response.status_code == 401:
                    self._record_401(key)
                    time.sleep(_backoff_with_jitter(attempt, 1, 10))
                    continue
                else:
                    time.sleep(_backoff_with_jitter(attempt, 2, 15))
                    continue
            except requests.exceptions.RequestException as e:
                logging.error(f"Error checking hash: {e}")
                time.sleep(_backoff_with_jitter(attempt, 5, 30))
        return None
    
    def submit_file(self, file_path: str) -> Optional[Tuple[str, str]]:
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return None
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:
            logging.warning(f"File too large: {file_size} bytes")
            return None
        max_retries = 3
        for attempt in range(max_retries):
            key = self._get_key()
            if not key:
                return None
            try:
                headers = {"x-apikey": key}
                with open(file_path, "rb") as file:
                    files = {"file": (os.path.basename(file_path), file)}
                    response = requests.post(VT_API_URL_FILES, headers=headers, files=files, timeout=120)
                if response.status_code == 429:
                    self._record_429(key)
                    time.sleep(_backoff_with_jitter(attempt, 5, 25))
                    continue
                if response.status_code == 401:
                    self._record_401(key)
                    time.sleep(_backoff_with_jitter(attempt, 2, 15))
                    continue
                response.raise_for_status()
                analysis_id = response.json().get("data", {}).get("id")
                if analysis_id:
                    if self.rate_limiter:
                        self.rate_limiter.record_success(key)
                    return (analysis_id, key)
                return None
            except requests.exceptions.RequestException as e:
                logging.error(f"Error submitting file (attempt {attempt + 1}): {e}")
                time.sleep(_backoff_with_jitter(attempt, 10, 60))
        return None
    
    def get_analysis_report(self, analysis_id: str, api_key: str, max_wait_time: int = VT_POLL_MAX_WAIT) -> Optional[Dict]:
        url = VT_API_URL_ANALYSES.format(analysis_id)
        start_time = time.time()
        delay = VT_POLL_INITIAL_DELAY
        current_key = api_key
        while time.time() - start_time < max_wait_time:
            key = current_key
            if self.rate_limiter:
                key = self.rate_limiter.acquire(timeout=min(30, max_wait_time - (time.time() - start_time)))
                if not key:
                    break
            try:
                headers = {"x-apikey": key}
                response = requests.get(url, headers=headers, timeout=30)
                if response.status_code == 429:
                    if self.rate_limiter:
                        self.rate_limiter.record_429(key)
                    current_key = self.key_rotator.get_vt_key()
                    time.sleep(min(delay, VT_POLL_MAX_DELAY))
                    delay = min(VT_POLL_MAX_DELAY, delay * 2)
                    continue
                if response.status_code == 401:
                    if self.rate_limiter:
                        self.rate_limiter.record_401(key)
                    current_key = self.key_rotator.get_vt_key()
                    time.sleep(_backoff_with_jitter(0, 2, 10))
                    continue
                response.raise_for_status()
                result = response.json()
                status = result.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    if self.rate_limiter:
                        self.rate_limiter.record_success(key)
                    return result
                delay = min(VT_POLL_MAX_DELAY, delay * 2)
                time.sleep(delay * (0.5 + 0.5 * random.random()))
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching report: {e}")
                time.sleep(delay)
                delay = min(VT_POLL_MAX_DELAY, delay * 2)
        logging.error(f"Analysis timeout after {max_wait_time}s")
        return None
    
    def parse_report(self, report: Dict) -> Dict:
        if not report:
            return {}
        
        attributes = report.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {})
        results = attributes.get("results", {})
        
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        harmless_count = stats.get("harmless", 0)
        undetected_count = stats.get("undetected", 0)
        total_engines = sum(stats.values())
        
        detection_names = []
        for engine, result in results.items():
            if result.get("category") in ["malicious", "suspicious"]:
                detection_name = result.get('result', 'Unknown')
                detection_names.append(f"{engine}: {detection_name}")
        
        is_malicious = (
            malicious_count >= MALICIOUS_THRESHOLD or 
            (malicious_count + suspicious_count) >= (MALICIOUS_THRESHOLD + SUSPICIOUS_THRESHOLD)
        )
        
        file_hash = attributes.get("sha256", "")
        
        return {
            'file_hash': file_hash,
            'is_malicious': is_malicious,
            'vt_malicious_count': malicious_count,
            'vt_suspicious_count': suspicious_count,
            'vt_harmless_count': harmless_count,
            'vt_undetected_count': undetected_count,
            'total_engines': total_engines,
            'detection_names': detection_names
        }


class VTJobScheduler:
    """Producer/consumer VT flow: hash lookup (with cache) -> submit unknown -> poll until done. Resumable via PendingAnalyses."""

    def __init__(self, db: LabelingDatabase, vt_analyzer: VirusTotalAnalyzer, extractor: "HDF5CodebaseExtractor",
                 hash_ttl_days: int = HASHCACHE_TTL_DAYS, hash_workers: int = VT_HASH_LOOKUP_WORKERS,
                 submit_workers: int = VT_SUBMIT_WORKERS, poll_workers: int = VT_POLL_WORKERS):
        self.db = db
        self.vt_analyzer = vt_analyzer
        self.extractor = extractor
        self.hash_ttl_days = hash_ttl_days
        self.hash_workers = hash_workers
        self.submit_workers = submit_workers
        self.poll_workers = poll_workers

    def _one_hash_lookup(self, item: Tuple[str, str, str]) -> Tuple[str, str, str, str, Optional[Dict]]:
        repo_name, rel_path, full_path = item
        sha256 = self.extractor.calculate_file_hash(full_path)
        cached = self.db.get_hash_cache(sha256, self.hash_ttl_days)
        if cached is not None:
            if cached["found"] and cached.get("vt_json"):
                import json as _json
                try:
                    report = _json.loads(cached["vt_json"])
                    return (repo_name, rel_path, full_path, sha256, report)
                except Exception:
                    pass
            return (repo_name, rel_path, full_path, sha256, None)
        report = self.vt_analyzer.check_hash_exists(sha256)
        if report:
            self.db.set_hash_cache(sha256, True, json.dumps(report))
            return (repo_name, rel_path, full_path, sha256, report)
        self.db.set_hash_cache(sha256, False)
        return (repo_name, rel_path, full_path, sha256, None)

    def _one_submit(self, item: Tuple[str, str, str, str]) -> Optional[Tuple[str, str, str, str, str, str]]:
        repo_name, rel_path, full_path, sha256 = item
        result = self.vt_analyzer.submit_file(full_path)
        if not result:
            return None
        analysis_id, api_key = result
        self.db.add_pending_analysis(analysis_id, sha256, repo_name, rel_path, api_key)
        return (analysis_id, api_key, repo_name, rel_path, sha256, full_path)

    def _poll_one(self, pending: Dict) -> Optional[Tuple[str, str, Dict]]:
        analysis_id = pending["analysis_id"]
        api_key = pending.get("api_key_id") or self.vt_analyzer.key_rotator.get_vt_key()
        report = self.vt_analyzer.get_analysis_report(analysis_id, api_key)
        self.db.update_pending_analysis_polled(analysis_id)
        if report:
            return (pending["repo_name"], pending["file_path"], report)
        return None

    def run_vt_scan(self, repo_name: str, files_to_scan: List[Tuple[str, str]]) -> int:
        """Run 3-stage VT flow for repo; resume pending first. Returns count of file labels saved."""
        stage_start = time.time()
        done = []
        # Resume: drain pending analyses for this repo
        pending_list = self.db.get_pending_analyses(repo_name)
        if pending_list:
            logging.info(f"[{repo_name}] Resuming {len(pending_list)} pending VT analyses")
            done = []
            while pending_list:
                with ThreadPoolExecutor(max_workers=self.poll_workers) as ex:
                    futures = {ex.submit(self._poll_one, p): p for p in pending_list}
                    for fut in as_completed(futures):
                        p = futures[fut]
                        try:
                            r = fut.result()
                            if r:
                                r_repo, r_path, report = r
                                parsed = self.vt_analyzer.parse_report(report)
                                if parsed:
                                    self.db.save_file_label(r_repo, r_path, parsed)
                                self.db.remove_pending_analysis(p["analysis_id"])
                                done.append(p["analysis_id"])
                        except Exception as e:
                            logging.error(f"Poll error for {p.get('analysis_id')}: {e}")
                pending_list = self.db.get_pending_analyses(repo_name)
                if len(pending_list) >= len([x for x in futures]):
                    time.sleep(10)
            logging.info(f"[{repo_name}] Resumed {len(done)} analyses in {time.time() - stage_start:.1f}s")

        if not files_to_scan:
            return len(done)

        # Stage 1: hash + cache + VT lookup (concurrent)
        items = [(repo_name, rel, full) for rel, full in files_to_scan]
        hash_results = []
        with ThreadPoolExecutor(max_workers=self.hash_workers) as ex:
            for res in ex.map(self._one_hash_lookup, items):
                hash_results.append(res)
        with_report = sum(1 for r in hash_results if r[4] is not None)
        logging.info(f"[{repo_name}] Stage 1: {len(files_to_scan)} files, hash lookup done, already had report: {with_report}")

        # Save reports we already have
        for repo_name_, rel_path, full_path, sha256, report in hash_results:
            if report:
                parsed = self.vt_analyzer.parse_report(report)
                if parsed:
                    self.db.save_file_label(repo_name_, rel_path, parsed)

        # Stage 2: submit unknown (concurrent, bounded)
        to_submit = [(r[0], r[1], r[2], r[3]) for r in hash_results if r[4] is None]
        submitted = 0
        with ThreadPoolExecutor(max_workers=self.submit_workers) as ex:
            for _ in ex.map(self._one_submit, to_submit):
                if _ is not None:
                    submitted += 1
        logging.info(f"[{repo_name}] Stage 2: submitted {submitted}/{len(to_submit)} to VT in {time.time() - stage_start:.1f}s")

        # Stage 3: poll until all pending done
        pending_list = self.db.get_pending_analyses(repo_name)
        poll_start = time.time()
        while pending_list:
            with ThreadPoolExecutor(max_workers=self.poll_workers) as ex:
                futures = {ex.submit(self._poll_one, p): p for p in pending_list}
                for fut in as_completed(futures):
                    p = futures[fut]
                    try:
                        r = fut.result()
                        if r:
                            r_repo, r_path, report = r
                            parsed = self.vt_analyzer.parse_report(report)
                            if parsed:
                                self.db.save_file_label(r_repo, r_path, parsed)
                            self.db.remove_pending_analysis(p["analysis_id"])
                    except Exception as e:
                        logging.error(f"Poll error: {e}")
            pending_list = self.db.get_pending_analyses(repo_name)
            if pending_list:
                time.sleep(max(5, min(20, _backoff_with_jitter(0, 10, 25))))

        logging.info(f"[{repo_name}] VT stage complete in {time.time() - stage_start:.1f}s (poll: {time.time() - poll_start:.1f}s)")
        return len(self.db.get_file_labels(repo_name))


class LLMConsensusAnalyzer:
    def __init__(self, key_rotator: APIKeyRotator):
        self.key_rotator = key_rotator
    
    def call_groq(self, messages: List[Dict], model: str = "llama-3.3-70b-versatile") -> Optional[str]:
        api_key = self.key_rotator.get_groq_key()
        if not api_key:
            logging.warning("No Groq API key available")
            return None
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            return content
            
        except requests.exceptions.RequestException as e:
            logging.error(f"Groq API error: {e}")
            return None
    
    def agent_analysis(self, file_labels: List[Dict], agent_name: str, previous_analysis: str = None) -> Tuple[float, str]:
        malicious_files = [f for f in file_labels if f['is_malicious']]
        total_files = len(file_labels)
        
        summary = f"Repository Analysis Data:\n"
        summary += f"Total files scanned: {total_files}\n"
        summary += f"Malicious files: {len(malicious_files)}\n\n"
        
        if malicious_files:
            summary += "Malicious file details:\n"
            for f in malicious_files[:10]:
                summary += f"- {f['file_path']}: {f['vt_malicious_count']} detections\n"
                if f['detection_names']:
                    summary += f"  Detections: {', '.join(f['detection_names'][:3])}\n"
        
        system_prompt = f"""You are {agent_name}, a cybersecurity expert analyzing repository safety.
Your task is to assess the maliciousness of a code repository based on VirusTotal scan results.
Provide a risk score from 0-10 (0=safe, 10=highly malicious) and detailed reasoning."""
        
        user_prompt = summary
        
        if previous_analysis:
            user_prompt += f"\n\nPrevious agent analysis:\n{previous_analysis}\n\n"
            user_prompt += "Consider the previous analysis but form your own independent judgment. "
            user_prompt += "You may agree or disagree with the previous assessment."
        
        user_prompt += "\n\nProvide your response in JSON format: {\"score\": <float>, \"reasoning\": \"<text>\"}"
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        response = self.call_groq(messages)
        
        if not response:
            return 0.0, "Analysis failed"
        
        try:
            cleaned = response.strip().replace("```json", "").replace("```", "").strip()
            result = json.loads(cleaned)
            return float(result.get("score", 0.0)), result.get("reasoning", "")
        except (json.JSONDecodeError, ValueError) as e:
            logging.error(f"Failed to parse LLM response: {e}")
            return 0.0, response
    
    def consensus_analysis(self, file_labels: List[Dict], agent1_score: float, agent1_reasoning: str,
                          agent2_score: float, agent2_reasoning: str, rounds: int = 2) -> Tuple[float, str]:
        
        conversation_history = []
        current_agent1_score, current_agent1_reasoning = agent1_score, agent1_reasoning
        current_agent2_score, current_agent2_reasoning = agent2_score, agent2_reasoning
        
        for round_num in range(rounds):
            logging.info(f"Consensus round {round_num + 1}/{rounds}")
            
            agent1_context = f"Agent 2's analysis (score: {current_agent2_score}):\n{current_agent2_reasoning}"
            score1, reasoning1 = self.agent_analysis(file_labels, "Agent 1 (Reassessment)", agent1_context)
            
            agent2_context = f"Agent 1's analysis (score: {score1}):\n{reasoning1}"
            score2, reasoning2 = self.agent_analysis(file_labels, "Agent 2 (Reassessment)", agent2_context)
            
            current_agent1_score, current_agent1_reasoning = score1, reasoning1
            current_agent2_score, current_agent2_reasoning = score2, reasoning2
            
            conversation_history.append({
                'round': round_num + 1,
                'agent1_score': score1,
                'agent2_score': score2
            })
        
        final_score = (current_agent1_score + current_agent2_score) / 2
        final_reasoning = f"After {rounds} rounds of discussion:\n\n"
        final_reasoning += f"Agent 1 final assessment (score: {current_agent1_score}):\n{current_agent1_reasoning}\n\n"
        final_reasoning += f"Agent 2 final assessment (score: {current_agent2_score}):\n{current_agent2_reasoning}\n\n"
        final_reasoning += f"Consensus score: {final_score:.2f}"
        
        return final_score, final_reasoning
    
    def analyze_repository(self, file_labels: List[Dict]) -> Dict:
        logging.info("Starting LLM consensus analysis")
        
        agent1_score, agent1_reasoning = self.agent_analysis(file_labels, "Agent 1 (Security Analyst)")
        agent2_score, agent2_reasoning = self.agent_analysis(file_labels, "Agent 2 (Malware Researcher)")
        
        consensus_score, consensus_reasoning = self.consensus_analysis(
            file_labels, agent1_score, agent1_reasoning, agent2_score, agent2_reasoning, rounds=2
        )
        
        return {
            'llm_agent1_score': agent1_score,
            'llm_agent1_reasoning': agent1_reasoning,
            'llm_agent2_score': agent2_score,
            'llm_agent2_reasoning': agent2_reasoning,
            'final_consensus_score': consensus_score,
            'final_consensus_reasoning': consensus_reasoning
        }

    def analyze_repository_gray_zone(self, file_labels: List[Dict]) -> Dict:
        """Single-agent by default; second agent + consensus only when near decision boundary."""
        logging.info("Starting LLM single-agent analysis")
        agent1_score, agent1_reasoning = self.agent_analysis(file_labels, "Agent 1 (Security Analyst)")
        if LLM_CONSENSUS_BOUNDARY_LOW <= agent1_score <= LLM_CONSENSUS_BOUNDARY_HIGH:
            logging.info("Near decision boundary, running second agent and consensus")
            agent2_score, agent2_reasoning = self.agent_analysis(file_labels, "Agent 2 (Malware Researcher)")
            consensus_score, consensus_reasoning = self.consensus_analysis(
                file_labels, agent1_score, agent1_reasoning, agent2_score, agent2_reasoning, rounds=2
            )
            return {
                'llm_agent1_score': agent1_score,
                'llm_agent1_reasoning': agent1_reasoning,
                'llm_agent2_score': agent2_score,
                'llm_agent2_reasoning': agent2_reasoning,
                'final_consensus_score': consensus_score,
                'final_consensus_reasoning': consensus_reasoning
            }
        return {
            'llm_agent1_score': agent1_score,
            'llm_agent1_reasoning': agent1_reasoning,
            'llm_agent2_score': None,
            'llm_agent2_reasoning': None,
            'final_consensus_score': agent1_score,
            'final_consensus_reasoning': agent1_reasoning
        }


class RepositoryLabelingPipeline:
    def __init__(self, vt_api_keys: List[str], groq_api_keys: List[str], dataset_base_path: str, 
                 group_name: str, use_keyword_filter: bool = True,
                 scan_only_malicious_files: bool = True, max_repos: int = None,
                 enable_behavioral_analysis: bool = True,
                 top_n_files: int = TOP_N_FILES,
                 vt_submit_workers: int = VT_SUBMIT_WORKERS,
                 vt_poll_workers: int = VT_POLL_WORKERS,
                 behavioral_workers: int = BEHAVIORAL_WORKERS):
        self.key_rotator = APIKeyRotator(vt_api_keys, groq_api_keys)
        self.rate_limiter = VTRateLimiter(vt_api_keys, requests_per_minute=VT_REQUESTS_PER_MINUTE,
                                          cooldown_seconds=VT_429_COOLDOWN_SECONDS,
                                          invalidate_after_401=VT_401_INVALIDATE_AFTER)
        self.vt_analyzer = VirusTotalAnalyzer(self.key_rotator, self.rate_limiter)
        self.llm_analyzer = LLMConsensusAnalyzer(self.key_rotator)
        self.extractor = HDF5CodebaseExtractor()
        self.db = LabelingDatabase()
        self.dataset_base_path = dataset_base_path
        self.group_name = group_name
        self.temp_dir = tempfile.mkdtemp(prefix="vt_labeling_")
        self.use_keyword_filter = use_keyword_filter
        self.scan_only_malicious_files = scan_only_malicious_files
        self.max_repos = max_repos
        self.enable_behavioral_analysis = enable_behavioral_analysis
        self.top_n_files = top_n_files
        self.behavioral_workers = max(1, behavioral_workers)
        self.keyword_analyzer = KeywordAnalyzer() if use_keyword_filter else None
        self.vt_scheduler = VTJobScheduler(
            self.db, self.vt_analyzer, self.extractor,
            hash_ttl_days=HASHCACHE_TTL_DAYS,
            hash_workers=VT_HASH_LOOKUP_WORKERS,
            submit_workers=vt_submit_workers,
            poll_workers=vt_poll_workers
        )
        self._behavioral_semaphore = Semaphore(self.behavioral_workers)
        
        if enable_behavioral_analysis and groq_api_keys:
            vt_key = vt_api_keys[0] if vt_api_keys else None
            llm_key = groq_api_keys[0] if groq_api_keys else None
            if vt_key and llm_key:
                self.behavioral_analyzer = BehavioralAnalysisPipeline(vt_key, llm_key)
                logging.info("Behavioral analysis ENABLED")
            else:
                self.behavioral_analyzer = None
                logging.warning("Behavioral analysis DISABLED (missing API keys)")
        else:
            self.behavioral_analyzer = None
            if not enable_behavioral_analysis:
                logging.info("Behavioral analysis DISABLED by configuration")
        
        logging.info(f"Pipeline initialized with temp dir: {self.temp_dir}")
        if max_repos:
            logging.info(f"Max repositories to process: {max_repos}")
        if use_keyword_filter:
            logging.info("Keyword-based pre-filtering ENABLED")
            if scan_only_malicious_files:
                logging.info("VirusTotal optimization: Scanning ONLY malicious files (file-level filtering)")
            else:
                logging.info("VirusTotal mode: Scanning ALL files in suspicious repositories")
        else:
            logging.info("Keyword-based pre-filtering DISABLED")
    
    def find_hdf5_files(self) -> List[Tuple[str, str]]:
        hdf5_files = []
        group_path = os.path.join(self.dataset_base_path, self.group_name)
        
        if not os.path.exists(group_path):
            logging.error(f"Group path does not exist: {group_path}")
            return []
        repos_filecounts = []

        for repo_dir in os.listdir(group_path):
            repo_path = os.path.join(group_path, repo_dir)
            if os.path.isdir(repo_path):
                for file in os.listdir(repo_path):
                    if file.endswith('.h5'):
                        hdf5_path = os.path.join(repo_path, file)

                        try:
                            with h5py.File(hdf5_path, 'r') as h5file:
                                if 'codebase' in h5file and 'files' in h5file['codebase']:
                                    file_count = len(h5file['codebase']['files'])
                                else:
                                    file_count = 0
                        except Exception as e:
                            logging.warning(f"Error reading HDF5 {hdf5_path}: {e}")
                            file_count = 0
                    
                        repos_filecounts.append((repo_dir, hdf5_path, file_count))
                        break
        
        repos_filecounts.sort(key=lambda x: x[2])

        for repo_dir, hdf5_path, file_count in repos_filecounts[:5]:
            logging.info(f"Repo: {repo_dir}, Files: {file_count}")

        
        logging.info(f"Found {len(repos_filecounts)} HDF5 files")

        return [(repo_dir, hdf5_path) for repo_dir, hdf5_path, _ in repos_filecounts]
    
    def scan_file(self, repo_name: str, file_path: str, full_path: str) -> Optional[Dict]:
        file_hash = self.extractor.calculate_file_hash(full_path)
        
        existing_report = self.vt_analyzer.check_hash_exists(file_hash)
        
        if existing_report:
            logging.info(f"Using existing VT report for {file_path}")
            parsed = self.vt_analyzer.parse_report(existing_report)
        else:
            submit_result = self.vt_analyzer.submit_file(full_path)
            if not submit_result:
                return None
            
            analysis_id, api_key = submit_result
            report = self.vt_analyzer.get_analysis_report(analysis_id, api_key)
            if not report:
                return None
            
            parsed = self.vt_analyzer.parse_report(report)
        
        if parsed:
            self.db.save_file_label(repo_name, file_path, parsed)
        
        return parsed
    
    def process_repository(self, repo_name: str, hdf5_path: str) -> bool:
        start_time = time.time()
        
        try:
            if self.db.is_labeled(repo_name):
                logging.info(f"Repository {repo_name} already labeled")
                return True
            
            logging.info(f"Processing repository: {repo_name}")
            self.db.update_status(repo_name, "processing")
            
            keyword_analysis = None
            passed_keyword_filter = True
            
            if self.use_keyword_filter and self.keyword_analyzer:
                logging.info(f"[{repo_name}] Running keyword pre-screening...")
                
                keyword_analysis = self.keyword_analyzer.analyze_repository(repo_name, hdf5_path)
                
                self.db.save_keyword_prescreen(repo_name, keyword_analysis)
                
                is_suspicious = keyword_analysis.get('is_suspicious', False)
                passed_keyword_filter = is_suspicious
                
                if not is_suspicious:
                    logging.info(f"[{repo_name}] NOT suspicious based on keywords. "
                               f"Skipping VirusTotal scan. Score: {keyword_analysis['combined_score']:.3f}")
                    
                    repo_label = {
                        'total_files': keyword_analysis.get('analyzed_files', 0),
                        'malicious_files': 0,
                        'suspicious_files': 0,
                        'clean_files': keyword_analysis.get('analyzed_files', 0),
                        'file_level_score': 0.0,
                        'keyword_based_score': keyword_analysis['combined_score'],
                        'passed_keyword_filter': False,
                        'is_malicious': False,
                        'processing_time': time.time() - start_time
                    }
                    
                    self.db.save_repo_label(repo_name, repo_label)
                    self.db.update_status(repo_name, "completed_keyword_filter")
                    return True
                else:
                    logging.info(f"[{repo_name}] SUSPICIOUS based on keywords! "
                               f"Proceeding to VirusTotal scan. Score: {keyword_analysis['combined_score']:.3f}, "
                               f"Malicious keywords: {keyword_analysis['malicious_keywords_count']}, "
                               f"Suspicious patterns: {keyword_analysis['suspicious_patterns_count']}")
            
            repo_temp_dir = os.path.join(self.temp_dir, repo_name)
            extracted_files = self.extractor.extract_files_from_hdf5(hdf5_path, repo_temp_dir)
            
            if not extracted_files:
                self.db.update_status(repo_name, "failed", "No files extracted")
                return False
            
            keyword_db = KeywordDatabase()
            file_scores = keyword_db.get_file_scores(repo_name)
            malicious_file_paths = {fs["file_path"] for fs in (file_scores or []) if fs.get("is_malicious")}
            if file_scores and self.scan_only_malicious_files and malicious_file_paths:
                candidates = [
                    (rel_path, full_path) for rel_path, full_path in extracted_files
                    if rel_path in malicious_file_paths and self.extractor.should_scan_file(rel_path)
                ]
                logging.info(f"[{repo_name}] {len(malicious_file_paths)} files marked malicious by keyword; "
                           f"{len(candidates)} candidates for top-N")
            else:
                candidates = [
                    (rel_path, full_path) for rel_path, full_path in extracted_files
                    if self.extractor.should_scan_file(rel_path)
                ]
                if not (file_scores and self.scan_only_malicious_files):
                    logging.info(f"[{repo_name}] {len(candidates)} scanable candidates (no malicious filter or no file_scores)")
            
            def content_getter(rel_path: str) -> Optional[str]:
                for r, full in extracted_files:
                    if r == rel_path:
                        try:
                            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                                return f.read(2048)
                        except Exception:
                            pass
                return None
            
            files_to_scan = select_top_n_files(
                candidates, file_scores_from_db=file_scores, content_getter=content_getter, n=self.top_n_files
            )
            logging.info(f"[{repo_name}] Files considered: {len(candidates)}, top-N chosen: {len(files_to_scan)} (N={self.top_n_files})")
            
            vt_stage_start = time.time()
            self.vt_scheduler.run_vt_scan(repo_name, files_to_scan)
            logging.info(f"[{repo_name}] VT stage wall time: {time.time() - vt_stage_start:.1f}s")
            
            file_labels = self.db.get_file_labels(repo_name)
            if not file_labels:
                logging.warning(f"No scan results for {repo_name}")
                self.db.update_status(repo_name, "failed", "No scan results")
                shutil.rmtree(repo_temp_dir, ignore_errors=True)
                return False
            
            malicious_files = sum(1 for f in file_labels if f['is_malicious'])
            suspicious_files = sum(1 for f in file_labels if f.get('vt_suspicious_count', 0) > 0 and not f['is_malicious'])
            clean_files = len(file_labels) - malicious_files - suspicious_files
            
            file_level_score = (malicious_files * 10 + suspicious_files * 5) / max(len(file_labels), 1)
            keyword_score = keyword_analysis['combined_score'] if keyword_analysis else 0.0
            combined_score = (file_level_score + keyword_score) / 2.0
            
            repo_label = {
                'total_files': len(file_labels),
                'malicious_files': malicious_files,
                'suspicious_files': suspicious_files,
                'clean_files': clean_files,
                'file_level_score': file_level_score,
                'keyword_based_score': keyword_score,
                'passed_keyword_filter': passed_keyword_filter,
                'processing_time': time.time() - start_time
            }
            
            has_vt_malicious = any(f.get("is_malicious") for f in file_labels)
            run_llm = (
                self.key_rotator.groq_keys
                and not has_vt_malicious
                and LLM_SKIP_BELOW_SCORE <= combined_score <= LLM_SKIP_ABOVE_SCORE
            )
            if run_llm:
                try:
                    llm_results = self.llm_analyzer.analyze_repository_gray_zone(file_labels)
                    repo_label.update(llm_results)
                    final_score = llm_results['final_consensus_score']
                    repo_label['is_malicious'] = final_score >= 5.0
                    logging.info(f"LLM gray-zone score for {repo_name}: {final_score:.2f}")
                except Exception as e:
                    logging.error(f"LLM analysis failed for {repo_name}: {e}")
                    repo_label['is_malicious'] = file_level_score >= 5.0
            else:
                repo_label['is_malicious'] = file_level_score >= 5.0
                if has_vt_malicious:
                    logging.info(f"[{repo_name}] Skipping LLM (VT malicious file present)")
                elif combined_score < LLM_SKIP_BELOW_SCORE or combined_score > LLM_SKIP_ABOVE_SCORE:
                    logging.info(f"[{repo_name}] Skipping LLM (combined score {combined_score:.2f} outside gray zone)")
            
            micro_behavior_score = compute_micro_behavior_score(repo_temp_dir)
            behavioral_gate = (
                not repo_label['is_malicious']
                and malicious_files == 0
                and self.behavioral_analyzer
                and micro_behavior_score >= MICRO_BEHAVIOR_THRESHOLD
                and (keyword_score >= 2.0 or file_level_score >= 1.0)
            )
            if behavioral_gate:
                logging.info(f"[{repo_name}] Behavioral gated: micro_behavior={micro_behavior_score}, triggering (concurrency capped)")
                acquired = self._behavioral_semaphore.acquire(timeout=1)
                if not acquired:
                    logging.warning(f"[{repo_name}] Behavioral analysis skipped (concurrency limit)")
                else:
                    try:
                        behavioral_output_dir = os.path.join(self.temp_dir, f"{repo_name}_behavioral")
                        os.makedirs(behavioral_output_dir, exist_ok=True)
                        behavioral_result = self.behavioral_analyzer.analyze_repository(
                            repo_temp_dir,
                            behavioral_output_dir
                        )
                        repo_label['behavioral_analysis'] = behavioral_result
                        if behavioral_result.get('success'):
                            vt_results = behavioral_result.get('vt_results', [])
                            behavioral_malicious = False
                            for vt_result in vt_results:
                                if vt_result.get('vt_result', {}).get('static_report'):
                                    static_report = vt_result['vt_result']['static_report']
                                    stats = static_report.get('data', {}).get('attributes', {}).get('stats', {})
                                    if stats.get('malicious', 0) >= MALICIOUS_THRESHOLD:
                                        behavioral_malicious = True
                                        logging.warning(f"[{repo_name}] Behavioral analysis detected malicious executable: {vt_result['variant_name']}")
                                        break
                            if behavioral_malicious:
                                repo_label['is_malicious'] = True
                                repo_label['malicious_reason'] = 'behavioral_analysis'
                            else:
                                logging.info(f"[{repo_name}] Behavioral analysis: No malicious executables detected")
                        else:
                            logging.warning(f"[{repo_name}] Behavioral analysis failed: {behavioral_result.get('error')}")
                        shutil.rmtree(behavioral_output_dir, ignore_errors=True)
                    except Exception as e:
                        logging.error(f"[{repo_name}] Error in behavioral analysis: {e}")
                        repo_label['behavioral_analysis_error'] = str(e)
                    finally:
                        self._behavioral_semaphore.release()
            
            self.db.save_repo_label(repo_name, repo_label)
            self.db.update_status(repo_name, "completed")
            
            shutil.rmtree(repo_temp_dir, ignore_errors=True)
            
            status = "MALICIOUS" if repo_label['is_malicious'] else "BENIGN"
            logging.info(f"{repo_name}: {status} (files: {malicious_files}/{len(file_labels)}, score: {file_level_score:.2f})")
            
            return True
            
        except Exception as e:
            logging.error(f"Error processing {repo_name}: {e}")
            self.db.update_status(repo_name, "failed", str(e))
            return False
    
    def run_pipeline(self, max_workers: int = 2):
        logging.info("Starting Repository Labeling Pipeline")
        
        hdf5_files = self.find_hdf5_files()
        
        if not hdf5_files:
            logging.warning("No HDF5 files found")
            return
        
        # Apply max_repos limit if specified
        if self.max_repos and len(hdf5_files) > self.max_repos:
            logging.info(f"Limiting to {self.max_repos} repositories (found {len(hdf5_files)} total)")
            hdf5_files = hdf5_files[:self.max_repos]
        
        total = len(hdf5_files)
        successful = 0
        failed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.process_repository, repo_name, hdf5_path): repo_name
                for repo_name, hdf5_path in hdf5_files
            }
            
            for future in as_completed(futures):
                repo_name = futures[future]
                try:
                    if future.result():
                        successful += 1
                    else:
                        failed += 1
                except Exception as e:
                    logging.error(f"Exception processing {repo_name}: {e}")
                    failed += 1
                
                completed = successful + failed
                logging.info(f"Progress: {completed}/{total} ({successful} successful, {failed} failed)")
        
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        self.key_rotator.report_usage()
        
        logging.info("Pipeline Complete")
        logging.info(f"Total: {total}, Success: {successful}, Failed: {failed}")
    
    def cleanup(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)


def get_vt_keys():
    with open("vt_keys.txt", "r") as f:
        keys = [line.strip() for line in f.readlines() if line.strip()]
        return keys


def get_groq_keys():
    try:
        with open("groq_keys.txt", "r") as f:
            keys = [line.strip() for line in f.readlines() if line.strip()]
            return keys
    except FileNotFoundError:
        logging.warning("groq_keys.txt not found, skipping LLM analysis")
        return []


def main():
    VT_API_KEYS = get_vt_keys()
    GROQ_API_KEYS = get_groq_keys()
    
    DATASET_BASE_PATH = os.path.expanduser("~/scratch/crawler/subset")
    GROUP_NAME = "all_repos_fivek"
    MAX_REPOS = None
    
    if not VT_API_KEYS or len(VT_API_KEYS) == 0:
        print("Configure your VT API keys first")
        logging.error("VT API keys not configured")
        return
    
    if not GROQ_API_KEYS or len(GROQ_API_KEYS) == 0:
        print("No Groq API keys found, running without LLM analysis")
        logging.warning("Groq API keys not configured, skipping LLM analysis")
    
    pipeline = RepositoryLabelingPipeline(
        vt_api_keys=VT_API_KEYS,
        groq_api_keys=GROQ_API_KEYS,
        dataset_base_path=DATASET_BASE_PATH,
        group_name=GROUP_NAME,
        use_keyword_filter=True,        
        scan_only_malicious_files=True,
        max_repos=MAX_REPOS,
        enable_behavioral_analysis=True
    )
    
    try:
        pipeline.run_pipeline(max_workers=2)
    except KeyboardInterrupt:
        logging.info("Pipeline interrupted")
        pipeline.cleanup()
    except Exception as e:
        logging.error(f"Pipeline error: {e}")
        pipeline.cleanup()
    finally:
        pipeline.cleanup()


if __name__ == "__main__":
    main()

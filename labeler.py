import os
import json
import h5py
import tempfile
import hashlib
import shutil
import logging
import time
import requests
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple
import sqlite3
from keyword_analyzer import KeywordAnalyzer

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

SUSPICIOUS_FILE_PATTERNS = [
    'exploit', 'payload', 'backdoor', 'shell', 'reverse', 'keylog',
    'inject', 'bypass', 'crack', 'hack', 'malware', 'trojan', 'virus'
]

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
                is_malicious BOOLEAN,
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
            c.execute("""
                INSERT OR REPLACE INTO RepositoryLabels 
                (repo_name, total_files, malicious_files, suspicious_files, clean_files,
                 file_level_score, keyword_based_score, passed_keyword_filter,
                 llm_agent1_score, llm_agent1_reasoning,
                 llm_agent2_score, llm_agent2_reasoning, final_consensus_score,
                 final_consensus_reasoning, is_malicious, labeling_date, processing_time_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                label_data.get('is_malicious'),
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


class VirusTotalAnalyzer:
    def __init__(self, key_rotator: APIKeyRotator):
        self.key_rotator = key_rotator
    
    def check_hash_exists(self, file_hash: str) -> Optional[Dict]:
        api_key = self.key_rotator.get_vt_key()
        headers = {"x-apikey": api_key}
        url = VT_API_URL_FILE_HASH.format(file_hash)
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                logging.info(f"Hash {file_hash[:8]}... found in VT database")
                return response.json()
            elif response.status_code == 404:
                logging.info(f"Hash {file_hash[:8]}... not found in VT database")
                return None
            elif response.status_code == 429:
                api_key = self.key_rotator.get_vt_key()
                headers = {"x-apikey": api_key}
                time.sleep(15)
                response = requests.get(url, headers=headers, timeout=30)
                if response.status_code == 200:
                    return response.json()
                return None
            else:
                return None
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Error checking hash: {e}")
            return None
    
    def submit_file(self, file_path: str) -> Optional[Tuple[str, str]]:
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return None
        
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:
            logging.warning(f"File too large: {file_size} bytes")
            return None
        
        logging.info(f"Submitting {os.path.basename(file_path)} to VT")
        
        api_key = self.key_rotator.get_vt_key()
        headers = {"x-apikey": api_key}
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with open(file_path, "rb") as file:
                    files = {"file": (os.path.basename(file_path), file)}
                    response = requests.post(VT_API_URL_FILES, headers=headers, files=files, timeout=120)
                    
                    if response.status_code == 429:
                        logging.warning("Rate limit hit, rotating key")
                        api_key = self.key_rotator.get_vt_key()
                        headers = {"x-apikey": api_key}
                        time.sleep(15)
                        continue
                    
                    response.raise_for_status()
                    
                    analysis_id = response.json().get("data", {}).get("id")
                    if analysis_id:
                        logging.info(f"File submitted, analysis ID: {analysis_id}")
                        return (analysis_id, api_key)
                    else:
                        logging.error("Could not get analysis ID")
                        return None
                        
            except requests.exceptions.RequestException as e:
                logging.error(f"Error submitting file (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(10 * (attempt + 1))
                    
        return None
    
    def get_analysis_report(self, analysis_id: str, api_key: str, max_wait_time: int = 300) -> Optional[Dict]:
        logging.info(f"Waiting for analysis {analysis_id}")
        
        headers = {"x-apikey": api_key}
        url = VT_API_URL_ANALYSES.format(analysis_id)
        
        start_time = time.time()
        retry_delay = 20
        
        while time.time() - start_time < max_wait_time:
            try:
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 429:
                    logging.warning("Rate limit hit, waiting longer before retry")
                    time.sleep(15)
                    continue
                
                response.raise_for_status()
                result = response.json()
                
                status = result.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    logging.info("Analysis complete")
                    return result
                else:
                    elapsed = int(time.time() - start_time)
                    logging.debug(f"Status: {status}, elapsed: {elapsed}s")
                    time.sleep(retry_delay)
                    
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching report: {e}")
                time.sleep(retry_delay)
        
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


class RepositoryLabelingPipeline:
    def __init__(self, vt_api_keys: List[str], groq_api_keys: List[str], dataset_base_path: str, 
                 group_name: str, use_keyword_filter: bool = True,
                 scan_only_malicious_files: bool = True, max_repos: int = None):
        self.key_rotator = APIKeyRotator(vt_api_keys, groq_api_keys)
        self.vt_analyzer = VirusTotalAnalyzer(self.key_rotator)
        self.llm_analyzer = LLMConsensusAnalyzer(self.key_rotator)
        self.extractor = HDF5CodebaseExtractor()
        self.db = LabelingDatabase()
        self.dataset_base_path = dataset_base_path
        self.group_name = group_name
        self.temp_dir = tempfile.mkdtemp(prefix="vt_labeling_")
        self.use_keyword_filter = use_keyword_filter
        self.scan_only_malicious_files = scan_only_malicious_files
        self.max_repos = max_repos
        self.keyword_analyzer = KeywordAnalyzer() if use_keyword_filter else None
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
        
        for repo_dir in os.listdir(group_path):
            repo_path = os.path.join(group_path, repo_dir)
            if os.path.isdir(repo_path):
                for file in os.listdir(repo_path):
                    if file.endswith('.h5'):
                        hdf5_path = os.path.join(repo_path, file)
                        hdf5_files.append((repo_dir, hdf5_path))
                        break
        
        logging.info(f"Found {len(hdf5_files)} HDF5 files")
        return hdf5_files
    
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
            
            file_scores = keyword_analysis.get('file_scores', []) if keyword_analysis else []
            malicious_file_paths = set()
            
            if file_scores and self.scan_only_malicious_files:
                for file_score in file_scores:
                    if file_score['is_malicious']:
                        malicious_file_paths.add(file_score['file_path'])
                
                logging.info(f"[{repo_name}] {len(malicious_file_paths)} files marked as malicious by keyword analysis")
            
            if malicious_file_paths and self.scan_only_malicious_files:
                files_to_scan = [
                    (rel_path, full_path) for rel_path, full_path in extracted_files 
                    if rel_path in malicious_file_paths and self.extractor.should_scan_file(rel_path)
                ]
                logging.info(f"[{repo_name}] OPTIMIZED MODE: Scanning {len(files_to_scan)} MALICIOUS files "
                           f"(out of {len(extracted_files)} total, skipping {len(extracted_files)-len(files_to_scan)} benign files)")
            else:
                files_to_scan = [
                    (rel_path, full_path) for rel_path, full_path in extracted_files 
                    if self.extractor.should_scan_file(rel_path)
                ]
                mode = "full scan" if not self.scan_only_malicious_files else "no file scores available"
                logging.info(f"[{repo_name}] Scanning {len(files_to_scan)}/{len(extracted_files)} files ({mode})")
            
            file_results = []
            for file_path, full_path in files_to_scan:
                result = self.scan_file(repo_name, file_path, full_path)
                if result:
                    file_results.append(result)
                time.sleep(1)
            
            if not file_results:
                logging.warning(f"No scan results for {repo_name}")
                self.db.update_status(repo_name, "failed", "No scan results")
                shutil.rmtree(repo_temp_dir, ignore_errors=True)
                return False
            
            total_files = len(extracted_files)
            scanned_files = len(files_to_scan)
            skipped_files = total_files - scanned_files
            if skipped_files > 0:
                savings_pct = (skipped_files / total_files) * 100
                logging.info(f"[{repo_name}] VirusTotal scan optimization: "
                           f"Skipped {skipped_files}/{total_files} files ({savings_pct:.1f}% reduction) "
                           f"by only scanning malicious files")
            
            file_labels = self.db.get_file_labels(repo_name)
            
            malicious_files = sum(1 for f in file_labels if f['is_malicious'])
            suspicious_files = sum(1 for f in file_labels if f['vt_suspicious_count'] > 0 and not f['is_malicious'])
            clean_files = len(file_labels) - malicious_files - suspicious_files
            
            file_level_score = (malicious_files * 10 + suspicious_files * 5) / max(len(file_labels), 1)
            keyword_score = keyword_analysis['combined_score'] if keyword_analysis else 0.0
            
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
            
            if self.key_rotator.groq_keys:
                try:
                    llm_results = self.llm_analyzer.analyze_repository(file_labels)
                    repo_label.update(llm_results)
                    
                    final_score = llm_results['final_consensus_score']
                    repo_label['is_malicious'] = final_score >= 5.0
                    
                    logging.info(f"LLM consensus score for {repo_name}: {final_score:.2f}")
                except Exception as e:
                    logging.error(f"LLM analysis failed for {repo_name}: {e}")
                    repo_label['is_malicious'] = file_level_score >= 5.0
            else:
                repo_label['is_malicious'] = file_level_score >= 5.0
            
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
    
    DATASET_BASE_PATH = "fivekdataset"
    GROUP_NAME = "all_repos_fivek"
    MAX_REPOS = None  # Set to an integer to limit number of repos, or None for no limit
    
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
        max_repos=MAX_REPOS
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

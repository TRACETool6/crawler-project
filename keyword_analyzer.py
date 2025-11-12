import os
import re
import json
import logging
import h5py
import numpy as np
import sqlite3
from typing import List, Dict, Set, Tuple, Optional
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

os.environ['USE_TF'] = '0'
os.environ['USE_TORCH'] = '1'

try:
    from transformers import AutoTokenizer, AutoModel
    import torch
    BERT_AVAILABLE = True
except ImportError:
    BERT_AVAILABLE = False
    logging.warning("BERT not available. Install with: pip install transformers torch")

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logging.warning("YARA not available. Install with: pip install yara-python")

from keyword_rules import (
    WeightedKeyword, YaraStyleRule, Context, Severity,
    WEIGHTED_KEYWORDS, YARA_RULES, CO_OCCURRENCE_PATTERNS,
    CROSS_FILE_PATTERNS, get_weighted_keyword_dict, get_keyword_weight
)

#Malicious-oriented keywords based on common malware patterns
MALICIOUS_KEYWORDS = {
    #Exploitation & Attacks
    'exploit', 'payload', 'shellcode', 'reverse_shell', 'backdoor', 'rootkit',
    'privilege_escalation', 'buffer_overflow', 'code_injection', 'sql_injection',
    'xss', 'csrf', 'rce', 'remote_code_execution', 'zero_day', 'vulnerability',
    
    #Malware Types
    'trojan', 'virus', 'worm', 'ransomware', 'spyware', 'adware', 'botnet',
    'keylogger', 'rat', 'remote_access_trojan', 'cryptominer', 'miner',
    
    #Evasion & Obfuscation
    'obfuscate', 'obfuscation', 'encode', 'decode', 'encrypt', 'decrypt',
    'base64', 'hex_encode', 'stealth', 'hide', 'bypass', 'evade', 'anti_debug',
    'anti_vm', 'sandbox_evasion', 'polymorphic', 'metamorphic',
    
    #Credential & Data Theft
    'steal', 'stealer', 'credential', 'password', 'harvest', 'exfiltrate',
    'dump', 'scrape', 'keylog', 'screenshot', 'webcam', 'clipboard',
    'cookie_stealer', 'token_grabber', 'session_hijack',
    
    #Network & C2
    'command_and_control', 'c2', 'beacon', 'callback', 'reverse_connection',
    'bind_shell', 'port_scan', 'network_scan', 'bruteforce', 'ddos',
    'botmaster', 'zombie', 'proxy', 'tunneling',
    
    #System Manipulation
    'inject', 'hook', 'patch', 'modify', 'disable_antivirus', 'kill_process',
    'registry_modification', 'persistence', 'autostart', 'scheduled_task',
    'privilege_abuse', 'process_injection', 'dll_injection',
    
    #Cryptographic Misuse
    'crack', 'cracker', 'keygen', 'license_bypass', 'drm_removal',
    'hash_crack', 'password_crack', 'brute_force',
    
    #Malicious File Operations
    'dropper', 'loader', 'downloader', 'unpacker', 'packer', 'crypter',
    'binder', 'stub', 'malicious_file', 'infected',
    
    #Hacking Tools
    'metasploit', 'meterpreter', 'mimikatz', 'psexec', 'powershell_empire',
    'cobalt_strike', 'empire', 'havoc', 'sliver',
    
    #Suspicious Behavior
    'malicious', 'malware', 'harmful', 'dangerous', 'weaponize', 'attack',
    'victim', 'target', 'infect', 'compromise', 'pwn', 'owned'
}

#Code patterns that are suspicious (regex patterns)
SUSPICIOUS_PATTERNS = [
    # Python patterns
    r'eval\s*\(',  # Dynamic code execution
    r'exec\s*\(',  # Command execution
    r'__import__\s*\(',  # Dynamic imports
    r'compile\s*\(',  # Code compilation
    
    # General system patterns
    r'system\s*\(',  # System calls
    r'popen\s*\(',  # Process execution
    r'subprocess\.',  # Subprocess execution
    r'os\.system',  # OS system calls
    
    # C/C++ patterns
    r'memcpy\s*\(',  # Memory manipulation
    r'strcpy\s*\(',  # Unsafe string operations
    r'gets\s*\(',  # Unsafe input
    r'scanf\s*\(',  # Unsafe input
    r'CreateRemoteThread',  # Process injection (Windows)
    r'VirtualAlloc',  # Memory allocation (Windows API)
    r'WriteProcessMemory',  # Memory writing
    r'OpenProcess',  # Process manipulation
    r'SetWindowsHook',  # Hooking
    r'ptrace\s*\(',  # Process tracing (Unix)
    
    # Java patterns
    r'Runtime\.getRuntime\(\)\.exec',  # Java command execution
    r'ProcessBuilder',  # Java process execution
    r'ClassLoader\.defineClass',  # Dynamic class loading
    r'sun\.misc\.Unsafe',  # Unsafe operations
    
    # PHP patterns
    r'shell_exec\s*\(',  # PHP command execution
    r'passthru\s*\(',  # PHP command execution
    r'base64_decode\s*\(',  # Often used for obfuscation
    r'assert\s*\(',  # PHP assertion (can execute code)
    r'create_function\s*\(',  # PHP dynamic function
    r'preg_replace.*\/e',  # PHP regex with eval
    
    # PowerShell patterns
    r'Invoke-Expression',  # PowerShell code execution
    r'\bIEX\b',  # PowerShell alias for Invoke-Expression
    r'-EncodedCommand',  # PowerShell encoded command
    r'DownloadString',  # PowerShell web download
    r'Start-Process',  # PowerShell process start
    
    # Ruby patterns
    r'Kernel\.eval',  # Ruby code evaluation
    r'instance_eval',  # Ruby instance evaluation
    r'IO\.popen',  # Ruby process execution
    
    # Go patterns
    r'os/exec\.Command',  # Go command execution
    r'syscall\.Exec',  # Go syscall execution
    
    # SQL Injection patterns
    r'UNION\s+SELECT',  # SQL injection
    r"'\s*OR\s*'1'\s*=\s*'1",  # SQL injection
    r'xp_cmdshell',  # SQL Server command execution
    
    # Network patterns (multi-language)
    r'socket\s*\(',  # Network sockets
    r'bind\s*\(',  # Network binding
    r'listen\s*\(',  # Network listening
    r'connect\s*\(',  # Network connection
]

#File extensions to analyze
CODE_EXTENSIONS = {
    '.py', '.js', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.php',
    '.rb', '.go', '.rs', '.swift', '.kt', '.scala', '.sh', '.bash',
    '.ps1', '.bat', '.cmd', '.vbs', '.pl', '.lua', '.r', '.m', '.asm'
}

class YaraScanner:
    """
    YARA-based malware scanner for source code files
    Uses actual YARA rules for industry-standard detection
    """
    
    def __init__(self, rules_dir: str = None):
        """
        Initialize YARA scanner
        
        Args:
            rules_dir: Directory containing YARA rules files
        """
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(__file__), 
            'yara_rules'
        )
        self.rules = None
        self.load_rules()
    
    def load_rules(self) -> bool:
        """
        Load YARA rules from the rules directory
        
        Returns:
            True if rules loaded successfully
        """
        if not YARA_AVAILABLE:
            return False
            
        try:
            rule_files = {}
            rules_path = Path(self.rules_dir)
            
            if not rules_path.exists():
                logging.warning(f"YARA rules directory not found: {self.rules_dir}")
                return False
            
            for ext in ['*.yar', '*.yara']:
                for rule_file in rules_path.glob(ext):
                    namespace = rule_file.stem  
                    rule_files[namespace] = str(rule_file)
            
            if not rule_files:
                logging.warning(f"No YARA rules found in {self.rules_dir}")
                return False
            
            logging.info(f"Loading YARA rules from {len(rule_files)} file(s)...")
            self.rules = yara.compile(filepaths=rule_files)
            logging.info(f"YARA rules loaded successfully: {', '.join(rule_files.keys())}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to load YARA rules: {e}")
            return False
    
    def scan_file(self, file_path: str, file_content: str = None) -> List[Dict]:
        """
        Scan a single file with YARA rules
        
        Args:
            file_path: Path to the file (for context)
            file_content: Content of the file to scan
        
        Returns:
            List of matches with rule details
        """
        if not self.rules:
            return []
        
        try:
            if file_content:
                matches = self.rules.match(data=file_content.encode('utf-8', errors='ignore'))
            else:
                if os.path.exists(file_path):
                    matches = self.rules.match(filepath=file_path)
                else:
                    return []
            
            results = []
            for match in matches:
                result = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                for string_match in match.strings:
                    result['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })
                
                results.append(result)
            
            if results:
                logging.info(f"YARA matched {len(results)} rule(s) in {os.path.basename(file_path)}")
            
            return results
            
        except Exception as e:
            logging.debug(f"YARA scan error for {file_path}: {e}")
            return []
    
    def get_severity_score(self, matches: List[Dict]) -> Tuple[float, str]:
        """
        Calculate severity score from YARA matches
        
        Args:
            matches: List of YARA rule matches
        
        Returns:
            (score, severity_level) tuple
        """
        if not matches:
            return 0.0, "BENIGN"
        
        severity_map = {
            'critical': 100.0,
            'high': 75.0,
            'medium': 50.0,
            'low': 25.0
        }
        
        total_score = 0.0
        max_severity = "BENIGN"
        
        for match in matches:
            severity = match.get('meta', {}).get('severity', 'medium').lower()
            score = severity_map.get(severity, 50.0)
            total_score += score
            
            if severity == 'critical':
                max_severity = "CRITICAL"
            elif severity == 'high' and max_severity not in ['CRITICAL']:
                max_severity = "HIGH"
            elif severity == 'medium' and max_severity not in ['CRITICAL', 'HIGH']:
                max_severity = "MEDIUM"
            elif severity == 'low' and max_severity == "BENIGN":
                max_severity = "LOW"
        
        #Cap at 100
        total_score = min(total_score, 100.0)
        
        return total_score, max_severity
    
    def get_matched_rule_names(self, matches: List[Dict]) -> List[str]:
        """Extract rule names from matches"""
        return [match['rule'] for match in matches]
    
    def get_match_summary(self, matches: List[Dict]) -> str:
        """Generate human-readable summary of matches"""
        if not matches:
            return "No YARA rules matched"
        
        summaries = []
        for match in matches:
            rule = match['rule']
            desc = match.get('meta', {}).get('description', 'No description')
            category = match.get('meta', {}).get('category', 'unknown')
            severity = match.get('meta', {}).get('severity', 'medium')
            
            summaries.append(
                f"[{severity.upper()}] {rule} ({category}): {desc}"
            )
        
        return "\n".join(summaries)


class YaraIntegration:
    """
    Integration layer between YARA scanner and keyword analyzer
    """
    
    def __init__(self, rules_dir: str = None):
        """
        Initialize YARA integration
        
        Args:
            rules_dir: Directory containing YARA rules
        """
        self.scanner = YaraScanner(rules_dir)
        self.enabled = self.scanner.rules is not None
    
    def analyze_file(self, file_path: str, file_content: str) -> Dict:
        """
        Analyze a file with YARA and return results compatible with keyword analyzer
        
        Args:
            file_path: Path to the file
            file_content: Content of the file
        
        Returns:
            Dictionary with YARA analysis results
        """
        if not self.enabled:
            return {
                'yara_matches': [],
                'yara_score': 0.0,
                'yara_severity': 'BENIGN',
                'yara_enabled': False
            }
        
        matches = self.scanner.scan_file(file_path, file_content)
        
        score, severity = self.scanner.get_severity_score(matches)
        
        return {
            'yara_matches': self.scanner.get_matched_rule_names(matches),
            'yara_match_details': matches,
            'yara_score': score,
            'yara_severity': severity,
            'yara_summary': self.scanner.get_match_summary(matches),
            'yara_enabled': True
        }
    
    def analyze_repository(self, files: Dict[str, str]) -> Dict[str, Dict]:
        """
        Analyze multiple files in a repository
        
        Args:
            files: Dictionary of {file_path: file_content}
        
        Returns:
            Dictionary of {file_path: yara_results}
        """
        results = {}
        
        for file_path, content in files.items():
            results[file_path] = self.analyze_file(file_path, content)
        
        return results

class KeywordDatabase:
    """Database for storing keyword analysis results"""
    
    def __init__(self, db_path: str = "keyword_analysis.sqlite"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        #Keyword analysis results table
        c.execute("""
            CREATE TABLE IF NOT EXISTS KeywordAnalysis (
                repo_name TEXT PRIMARY KEY,
                total_files INTEGER,
                analyzed_files INTEGER,
                total_keywords INTEGER,
                malicious_keywords_count INTEGER,
                malicious_keywords TEXT,
                suspicious_patterns_count INTEGER,
                suspicious_patterns TEXT,
                keyword_score REAL,
                pattern_score REAL,
                combined_score REAL,
                is_suspicious BOOLEAN,
                embedding_vector TEXT,
                analysis_date TEXT
            )
        """)
        
        #File-level keyword extraction
        c.execute("""
            CREATE TABLE IF NOT EXISTS FileKeywords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_name TEXT,
                file_path TEXT,
                keywords TEXT,
                malicious_keywords TEXT,
                suspicious_patterns INTEGER,
                UNIQUE(repo_name, file_path)
            )
        """)
        
        conn.commit()
        conn.close()
        logging.info(f"Keyword database initialized at {self.db_path}")
    
    def save_keyword_analysis(self, repo_name: str, analysis_data: Dict):
        """Save keyword analysis results for a repository"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                INSERT OR REPLACE INTO KeywordAnalysis 
                (repo_name, total_files, analyzed_files, total_keywords,
                 malicious_keywords_count, malicious_keywords, suspicious_patterns_count,
                 suspicious_patterns, keyword_score, pattern_score, combined_score,
                 is_suspicious, embedding_vector, analysis_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_name,
                analysis_data.get('total_files', 0),
                analysis_data.get('analyzed_files', 0),
                analysis_data.get('total_keywords', 0),
                analysis_data.get('malicious_keywords_count', 0),
                json.dumps(analysis_data.get('malicious_keywords', [])),
                analysis_data.get('suspicious_patterns_count', 0),
                json.dumps(analysis_data.get('suspicious_patterns', [])),
                analysis_data.get('keyword_score', 0.0),
                analysis_data.get('pattern_score', 0.0),
                analysis_data.get('combined_score', 0.0),
                analysis_data.get('is_suspicious', False),
                json.dumps(analysis_data.get('embedding_vector', [])),
                datetime.now().isoformat()
            ))
            conn.commit()
            logging.info(f"Saved keyword analysis for {repo_name}")
        except Exception as e:
            logging.error(f"Error saving keyword analysis for {repo_name}: {e}")
        finally:
            conn.close()
    
    def save_file_keywords(self, repo_name: str, file_path: str, keywords: List[str],
                          malicious_keywords: List[str], suspicious_patterns: int,
                          file_score: float = 0.0, malicious_keywords_weighted: Dict[str, float] = None):
        """Save keywords extracted from a single file with malicious score"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                INSERT OR REPLACE INTO FileKeywords 
                (repo_name, file_path, keywords, malicious_keywords, suspicious_patterns)
                VALUES (?, ?, ?, ?, ?)
            """, (
                repo_name,
                file_path,
                json.dumps(keywords),
                json.dumps(malicious_keywords),
                suspicious_patterns
            ))
            conn.commit()
        except Exception as e:
            logging.error(f"Error saving file keywords for {repo_name}/{file_path}: {e}")
        finally:
            conn.close()
    
    def save_file_malicious_score(self, repo_name: str, file_path: str, score_data: Dict):
        """Save detailed malicious score for a file"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                CREATE TABLE IF NOT EXISTS FileMaliciousScores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_name TEXT,
                    file_path TEXT,
                    file_extension TEXT,
                    weighted_keyword_score REAL,
                    co_occurrence_score REAL,
                    pattern_score REAL,
                    context_score REAL,
                    total_score REAL,
                    normalized_score REAL,
                    severity_level TEXT,
                    malicious_keywords TEXT,
                    critical_keywords TEXT,
                    yara_matches TEXT,
                    suspicion_reasons TEXT,
                    is_malicious BOOLEAN,
                    analysis_date TEXT,
                    UNIQUE(repo_name, file_path)
                )
            """)
            
            c.execute("""
                INSERT OR REPLACE INTO FileMaliciousScores 
                (repo_name, file_path, file_extension, weighted_keyword_score,
                 co_occurrence_score, pattern_score, context_score, total_score,
                 normalized_score, severity_level, malicious_keywords, critical_keywords,
                 yara_matches, suspicion_reasons, is_malicious, analysis_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                repo_name,
                file_path,
                score_data.get('file_extension', ''),
                score_data.get('weighted_keyword_score', 0.0),
                score_data.get('co_occurrence_score', 0.0),
                score_data.get('pattern_score', 0.0),
                score_data.get('context_score', 0.0),
                score_data.get('total_score', 0.0),
                score_data.get('normalized_score', 0.0),
                score_data.get('severity_level', 'BENIGN'),
                json.dumps(score_data.get('malicious_keywords', [])),
                json.dumps(score_data.get('critical_keywords', [])),
                json.dumps(score_data.get('yara_matches', [])),
                json.dumps(score_data.get('suspicion_reasons', [])),
                score_data.get('is_malicious', False),
                datetime.now().isoformat()
            ))
            conn.commit()
        except Exception as e:
            logging.error(f"Error saving file malicious score for {repo_name}/{file_path}: {e}")
        finally:
            conn.close()
    
    def get_file_scores(self, repo_name: str) -> List[Dict]:
        """Get malicious scores for all files in a repository"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                SELECT file_path, total_score, normalized_score, severity_level,
                       malicious_keywords, critical_keywords, is_malicious
                FROM FileMaliciousScores 
                WHERE repo_name = ?
                ORDER BY total_score DESC
            """, (repo_name,))
            
            results = []
            for row in c.fetchall():
                results.append({
                    'file_path': row[0],
                    'total_score': row[1],
                    'normalized_score': row[2],
                    'severity_level': row[3],
                    'malicious_keywords': json.loads(row[4]) if row[4] else [],
                    'critical_keywords': json.loads(row[5]) if row[5] else [],
                    'is_malicious': bool(row[6])
                })
            return results
        finally:
            conn.close()
    
    def is_analyzed(self, repo_name: str) -> bool:
        """Check if repository has already been analyzed"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("SELECT 1 FROM KeywordAnalysis WHERE repo_name = ?", (repo_name,))
            return c.fetchone() is not None
        finally:
            conn.close()
    
    def get_analysis(self, repo_name: str) -> Optional[Dict]:
        """Retrieve keyword analysis for a repository"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        try:
            c.execute("""
                SELECT combined_score, is_suspicious, malicious_keywords, 
                       malicious_keywords_count, suspicious_patterns_count
                FROM KeywordAnalysis WHERE repo_name = ?
            """, (repo_name,))
            
            row = c.fetchone()
            if row:
                return {
                    'combined_score': row[0],
                    'is_suspicious': bool(row[1]),
                    'malicious_keywords': json.loads(row[2]) if row[2] else [],
                    'malicious_keywords_count': row[3],
                    'suspicious_patterns_count': row[4]
                }
            return None
        finally:
            conn.close()

class BERTKeywordEmbedder:
    """
    Generate BERT-based feature embeddings from keyword sets.
    
    Feed the keyword set of each repository to BERT to obtain 
    a keyword-based feature embedding for downstream analysis.
    """
    
    def __init__(self, model_name: str = "bert-base-uncased"):
        """
        Initialize BERT embedder
        
        Args:
            model_name: Name of the BERT model to use
        """
        self.bert_available = BERT_AVAILABLE
        self.model = None
        self.tokenizer = None
        self.device = None
        
        if self.bert_available:
            try:
                logging.info(f"Loading BERT model: {model_name}")
                self.tokenizer = AutoTokenizer.from_pretrained(model_name)
                self.model = AutoModel.from_pretrained(model_name)
                
                self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
                self.model.to(self.device)
                self.model.eval()
                
                logging.info(f"BERT model loaded successfully on {self.device}")
            except Exception as e:
                logging.error(f"Failed to load BERT model: {e}")
                self.bert_available = False
        else:
            logging.warning("BERT not available. Keyword embeddings will not be generated.")
    
    def encode_keywords(self, keywords: List[str], aggregate: str = 'mean') -> Optional[np.ndarray]:
        """
        Generate BERT embedding from a list of keywords
        
        Args:
            keywords: List of malicious keywords extracted from repository
            aggregate: How to aggregate token embeddings ('mean', 'max', 'cls')
        
        Returns:
            Numpy array of shape (768,) representing the keyword-based embedding,
            or None if BERT is not available
        """
        if not self.bert_available or not keywords:
            return None
        
        try:
            keyword_text = " ".join(keywords)
            
            inputs = self.tokenizer(
                keyword_text,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=512
            )
            
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                last_hidden_state = outputs.last_hidden_state  #Shape: (1, seq_len, 768)
            
            if aggregate == 'mean':
                #Mean pooling over all tokens
                embedding = last_hidden_state.mean(dim=1).squeeze(0)
            elif aggregate == 'max':
                #Max pooling over all tokens
                embedding = last_hidden_state.max(dim=1)[0].squeeze(0)
            elif aggregate == 'cls':
                #Use [CLS] token embedding
                embedding = last_hidden_state[:, 0, :].squeeze(0)
            else:
                raise ValueError(f"Unknown aggregation method: {aggregate}")
            
            embedding_np = embedding.cpu().numpy()
            
            return embedding_np
            
        except Exception as e:
            logging.error(f"Error generating BERT embedding: {e}")
            return None
    
    def encode_repository_keywords(self, 
                                   keyword_data: Dict[str, List[str]], 
                                   aggregate: str = 'mean') -> Optional[np.ndarray]:
        """
        Generate BERT embedding for repository from file-level keywords
        
        Args:
            keyword_data: Dict mapping file paths to their extracted keywords
            aggregate: Aggregation method for token embeddings
        
        Returns:
            Repository-level BERT embedding or None
        """
        if not self.bert_available:
            return None
        
        all_keywords = set()
        for file_keywords in keyword_data.values():
            all_keywords.update(file_keywords)
        
        #Generate embedding from keyword set
        if all_keywords:
            return self.encode_keywords(list(all_keywords), aggregate=aggregate)
        
        return None
    
    def batch_encode_keywords(self, 
                             keyword_lists: List[List[str]], 
                             aggregate: str = 'mean') -> Optional[np.ndarray]:
        """
        Generate BERT embeddings for multiple keyword sets (batch processing)
        
        Args:
            keyword_lists: List of keyword lists (one per repository)
            aggregate: Aggregation method
        
        Returns:
            Numpy array of shape (n_repos, 768) or None
        """
        if not self.bert_available or not keyword_lists:
            return None
        
        embeddings = []
        for keywords in keyword_lists:
            emb = self.encode_keywords(keywords, aggregate=aggregate)
            if emb is not None:
                embeddings.append(emb)
            else:
                embeddings.append(np.zeros(768))
        
        return np.array(embeddings)

class KeywordExtractor:
    """Extract and analyze keywords from source code files with advanced scoring"""
    
    def __init__(self):
        #Weighted keywords
        self.weighted_keywords = get_weighted_keyword_dict()
        self.malicious_keywords = set(self.weighted_keywords.keys())
        self.suspicious_patterns = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]
        
        #Co-occurrence tracking
        self.co_occurrence_patterns = CO_OCCURRENCE_PATTERNS
    
    def extract_keywords_from_text(self, text: str, preserve_context: bool = True) -> Tuple[List[str], Dict]:
        """Extract keywords from code text with context preservation"""
        
        #Extract keywords from different contexts
        contexts = {}
        
        if preserve_context:
            #Extract function names: def function_name, function function_name
            contexts[Context.FUNCTION_NAME] = re.findall(
                r'(?:def|function|func|fn)\s+([a-zA-Z_][a-zA-Z0-9_]*)', text, re.IGNORECASE
            )
            
            #Extract class names: class ClassName
            contexts[Context.CLASS_NAME] = re.findall(
                r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)', text, re.IGNORECASE
            )
            
            #Extract from comments
            comments = re.findall(r'(?://|#)\s*(.+?)$', text, re.MULTILINE)
            contexts[Context.COMMENT] = []
            for comment in comments:
                contexts[Context.COMMENT].extend(
                    re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', comment.lower())
                )
            
            #Extract from imports
            contexts[Context.IMPORT] = re.findall(
                r'(?:import|from|require|include)\s+([a-zA-Z_][a-zA-Z0-9_\.]*)', text, re.IGNORECASE
            )
        
        #Remove comments and strings to focus on actual code
        clean_text = self._remove_comments_and_strings(text)
        
        #Tokenize: split by non-alphanumeric characters
        tokens = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', clean_text.lower())
        
        #Filter out very short tokens and common keywords
        keywords = [t for t in tokens if len(t) >= 3 and not self._is_common_keyword(t)]
        
        return keywords, contexts
    
    def _remove_comments_and_strings(self, text: str) -> str:
        """Remove comments and string literals from code"""
        #Remove multi-line comments /* */
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        #Remove single-line comments //
        text = re.sub(r'//.*?$', '', text, flags=re.MULTILINE)
        #Remove Python comments #
        text = re.sub(r'#.*?$', '', text, flags=re.MULTILINE)
        #Remove string literals (simple approach)
        text = re.sub(r'"[^"]*"', '', text)
        text = re.sub(r"'[^']*'", '', text)
        return text
    
    def _is_common_keyword(self, token: str) -> bool:
        """Check if token is a common programming keyword to filter out"""
        common = {
            'for', 'while', 'if', 'else', 'elif', 'def', 'class', 'return',
            'import', 'from', 'as', 'try', 'except', 'finally', 'with',
            'int', 'str', 'bool', 'float', 'list', 'dict', 'set', 'tuple',
            'true', 'false', 'none', 'null', 'void', 'public', 'private',
            'protected', 'static', 'const', 'var', 'let', 'function'
        }
        return token in common
    
    def find_malicious_keywords(self, keywords: List[str], contexts: Dict = None) -> Dict[str, float]:
        """Find malicious keywords and return with weighted scores"""
        keyword_set = set(keywords)
        found = {}  #keyword -> weighted_score
        
        for keyword in keyword_set:
            if keyword in self.weighted_keywords:
                wk = self.weighted_keywords[keyword]
                
                context = Context.VARIABLE_NAME  # default
                if contexts:
                    if keyword in contexts.get(Context.FUNCTION_NAME, []):
                        context = Context.FUNCTION_NAME
                    elif keyword in contexts.get(Context.CLASS_NAME, []):
                        context = Context.CLASS_NAME
                    elif keyword in contexts.get(Context.COMMENT, []):
                        context = Context.COMMENT
                    elif keyword in contexts.get(Context.IMPORT, []):
                        context = Context.IMPORT
                
                #Check if required context is present
                has_required = True
                if wk.requires_context:
                    has_required = any(req in keyword_set for req in wk.requires_context)
                
                #Check if excluding context is present
                if wk.excludes_context:
                    if any(excl in keyword_set for excl in wk.excludes_context):
                        continue  
                
                weight = wk.calculate_weight(context, has_required)
                found[keyword] = weight
            else:
                #Partial match
                for mal_kw, wk in self.weighted_keywords.items():
                    if mal_kw in keyword or keyword in mal_kw:
                        if keyword not in found:
                            #Use reduced weight for partial matches
                            weight = wk.calculate_weight(Context.VARIABLE_NAME) * 0.5
                            found[keyword] = weight
        
        return found
    
    def find_suspicious_patterns(self, text: str) -> List[str]:
        """Find suspicious code patterns in text"""
        found = []
        
        for pattern in self.suspicious_patterns:
            matches = pattern.findall(text)
            if matches:
                found.extend(matches)
        
        return list(set(found))
    
    def analyze_file(self, file_path: str, content: str) -> Dict:
        """Analyze a single file for keywords and patterns with weighted scoring"""
        keywords, contexts = self.extract_keywords_from_text(content, preserve_context=True)
        malicious_kws_weighted = self.find_malicious_keywords(keywords, contexts)
        suspicious_pats = self.find_suspicious_patterns(content)
        
        #Calculate co-occurrence boost within file
        co_occurrence_boost = self._calculate_co_occurrence_boost(
            set(malicious_kws_weighted.keys())
        )

        #Calculate weighted score for this file
        base_score = sum(malicious_kws_weighted.values())
        file_score = base_score + co_occurrence_boost
        
        return {
            'file_path': file_path,
            'keywords': keywords,
            'malicious_keywords': list(malicious_kws_weighted.keys()),
            'malicious_keywords_weighted': malicious_kws_weighted,
            'suspicious_patterns': suspicious_pats,
            'malicious_count': len(malicious_kws_weighted),
            'pattern_count': len(suspicious_pats),
            'file_score': file_score,
            'co_occurrence_boost': co_occurrence_boost
        }
    
    def _calculate_co_occurrence_boost(self, keywords: Set[str]) -> float:
        """Calculate boost from co-occurring keywords"""
        boost = 0.0
        
        for (kw1, kw2), weight in self.co_occurrence_patterns.items():
            if kw1 in keywords and kw2 in keywords:
                boost += weight
        
        return boost
    
    def calculate_file_malicious_score(self, file_analysis: Dict, yara_matches: List[str] = None) -> Dict:
        """
        Calculate comprehensive malicious score for a single file
        
        Args:
            file_analysis: Dictionary from analyze_file_from_hdf5() containing:
                - file_path, keywords, malicious_keywords_weighted, file_score, etc.
            yara_matches: List of YARA rule names that matched this file
        
        Returns:
            Dictionary with detailed scoring breakdown:
            - weighted_keyword_score: Sum of all weighted keyword scores
            - co_occurrence_score: Boost from keyword co-occurrence
            - pattern_score: Score from YARA pattern matches
            - context_score: Score based on file name/extension
            - total_score: Combined raw score
            - normalized_score: Score normalized to 0-100 scale
            - severity_level: BENIGN, LOW, MEDIUM, HIGH, CRITICAL
            - malicious_keywords: List of malicious keywords found
            - critical_keywords: List of CRITICAL severity keywords
            - suspicion_reasons: List of human-readable reasons
            - is_malicious: Boolean flag if file exceeds threshold
        """
        yara_matches = yara_matches or []
        file_path = file_analysis.get('file_path', '')
        
        #1. Weighted keyword score 
        malicious_kws = file_analysis.get('malicious_keywords_weighted', {})
        weighted_score = sum(malicious_kws.values())
        
        #2. Co-occurrence score 
        co_occurrence_score = file_analysis.get('co_occurrence_boost', 0.0)
        
        #3. Pattern score from YARA matches
        pattern_score = len(yara_matches) * 50.0  #Each YARA match adds 50 points
        
        #4. Context score based on file characteristics
        context_score = 0.0
        file_ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path).lower()
        
        #Suspicious file extensions
        suspicious_extensions = {'.exe', '.dll', '.so', '.dylib', '.bat', '.ps1', '.vbs', '.sh', '.scr'}
        if file_ext in suspicious_extensions:
            context_score += 30.0
        
        #Suspicious file names
        suspicious_names = ['payload', 'exploit', 'backdoor', 'trojan', 'virus', 'malware',
                           'hack', 'crack', 'keygen', 'loader', 'injector', 'stealer']
        if any(name in file_name for name in suspicious_names):
            context_score += 40.0
        
        #Hidden files (Unix-style)
        if file_name.startswith('.') and len(file_name) > 1 and file_ext not in {'.py', '.js', '.txt'}:
            context_score += 10.0
        
        total_score = weighted_score + co_occurrence_score + pattern_score + context_score
        
        #Normalize score to 0-100 scale using logarithmic-like scaling
        max_expected_score = 500.0  
        normalized_score = min(100.0, (total_score / max_expected_score) * 100.0)
        
        severity_level = "BENIGN"
        if normalized_score >= 80:
            severity_level = "CRITICAL"
        elif normalized_score >= 60:
            severity_level = "HIGH"
        elif normalized_score >= 40:
            severity_level = "MEDIUM"
        elif normalized_score >= 20:
            severity_level = "LOW"
        
        #Identify critical keywords
        critical_keywords = []
        for kw in malicious_kws.keys():
            for weighted_kw in self.weighted_keywords.values():
                if weighted_kw.keyword == kw and weighted_kw.severity == Severity.CRITICAL:
                    critical_keywords.append(kw)
                    break
        
        #Build suspicion reasons
        suspicion_reasons = []
        if critical_keywords:
            suspicion_reasons.append(f"Contains {len(critical_keywords)} critical keywords: {', '.join(critical_keywords[:3])}")
        if len(malicious_kws) > 3:
            suspicion_reasons.append(f"High concentration of malicious keywords ({len(malicious_kws)} found)")
        if yara_matches:
            suspicion_reasons.append(f"Matches {len(yara_matches)} YARA rules: {', '.join(yara_matches[:3])}")
        if co_occurrence_score > 0:
            suspicion_reasons.append(f"Keyword co-occurrence detected (+{co_occurrence_score:.1f} points)")
        if context_score > 0:
            suspicion_reasons.append(f"Suspicious file characteristics (+{context_score:.1f} points)")
        
        #Determine if file is malicious (threshold: 40/100 normalized score)
        is_malicious = normalized_score >= 40.0 or len(critical_keywords) >= 2
        
        return {
            'file_path': file_path,
            'file_extension': file_ext,
            'weighted_keyword_score': weighted_score,
            'co_occurrence_score': co_occurrence_score,
            'pattern_score': pattern_score,
            'context_score': context_score,
            'total_score': total_score,
            'normalized_score': normalized_score,
            'severity_level': severity_level,
            'malicious_keywords': list(malicious_kws.keys()),
            'critical_keywords': critical_keywords,
            'yara_matches': yara_matches,
            'suspicion_reasons': suspicion_reasons,
            'is_malicious': is_malicious,
            'keyword_count': len(file_analysis.get('keywords', [])),
            'malicious_keyword_count': len(malicious_kws)
        }


class KeywordAnalyzer:
    """
    Main keyword analysis pipeline with YARA-style rules and advanced scoring
    
    Includes BERT-based keyword embedding generation for feature representation
    """
    
    def __init__(self, use_real_yara: bool = True, use_bert: bool = False):
        self.keyword_extractor = KeywordExtractor()
        self.db = KeywordDatabase()
        self.yara_rules = YARA_RULES
        self.cross_file_patterns = CROSS_FILE_PATTERNS
        self.bert_embedder = None
        self.use_bert = use_bert
        if use_bert and BERT_AVAILABLE:
            try:
                self.bert_embedder = BERTKeywordEmbedder()
                logging.info("BERT keyword embedder initialized")
            except Exception as e:
                logging.warning(f"Failed to initialize BERT embedder: {e}")
                self.use_bert = False
        elif use_bert and not BERT_AVAILABLE:
            logging.warning("BERT requested but not available. Install with: pip install transformers torch")
            self.use_bert = False
        self.real_yara = None
        if use_real_yara and YARA_AVAILABLE:
            try:
                self.real_yara = YaraIntegration()
                if self.real_yara.enabled:
                    logging.info("Real YARA scanner enabled")
                else:
                    logging.info("Real YARA scanner disabled (rules not loaded)")
                    self.real_yara = None
            except Exception as e:
                logging.warning(f"Failed to initialize real YARA scanner: {e}")
                self.real_yara = None
        else:
            if not use_real_yara:
                logging.info("Real YARA scanner disabled by configuration")
            elif not YARA_AVAILABLE:
                logging.info("Real YARA scanner not available (install yara-python)")
        
        self.weighted_score_threshold = 50.0  #Weighted score threshold
        self.critical_keyword_threshold = 1   #Even 1 critical keyword is suspicious
        self.yara_rule_match_threshold = 1    #Number of YARA rules to trigger
        self.pattern_threshold = 3            #Number of suspicious patterns
    
    def extract_from_hdf5(self, hdf5_path: str) -> List[Tuple[str, str]]:
        """Extract text files from HDF5"""
        try:
            files_data = []
            
            with h5py.File(hdf5_path, 'r') as h5file:
                if 'codebase' not in h5file or 'files' not in h5file['codebase']:
                    logging.warning(f"No codebase found in {hdf5_path}")
                    return []
                
                files_group = h5file['codebase']['files']
                
                for file_key in files_group.keys():
                    file_group = files_group[file_key]
                    
                    file_path = file_group['path'][()].decode('utf-8')
                    content_type = file_group['content_type'][()].decode('utf-8')
                    
                    ext = os.path.splitext(file_path)[1].lower()
                    if content_type == 'text' and ext in CODE_EXTENSIONS:
                        content = file_group['content'][()].decode('utf-8', errors='ignore')
                        files_data.append((file_path, content))
            
            return files_data
        except Exception as e:
            logging.error(f"Error extracting from HDF5 {hdf5_path}: {e}")
            return []
    
    def analyze_repository(self, repo_name: str, hdf5_path: str) -> Dict:
        """Analyze a repository using advanced weighted scoring and YARA rules"""
        logging.info(f"Analyzing keywords for repository: {repo_name}")
        
        files_data = self.extract_from_hdf5(hdf5_path)
        
        if not files_data:
            logging.warning(f"No code files found in {repo_name}")
            return {
                'repo_name': repo_name,
                'total_files': 0,
                'analyzed_files': 0,
                'is_suspicious': False,
                'combined_score': 0.0,
                'weighted_score': 0.0
            }
        
        #Analyze each file
        all_keywords = []
        all_malicious_keywords_weighted = {}  # keyword -> total_weight
        all_patterns = []
        file_analyses = []
        total_file_score = 0.0
        real_yara_results = {}  
        
        # Track keywords per file for cross-file analysis
        keywords_per_file = []
        file_scores_list = []  # Track individual file scores for reporting
        
        for file_path, content in files_data:
            file_analysis = self.keyword_extractor.analyze_file(file_path, content)
            
            if self.real_yara:
                yara_result = self.real_yara.analyze_file(file_path, content)
                file_analysis['real_yara'] = yara_result
                real_yara_results[file_path] = yara_result
            else:
                file_analysis['real_yara'] = {'yara_enabled': False, 'yara_matches': []}
            
            file_analyses.append(file_analysis)
            
            all_keywords.extend(file_analysis['keywords'])
            all_patterns.extend(file_analysis['suspicious_patterns'])
            
            # Aggregate weighted malicious keywords
            for kw, weight in file_analysis['malicious_keywords_weighted'].items():
                all_malicious_keywords_weighted[kw] = \
                    all_malicious_keywords_weighted.get(kw, 0) + weight
            
            # Track file score
            total_file_score += file_analysis['file_score']
            
            # Track keywords for cross-file analysis
            keywords_per_file.append(set(file_analysis['malicious_keywords']))
            
            # Save file-level data
            self.db.save_file_keywords(
                repo_name,
                file_path,
                file_analysis['keywords'],
                file_analysis['malicious_keywords'],
                file_analysis['pattern_count']
            )
        
        # Count occurrences and get most common
        keyword_counter = Counter(all_keywords)
        malicious_keyword_counter = Counter(all_malicious_keywords_weighted.keys())
        
        # Calculate weighted score
        weighted_keyword_score = sum(all_malicious_keywords_weighted.values())
        
        # Check for critical keywords
        critical_keywords = []
        for kw, weight in all_malicious_keywords_weighted.items():
            wk = self.keyword_extractor.weighted_keywords.get(kw)
            if wk and wk.severity == Severity.CRITICAL:
                critical_keywords.append(kw)
        
        # Apply YARA-style rules
        yara_matches = []
        yara_score = 0.0
        
        all_keywords_set = set(all_keywords)
        all_patterns_set = set(all_patterns)
        
        for rule in self.yara_rules:
            matched, score = rule.matches(all_keywords_set, all_patterns_set)
            if matched:
                yara_matches.append({
                    'rule_name': rule.name,
                    'description': rule.description,
                    'severity': rule.severity.name,
                    'score': score
                })
                yara_score += score
                logging.info(f"[{repo_name}] YARA rule matched: {rule.name} (score: {score:.1f})")
        
        # Calculate cross-file pattern boost
        cross_file_boost = self._calculate_cross_file_boost(keywords_per_file)
        
        # Calculate and save individual file malicious scores
        for file_analysis in file_analyses:
            # Match YARA-style rules that apply to this specific file
            file_yara_matches = []
            file_keywords_set = set(file_analysis['malicious_keywords'])
            file_patterns_set = set(file_analysis['suspicious_patterns'])
            
            for rule in self.yara_rules:
                matched, score = rule.matches(file_keywords_set, file_patterns_set)
                if matched:
                    file_yara_matches.append(rule.name)
            
            # Add real YARA matches if available
            if 'real_yara' in file_analysis and file_analysis['real_yara']['yara_enabled']:
                real_yara = file_analysis['real_yara']
                # Combine pattern-based and real YARA matches
                file_yara_matches.extend(real_yara['yara_matches'])
                # Remove duplicates
                file_yara_matches = list(set(file_yara_matches))
            
            # Calculate comprehensive file score
            file_score_data = self.keyword_extractor.calculate_file_malicious_score(
                file_analysis,
                file_yara_matches
            )
            
            # Boost score with real YARA results if available
            if 'real_yara' in file_analysis and file_analysis['real_yara']['yara_enabled']:
                real_yara = file_analysis['real_yara']
                # Add real YARA score to total (capped contribution)
                yara_boost = min(real_yara['yara_score'], 50.0)  # Cap at 50 points
                file_score_data['total_score'] += yara_boost
                file_score_data['normalized_score'] = min(
                    (file_score_data['total_score'] / 400.0) * 100, 
                    100.0
                )
                # Update severity if real YARA found critical issues
                if real_yara['yara_severity'] in ['CRITICAL', 'HIGH']:
                    file_score_data['severity_level'] = real_yara['yara_severity']
                    file_score_data['is_malicious'] = True
            
            # Save file score to database
            self.db.save_file_malicious_score(repo_name, file_analysis['file_path'], file_score_data)
            
            # Track for reporting
            file_scores_list.append(file_score_data)
        
        # Pattern score: normalized pattern count
        pattern_count = len(all_patterns)
        pattern_score = min(pattern_count / 20.0, 1.0) * 100  # Scale to 0-100
        
        # Combined weighted score
        combined_weighted_score = (
            weighted_keyword_score +
            yara_score +
            cross_file_boost +
            pattern_score
        )
        
        # Normalize combined score for reporting (0-1 scale)
        # Higher scores indicate higher suspicion
        max_possible_score = 200.0  # Estimated maximum
        normalized_score = min(combined_weighted_score / max_possible_score, 1.0)
        
        # Determine if suspicious using multiple criteria
        is_suspicious = (
            len(critical_keywords) >= self.critical_keyword_threshold or
            len(yara_matches) >= self.yara_rule_match_threshold or
            weighted_keyword_score >= self.weighted_score_threshold or
            pattern_count >= self.pattern_threshold
        )
        
        # Determine reason for suspicion
        suspicion_reasons = []
        if len(critical_keywords) > 0:
            suspicion_reasons.append(f"Critical keywords: {', '.join(critical_keywords[:5])}")
        if len(yara_matches) > 0:
            suspicion_reasons.append(f"YARA rules: {', '.join([m['rule_name'] for m in yara_matches[:3]])}")
        if weighted_keyword_score >= self.weighted_score_threshold:
            suspicion_reasons.append(f"High weighted score: {weighted_keyword_score:.1f}")
        if pattern_count >= self.pattern_threshold:
            suspicion_reasons.append(f"Suspicious patterns: {pattern_count}")
        
        embedding_vector = None
        if self.use_bert and self.bert_embedder:
            try:
                malicious_keywords_list = list(all_malicious_keywords_weighted.keys())
                
                if malicious_keywords_list:
                    logging.info(f"[{repo_name}] Generating BERT embedding from {len(malicious_keywords_list)} keywords")
                    embedding_vector = self.bert_embedder.encode_keywords(
                        malicious_keywords_list, 
                        aggregate='mean'
                    )
                    
                    if embedding_vector is not None:
                        logging.info(f"[{repo_name}] BERT embedding generated: shape {embedding_vector.shape}")
                    else:
                        logging.warning(f"[{repo_name}] Failed to generate BERT embedding")
            except Exception as e:
                logging.error(f"[{repo_name}] Error generating BERT embedding: {e}")
                embedding_vector = None

        analysis_data = {
            'repo_name': repo_name,
            'total_files': len(files_data),
            'analyzed_files': len(files_data),
            'total_keywords': len(set(all_keywords)),
            'malicious_keywords_count': len(all_malicious_keywords_weighted),
            'malicious_keywords': [kw for kw, _ in malicious_keyword_counter.most_common(50)],
            'malicious_keywords_weighted': all_malicious_keywords_weighted,
            'critical_keywords': critical_keywords,
            'suspicious_patterns_count': pattern_count,
            'suspicious_patterns': list(set(all_patterns))[:50],
            'keyword_score': weighted_keyword_score,
            'pattern_score': pattern_score,
            'yara_score': yara_score,
            'yara_matches': yara_matches,
            'cross_file_boost': cross_file_boost,
            'combined_score': normalized_score,  #0-1 normalized
            'weighted_score': combined_weighted_score,  #Raw weighted score
            'is_suspicious': is_suspicious,
            'suspicion_reasons': suspicion_reasons,
            'embedding_vector': embedding_vector.tolist() if embedding_vector is not None else [],
            'file_scores': file_scores_list,  #Individual file malicious scores
            'files_analyzed': len(file_scores_list),
            'malicious_files_count': sum(1 for fs in file_scores_list if fs['is_malicious']),
            'high_risk_files': [fs for fs in file_scores_list if fs['severity_level'] in ['CRITICAL', 'HIGH']]
        }
        
        #Save to database
        self.db.save_keyword_analysis(repo_name, analysis_data)
        
        status = "SUSPICIOUS" if is_suspicious else "BENIGN"
        reasons = "; ".join(suspicion_reasons) if suspicion_reasons else "No threats detected"
        logging.info(f"{repo_name}: {status} (weighted_score: {combined_weighted_score:.1f}, "
                    f"normalized: {normalized_score:.3f}) - {reasons}")
        
        return analysis_data
    
    def _calculate_cross_file_boost(self, keywords_per_file: List[Set[str]]) -> float:
        """Calculate boost from keywords appearing across multiple files"""
        boost = 0.0
        
        #Check each cross-file pattern
        for pattern_set, description, multiplier in self.cross_file_patterns:
            #Check if pattern keywords are distributed across files
            files_with_pattern_kw = 0
            for file_keywords in keywords_per_file:
                if any(kw in file_keywords for kw in pattern_set):
                    files_with_pattern_kw += 1
            
            #If pattern spans multiple files, it's more suspicious
            if files_with_pattern_kw >= 2:
                all_repo_keywords = set().union(*keywords_per_file)
                if pattern_set.issubset(all_repo_keywords):
                    boost += multiplier * 10.0 
                    logging.info(f"Cross-file pattern detected: {description}")
        
        return boost
    
    def is_suspicious(self, repo_name: str) -> bool:
        """Check if a repository has been marked as suspicious"""
        analysis = self.db.get_analysis(repo_name)
        if analysis:
            return analysis['is_suspicious']
        return False
    
    def get_analysis(self, repo_name: str) -> Optional[Dict]:
        """Get analysis results for a repository"""
        return self.db.get_analysis(repo_name)


def main():
    """Test the keyword analyzer"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    analyzer = KeywordAnalyzer()
    
    test_repo = "test_repo"
    test_hdf5 = "fivekdataset/test_group/test_repo/codebase.h5"
    
    if os.path.exists(test_hdf5):
        result = analyzer.analyze_repository(test_repo, test_hdf5)
        print(json.dumps(result, indent=2))
    else:
        print(f"Test file not found: {test_hdf5}")


if __name__ == "__main__":
    main()

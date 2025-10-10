#!/usr/bin/env python3
"""
YARA-based malware detection module for repository scanning.
Complements keyword-based detection with pattern matching and behavioral analysis.
"""

import os
import yara
import json
import logging
from typing import Dict, List, Tuple, Any
from pathlib import Path

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

class YaraRepositoryScanner:
    """
    YARA-based scanner for detecting malicious patterns in repository source code.
    """
    
    def __init__(self, rules_dir: str = None):
        """
        Initialize YARA scanner with rules.
        
        Args:
            rules_dir: Directory containing YARA rule files
        """
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(__file__), "yara_rules")
        self.compiled_rules = None
        self.rule_stats = {}
        
        # Supported file extensions for scanning
        self.scannable_extensions = {
            '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp', '.cs', '.go',
            '.rs', '.php', '.rb', '.swift', '.kt', '.scala', '.clj', '.hs', '.ml',
            '.r', '.m', '.sh', '.bash', '.zsh', '.ps1', '.sql', '.html', '.css',
            '.xml', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
            '.md', '.txt', '.rst', '.tex', '.dockerfile', '.makefile', '.cmake',
            '.bat', '.cmd', '.vbs', '.powershell'
        }
        
    def initialize_rules(self):
        """Load and compile YARA rules."""
        if not os.path.exists(self.rules_dir):
            logging.warning(f"YARA rules directory not found: {self.rules_dir}")
            self._create_default_rules()
        
        try:
            # Find all .yar and .yara files
            rule_files = {}
            for rule_file in Path(self.rules_dir).glob("*.yar*"):
                rule_name = rule_file.stem
                rule_files[rule_name] = str(rule_file)
            
            if not rule_files:
                logging.warning("No YARA rule files found, creating default rules")
                self._create_default_rules()
                # Retry loading
                for rule_file in Path(self.rules_dir).glob("*.yar*"):
                    rule_name = rule_file.stem
                    rule_files[rule_name] = str(rule_file)
            
            # Compile rules
            self.compiled_rules = yara.compile(filepaths=rule_files)
            logging.info(f"Successfully compiled {len(rule_files)} YARA rule files")
            
        except Exception as e:
            logging.error(f"Error compiling YARA rules: {e}")
            raise
    
    def _create_default_rules(self):
        """Create default YARA rules for malware detection."""
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # Backdoor/RAT detection rules
        backdoor_rules = """
rule Backdoor_Patterns
{
    meta:
        description = "Detects common backdoor and RAT patterns"
        category = "backdoor"
        severity = "high"
    
    strings:
        // More specific patterns to reduce false positives
        $reverse_shell_1 = /socket\\.connect\\s*\\(\\s*\\([^)]+\\)\\s*\\).*exec\s*\(/
        $command_exec = /exec\s*\(\s*[^)]*recv\s*\([^)]*\)\s*\)/
        $c2_communication = /(command.{0,20}control|c2.{0,10}server)/i
        $persistence_registry = /reg\s+add.*CurrentVersion.*Run.*backdoor/i
        $remote_access_tool = /remote.{0,10}access.{0,20}(tool|trojan|backdoor)/i
        $shell_backdoor = /(reverse|bind).{0,20}shell.{0,20}(backdoor|trojan)/i
        
    condition:
        any of them
}

rule Keylogger_Patterns
{
    meta:
        description = "Detects keylogger patterns and behaviors"
        category = "keylogger"
        severity = "high"
    
    strings:
        $keylog_1 = /pynput.*keyboard/
        $keylog_2 = /on_press.*key/
        $keylog_3 = /GetAsyncKeyState/i
        $keylog_4 = /SetWindowsHookEx/i
        $keylog_5 = /keylog/i
        $clipboard_1 = /clipboard/i
        $credential_1 = /(password|credential).{0,30}(steal|extract|harvest)/i
        
    condition:
        any of them
}
"""
        
        # Cryptocurrency miner rules - more specific
        crypto_rules = """
rule Cryptocurrency_Miner
{
    meta:
        description = "Detects cryptocurrency mining patterns"
        category = "cryptominer"
        severity = "medium"
    
    strings:
        // More specific mining patterns
        $mining_1 = /stratum\\+tcp/i
        $mining_2 = /cryptonight/i
        $cryptojacking = /cryptojacking/i
        $coinhive = /coinhive/i
        $mining_malware = /(mining|miner).{0,20}(malware|trojan|backdoor)/i
        // Only flag wallets in suspicious contexts
        $suspicious_wallet = /(steal|hijack|mine).{0,50}[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        
    condition:
        any of them
}

rule Steganography_Hiding
{
    meta:
        description = "Detects steganography and data hiding techniques"
        category = "evasion"
        severity = "medium"
    
    strings:
        $stego_1 = /steganography/i
        $stego_2 = /hide.{0,20}(data|payload)/i
        $stego_3 = /embed.{0,20}(data|code)/i
        $obfuscation = /obfuscat/i
        $base64_suspicious = /base64.*exec/i
        $hex_decode = /hex.*decode.*exec/i
        
    condition:
        any of them
}
"""
        
        # Ransomware detection rules  
        ransomware_rules = """
rule Ransomware_Patterns
{
    meta:
        description = "Detects ransomware patterns and behaviors"
        category = "ransomware"
        severity = "critical"
    
    strings:
        $encrypt_1 = /encrypt.{0,30}files?/i
        $encrypt_2 = /AES|Fernet|cipher/
        $ransom_1 = /(ransom|decrypt).{0,30}(note|message|instructions)/i
        $ransom_2 = /pay.{0,20}bitcoin/i
        $ransom_3 = /files?.{0,20}encrypted/i
        $file_ext_change = /\\.(locked|encrypted|crypto|vault)/
        $bitcoin_demand = /[0-9.]+\s*(BTC|bitcoin)/i
        $tor_contact = /\.onion/
        $file_destruction = /remove|delete.*original/i
        
    condition:
        2 of them
}

rule Network_Scanner_Botnet
{
    meta:
        description = "Detects network scanning and botnet patterns"
        category = "botnet"
        severity = "high"
    
    strings:
        $botnet_1 = /botnet/i
        $ddos_1 = /(ddos|dos).{0,20}attack/i
        $ddos_2 = /flood.{0,20}(target|server)/i
        $port_scan = /port.{0,20}scan/i
        $network_scan = /nmap|masscan/i
        $irc_bot = /irc.{0,30}(bot|command)/i
        $zombie = /zombie/i
        
    condition:
        any of them
}
"""
        
        # Vulnerability exploitation rules
        exploit_rules = """
rule Exploit_Patterns
{
    meta:
        description = "Detects exploit patterns and vulnerability usage"
        category = "exploit"
        severity = "high"
    
    strings:
        $exploit_1 = /exploit/i
        $payload_1 = /payload/i
        $shellcode = /shellcode/i
        $buffer_overflow = /buffer.{0,20}overflow/i
        $injection_1 = /(sql|code|command).{0,20}injection/i
        $injection_2 = /inject/i
        $privilege_esc = /privilege.{0,20}escalat/i
        $zero_day = /zero.{0,5}day/i
        $vulnerability = /vulnerabilit/i
        $rce = /(remote|code).{0,20}execut/i
        
    condition:
        any of them
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detects suspicious network communication patterns"
        category = "network"
        severity = "medium"
    
    strings:
        $suspicious_url_1 = /https?:\\/\\/[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/
        $suspicious_url_2 = /[a-z0-9]{10,}\.tk|\.ml|\.ga|\.cf/i
        $tor_hidden = /[a-z2-7]{16}\.onion/i
        $exfiltration = /exfiltrat/i
        $beacon = /beacon/i
        $tunnel = /tunnel/i
        $proxy_chain = /proxy.{0,20}chain/i
        
    condition:
        any of them
}
"""
        
        # Write rule files
        rules = {
            "backdoor_rules.yara": backdoor_rules,
            "crypto_rules.yara": crypto_rules,
            "ransomware_rules.yara": ransomware_rules,
            "exploit_rules.yara": exploit_rules
        }
        
        for filename, content in rules.items():
            rule_path = os.path.join(self.rules_dir, filename)
            with open(rule_path, 'w') as f:
                f.write(content)
        
        logging.info(f"Created {len(rules)} default YARA rule files in {self.rules_dir}")
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        Scan repository with YARA rules.
        
        Args:
            repo_path: Path to repository to scan
            
        Returns:
            Dictionary containing scan results
        """
        if not self.compiled_rules:
            self.initialize_rules()
        
        logging.info(f"Starting YARA scan of repository: {repo_path}")
        
        scan_results = {
            'total_files_scanned': 0,
            'total_matches': 0,
            'matches_by_category': {},
            'matches_by_severity': {},
            'file_matches': {},
            'rule_statistics': {},
            'threat_score': 0.0,
            'detected_categories': set()
        }
        
        try:
            for root, dirs, files in os.walk(repo_path):
                # Skip .git directory
                if ".git" in dirs:
                    dirs.remove(".git")
                
                for filename in files:
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, repo_path)
                    
                    # Check if file should be scanned
                    if self._should_scan_file(filename):
                        file_matches = self._scan_file(file_path)
                        if file_matches:
                            scan_results['file_matches'][rel_path] = file_matches
                            scan_results['total_matches'] += len(file_matches)
                            
                            # Update statistics
                            for match in file_matches:
                                category = match.get('category', 'unknown')
                                severity = match.get('severity', 'low')
                                
                                scan_results['matches_by_category'][category] = \
                                    scan_results['matches_by_category'].get(category, 0) + 1
                                scan_results['matches_by_severity'][severity] = \
                                    scan_results['matches_by_severity'].get(severity, 0) + 1
                                scan_results['detected_categories'].add(category)
                        
                        scan_results['total_files_scanned'] += 1
            
            # Calculate threat score
            scan_results['threat_score'] = self._calculate_threat_score(scan_results)
            scan_results['detected_categories'] = list(scan_results['detected_categories'])
            
            logging.info(f"YARA scan completed: {scan_results['total_matches']} matches in "
                        f"{scan_results['total_files_scanned']} files")
            
            return scan_results
            
        except Exception as e:
            logging.error(f"Error during YARA scan of {repo_path}: {e}")
            return {}
    
    def _should_scan_file(self, filename: str) -> bool:
        """Determine if file should be scanned based on extension."""
        _, ext = os.path.splitext(filename.lower())
        return (ext in self.scannable_extensions or 
                filename.lower() in ['makefile', 'dockerfile', 'readme'])
    
    def _scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan individual file with YARA rules."""
        try:
            matches = self.compiled_rules.match(file_path)
            results = []
            
            for match in matches:
                match_info = {
                    'rule_name': match.rule,
                    'category': match.meta.get('category', 'unknown'),
                    'severity': match.meta.get('severity', 'low'),
                    'description': match.meta.get('description', ''),
                    'strings': []
                }
                
                # Extract matched strings with their positions
                for string_match in match.strings:
                    match_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': len(string_match.instances)
                    })
                
                results.append(match_info)
            
            return results
            
        except Exception as e:
            logging.warning(f"Error scanning file {file_path}: {e}")
            return []
    
    def _calculate_threat_score(self, scan_results: Dict[str, Any]) -> float:
        """Calculate overall threat score based on matches."""
        if scan_results['total_matches'] == 0:
            return 0.0
        
        # Severity weights
        severity_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.2
        }
        
        # Category multipliers
        category_multipliers = {
            'ransomware': 1.2,
            'backdoor': 1.1,
            'keylogger': 1.1,
            'botnet': 1.0,
            'cryptominer': 0.8,
            'exploit': 1.0,
            'evasion': 0.9,
            'network': 0.7
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        
        for severity, count in scan_results['matches_by_severity'].items():
            weight = severity_weights.get(severity, 0.1)
            weighted_score += count * weight
            total_weight += count
        
        # Apply category multipliers
        for category in scan_results['detected_categories']:
            multiplier = category_multipliers.get(category, 1.0)
            weighted_score *= multiplier
        
        # Normalize by total files scanned
        if scan_results['total_files_scanned'] > 0:
            normalized_score = weighted_score / scan_results['total_files_scanned']
        else:
            normalized_score = 0.0
        
        return min(round(normalized_score, 3), 1.0)


# Integration function for existing codebase
def scan_repository_yara(repo_path: str, rules_dir: str = None) -> Dict[str, Any]:
    """
    Convenience function to scan repository with YARA rules.
    
    Args:
        repo_path: Path to repository to scan
        rules_dir: Optional custom rules directory
        
    Returns:
        Dictionary containing YARA scan results
    """
    scanner = YaraRepositoryScanner(rules_dir)
    return scanner.scan_repository(repo_path)
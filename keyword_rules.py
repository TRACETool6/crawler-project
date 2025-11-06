"""
Advanced Keyword Rules with YARA-style pattern matching
Provides weighted keywords, context rules, and co-occurrence patterns
"""

from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    """Severity levels for keyword matches"""
    CRITICAL = 10.0
    HIGH = 7.5
    MEDIUM = 5.0
    LOW = 2.5
    INFO = 1.0

class Context(Enum):
    """Context types for better scoring"""
    FUNCTION_NAME = "function_name"
    VARIABLE_NAME = "variable_name"
    COMMENT = "comment"
    STRING_LITERAL = "string_literal"
    IMPORT = "import"
    CLASS_NAME = "class_name"
    FILE_PATH = "file_path"

@dataclass
class WeightedKeyword:
    """A keyword with weight, severity, and context rules"""
    keyword: str
    weight: float
    severity: Severity
    context_boost: Dict[Context, float]  #Context-specific weight multipliers
    requires_context: List[str] = None   #Must appear with these words
    excludes_context: List[str] = None   #Don't match if these words present
    description: str = ""
    
    def calculate_weight(self, context: Context, has_required: bool = True) -> float:
        """Calculate weight based on context"""
        base_weight = self.weight * self.severity.value
        context_multiplier = self.context_boost.get(context, 1.0)
        
        #Reduce weight if required context is missing
        if self.requires_context and not has_required:
            return base_weight * 0.3
        
        return base_weight * context_multiplier


@dataclass
class YaraStyleRule:
    """YARA-style rule for complex pattern matching"""
    name: str
    description: str
    severity: Severity
    
    all_of: List[str] = None  #All keywords must be present
    
    n_of: Tuple[int, List[str]] = None  #(n, keywords) - at least n must be present
    
    any_of: List[str] = None  #Any keyword present
    
    patterns: List[Dict[str, any]] = None  #Complex pattern matching
    
    file_extensions: List[str] = None  #Only match in these file types
    max_file_size: int = None  #Max file size in bytes
    
    #Scoring
    base_score: float = 5.0
    
    def matches(self, keywords: Set[str], patterns: Set[str], 
                file_ext: str = None, file_size: int = None) -> Tuple[bool, float]:
        """Check if rule matches and return score"""
        
        if self.file_extensions and file_ext not in self.file_extensions:
            return False, 0.0
        
        if self.max_file_size and file_size and file_size > self.max_file_size:
            return False, 0.0
        
        matches_found = 0
        
        if self.all_of:
            if not all(kw in keywords for kw in self.all_of):
                return False, 0.0
            matches_found += 1
        
        if self.n_of:
            n, kw_list = self.n_of
            count = sum(1 for kw in kw_list if kw in keywords)
            if count < n:
                return False, 0.0
            matches_found += 1
        
        if self.any_of:
            if not any(kw in keywords for kw in self.any_of):
                return False, 0.0
            matches_found += 1
        
        if self.patterns:
            for pattern_rule in self.patterns:
                if not self._check_pattern(pattern_rule, keywords, patterns):
                    return False, 0.0
            matches_found += 1
        
        if matches_found == 0:
            return False, 0.0
        
        #Calculate score based on severity and number of matches
        score = self.base_score * self.severity.value * matches_found
        return True, score
    
    def _check_pattern(self, pattern_rule: Dict, keywords: Set[str], 
                      patterns: Set[str]) -> bool:
        """Check complex pattern rules"""
        pattern_type = pattern_rule.get('type')
        
        if pattern_type == 'keyword':
            return pattern_rule.get('value') in keywords
        elif pattern_type == 'pattern':
            return pattern_rule.get('value') in patterns
        elif pattern_type == 'and':
            return all(self._check_pattern(p, keywords, patterns) 
                      for p in pattern_rule.get('conditions', []))
        elif pattern_type == 'or':
            return any(self._check_pattern(p, keywords, patterns) 
                      for p in pattern_rule.get('conditions', []))
        
        return False


#WEIGHTED KEYWORD DATABASE
WEIGHTED_KEYWORDS = [
    #CRITICAL SEVERITY - Definitely malicious
    WeightedKeyword(
        keyword="ransomware",
        weight=10.0,
        severity=Severity.CRITICAL,
        context_boost={
            Context.FUNCTION_NAME: 2.0,
            Context.CLASS_NAME: 2.0,
            Context.FILE_PATH: 1.5,
            Context.COMMENT: 0.5
        },
        description="Ransomware-related code"
    ),
    WeightedKeyword(
        keyword="keylogger",
        weight=10.0,
        severity=Severity.CRITICAL,
        context_boost={
            Context.FUNCTION_NAME: 2.0,
            Context.CLASS_NAME: 2.0,
            Context.VARIABLE_NAME: 1.5,
            Context.COMMENT: 0.3
        },
        description="Keystroke logging functionality"
    ),
    WeightedKeyword(
        keyword="backdoor",
        weight=9.0,
        severity=Severity.CRITICAL,
        context_boost={
            Context.FUNCTION_NAME: 2.0,
            Context.CLASS_NAME: 1.8,
            Context.COMMENT: 0.4
        },
        description="Backdoor implementation"
    ),
    WeightedKeyword(
        keyword="rootkit",
        weight=10.0,
        severity=Severity.CRITICAL,
        context_boost={
            Context.FUNCTION_NAME: 2.0,
            Context.CLASS_NAME: 2.0,
            Context.FILE_PATH: 1.5
        },
        description="Rootkit functionality"
    ),
    WeightedKeyword(
        keyword="cryptominer",
        weight=9.0,
        severity=Severity.CRITICAL,
        context_boost={
            Context.FUNCTION_NAME: 1.8,
            Context.CLASS_NAME: 1.8,
            Context.COMMENT: 0.5
        },
        description="Unauthorized cryptocurrency mining"
    ),
    
    #HIGH SEVERITY - Very suspicious
    WeightedKeyword(
        keyword="exploit",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={
            Context.FUNCTION_NAME: 1.8,
            Context.CLASS_NAME: 1.5,
            Context.COMMENT: 0.6  
        },
        excludes_context=["test", "demo", "example", "tutorial"],
        description="Exploitation code"
    ),
    WeightedKeyword(
        keyword="payload",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={
            Context.FUNCTION_NAME: 1.8,
            Context.VARIABLE_NAME: 1.5,
            Context.COMMENT: 0.7
        },
        requires_context=["execute", "inject", "deliver", "send"],
        description="Malicious payload"
    ),
    WeightedKeyword(
        keyword="shellcode",
        weight=9.0,
        severity=Severity.HIGH,
        context_boost={
            Context.FUNCTION_NAME: 2.0,
            Context.VARIABLE_NAME: 1.8,
            Context.STRING_LITERAL: 1.5
        },
        description="Shellcode execution"
    ),
    WeightedKeyword(
        keyword="reverse_shell",
        weight=9.0,
        severity=Severity.HIGH,
        context_boost={
            Context.FUNCTION_NAME: 2.0,
            Context.CLASS_NAME: 1.8,
            Context.COMMENT: 0.5
        },
        description="Reverse shell connection"
    ),
    WeightedKeyword(
        keyword="privilege_escalation",
        weight=8.5,
        severity=Severity.HIGH,
        context_boost={
            Context.FUNCTION_NAME: 1.8,
            Context.COMMENT: 0.7
        },
        description="Privilege escalation"
    ),
    WeightedKeyword(
        keyword="code_injection",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={
            Context.FUNCTION_NAME: 1.8,
            Context.CLASS_NAME: 1.5
        },
        description="Code injection attack"
    ),
    WeightedKeyword(
        keyword="stealer",
        weight=9.0,
        severity=Severity.HIGH,
        context_boost={
            Context.FUNCTION_NAME: 2.0,
            Context.CLASS_NAME: 2.0,
            Context.FILE_PATH: 1.5
        },
        requires_context=["password", "credential", "token", "cookie", "data"],
        description="Information stealer"
    ),
    WeightedKeyword(
        keyword="exfiltrate",
        weight=8.5,
        severity=Severity.HIGH,
        context_boost={
            Context.FUNCTION_NAME: 1.8,
            Context.VARIABLE_NAME: 1.5
        },
        requires_context=["data", "file", "credential", "send"],
        description="Data exfiltration"
    ),
    
    #MEDIUM SEVERITY - Suspicious but could be legitimate
    WeightedKeyword(
        keyword="obfuscate",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={
            Context.FUNCTION_NAME: 1.5,
            Context.COMMENT: 0.8
        },
        excludes_context=["deobfuscate", "analysis", "research"],
        description="Code obfuscation"
    ),
    WeightedKeyword(
        keyword="encrypt",
        weight=2.0,
        severity=Severity.LOW,
        context_boost={
            Context.FUNCTION_NAME: 1.0,
            Context.COMMENT: 0.3
        },
        requires_context=["malicious", "bypass", "hide", "stealth", "ransom"],  # Only suspicious with these
        description="Encryption (context-dependent)"
    ),
    WeightedKeyword(
        keyword="bypass",
        weight=6.5,
        severity=Severity.MEDIUM,
        context_boost={
            Context.FUNCTION_NAME: 1.5,
            Context.COMMENT: 0.7
        },
        requires_context=["antivirus", "firewall", "security", "detection"],
        description="Security bypass"
    ),
    WeightedKeyword(
        keyword="persistence",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={
            Context.FUNCTION_NAME: 1.5,
            Context.COMMENT: 0.8
        },
        requires_context=["registry", "autostart", "scheduled", "service"],
        description="Persistence mechanism"
    ),
    WeightedKeyword(
        keyword="hook",
        weight=5.5,
        severity=Severity.MEDIUM,
        context_boost={
            Context.FUNCTION_NAME: 1.4,
            Context.COMMENT: 0.6
        },
        requires_context=["keyboard", "mouse", "window", "api"],
        description="API/Event hooking"
    ),
    
    #LOW SEVERITY - Need more context
    WeightedKeyword(
        keyword="download",
        weight=2.0,
        severity=Severity.LOW,
        context_boost={
            Context.FUNCTION_NAME: 1.0,
            Context.COMMENT: 0.5
        },
        requires_context=["execute", "run", "payload", "malicious"],
        description="File download (context-dependent)"
    ),
    WeightedKeyword(
        keyword="execute",
        weight=2.5,
        severity=Severity.LOW,
        context_boost={
            Context.FUNCTION_NAME: 1.2,
            Context.COMMENT: 0.5
        },
        requires_context=["remote", "arbitrary", "shellcode", "payload"],
        description="Code execution (context-dependent)"
    ),
    WeightedKeyword(
        keyword="password",
        weight=2.0,
        severity=Severity.LOW,
        context_boost={
            Context.FUNCTION_NAME: 1.0,
            Context.COMMENT: 0.3
        },
        requires_context=["steal", "dump", "crack", "harvest", "grab"],
        description="Password-related (context-dependent)"
    ),
]



#YARA-STYLE DETECTION RULES
YARA_RULES = [
    #Rule 1: Credential Stealer
    YaraStyleRule(
        name="credential_stealer",
        description="Detects credential stealing functionality",
        severity=Severity.CRITICAL,
        all_of=["password", "steal"],
        any_of=["browser", "chrome", "firefox", "credential", "token"],
        base_score=8.0
    ),
    
    #Rule 2: Reverse Shell
    YaraStyleRule(
        name="reverse_shell_connection",
        description="Detects reverse shell establishment",
        severity=Severity.CRITICAL,
        n_of=(2, ["socket", "connect", "shell", "cmd", "bash", "powershell"]),
        base_score=9.0
    ),
    
    #Rule 3: Ransomware Behavior
    YaraStyleRule(
        name="ransomware_behavior",
        description="Detects ransomware-like behavior",
        severity=Severity.CRITICAL,
        n_of=(3, ["encrypt", "decrypt", "payment", "bitcoin", "ransom", "victim"]),
        base_score=10.0
    ),
    
    #Rule 4: Keylogger
    YaraStyleRule(
        name="keylogger_detection",
        description="Detects keystroke logging",
        severity=Severity.CRITICAL,
        all_of=["keyboard", "hook"],
        any_of=["log", "capture", "record", "monitor"],
        base_score=9.0
    ),
    
    #Rule 5: Process Injection
    YaraStyleRule(
        name="process_injection",
        description="Detects process injection techniques",
        severity=Severity.HIGH,
        n_of=(2, ["inject", "process", "memory", "write", "allocate"]),
        base_score=8.0
    ),
    
    #Rule 6: Persistence Mechanism
    YaraStyleRule(
        name="persistence_mechanism",
        description="Detects persistence establishment",
        severity=Severity.HIGH,
        n_of=(2, ["registry", "autostart", "scheduled_task", "service", "startup"]),
        any_of=["persist", "maintain", "install"],
        base_score=7.0
    ),
    
    #Rule 7: C2 Communication
    YaraStyleRule(
        name="c2_communication",
        description="Detects command and control communication",
        severity=Severity.HIGH,
        n_of=(2, ["connect", "send", "receive", "command", "control"]),
        any_of=["beacon", "callback", "heartbeat", "exfiltrate"],
        base_score=8.0
    ),
    
    #Rule 8: Anti-Analysis
    YaraStyleRule(
        name="anti_analysis",
        description="Detects anti-analysis techniques",
        severity=Severity.HIGH,
        n_of=(2, ["debugger", "virtual", "sandbox", "detect", "check"]),
        any_of=["bypass", "evade", "anti"],
        base_score=7.5
    ),
    
    #Rule 9: Network Scanner
    YaraStyleRule(
        name="network_scanner",
        description="Detects network scanning functionality",
        severity=Severity.MEDIUM,
        all_of=["scan", "port"],
        any_of=["network", "host", "ip", "target"],
        base_score=5.0
    ),
    
    #Rule 10: Crypto Mining
    YaraStyleRule(
        name="crypto_mining",
        description="Detects cryptocurrency mining",
        severity=Severity.HIGH,
        n_of=(2, ["mining", "miner", "hashrate", "pool", "stratum"]),
        any_of=["monero", "bitcoin", "ethereum", "crypto"],
        base_score=8.0
    ),
    
    #Rule 11: RAT (Remote Access Trojan)
    YaraStyleRule(
        name="remote_access_trojan",
        description="Detects RAT functionality",
        severity=Severity.CRITICAL,
        n_of=(3, ["remote", "control", "screen", "keyboard", "mouse", "file", "command"]),
        base_score=9.0
    ),
    
    #Rule 12: Data Exfiltration
    YaraStyleRule(
        name="data_exfiltration",
        description="Detects data exfiltration",
        severity=Severity.HIGH,
        all_of=["send", "data"],
        any_of=["exfiltrate", "upload", "transfer", "steal"],
        base_score=8.0
    ),
]


#CO-OCCURRENCE PATTERNS
CO_OCCURRENCE_PATTERNS = {
    #Pattern: (keyword1, keyword2) -> weight_boost
    #These pairs together are more suspicious than individually
    
    ("socket", "execute"): 3.0,
    ("download", "execute"): 3.5,
    ("encrypt", "ransom"): 5.0,
    ("encrypt", "bitcoin"): 4.5,
    ("password", "steal"): 4.0,
    ("password", "dump"): 3.5,
    ("keylog", "send"): 4.0,
    ("screenshot", "send"): 3.0,
    ("credential", "exfiltrate"): 4.5,
    ("privilege", "escalate"): 3.5,
    ("bypass", "antivirus"): 4.0,
    ("bypass", "firewall"): 3.5,
    ("inject", "process"): 4.0,
    ("inject", "code"): 3.5,
    ("hook", "keyboard"): 3.5,
    ("backdoor", "persist"): 4.0,
    ("reverse", "shell"): 4.5,
    ("command", "control"): 3.0,
    ("obfuscate", "malicious"): 3.5,
    ("exploit", "vulnerability"): 3.0,
    ("rootkit", "hide"): 4.0,
    ("trojan", "payload"): 3.5,
    ("virus", "spread"): 3.0,
    ("botnet", "zombie"): 3.5,
    ("mine", "crypto"): 3.0,
    ("scan", "exploit"): 2.5,
    ("brute", "force"): 2.5,
}


# ============================================================================
# FILE-LEVEL CO-OCCURRENCE PATTERNS (Cross-file analysis)
# ============================================================================

CROSS_FILE_PATTERNS = {
    # Pattern: Set of keywords that are suspicious when spread across files
    # Format: (keywords_set, description, weight_multiplier)
    
    (frozenset({"encrypt", "decrypt", "payment"}), 
     "Ransomware components across files", 2.5),
    
    (frozenset({"keylog", "send", "server"}), 
     "Keylogger with exfiltration", 2.8),
    
    (frozenset({"download", "execute", "payload"}), 
     "Dropper/Loader pattern", 2.3),
    
    (frozenset({"steal", "password", "browser"}), 
     "Browser credential stealer", 2.5),
    
    (frozenset({"inject", "process", "memory"}), 
     "Process injection framework", 2.4),
    
    (frozenset({"bypass", "antivirus", "disable"}), 
     "Security evasion framework", 2.6),
    
    (frozenset({"backdoor", "persist", "hide"}), 
     "Persistent backdoor", 2.7),
    
    (frozenset({"scan", "exploit", "target"}), 
     "Exploitation framework", 2.2),
}

#Java-specific malicious patterns
WEIGHTED_KEYWORDS.extend([
    WeightedKeyword(
        keyword="Runtime.getRuntime().exec",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.FUNCTION_NAME: 1.5},
        description="Java command execution"
    ),
    WeightedKeyword(
        keyword="ProcessBuilder",
        weight=7.0,
        severity=Severity.HIGH,
        context_boost={Context.CLASS_NAME: 1.8, Context.VARIABLE_NAME: 1.5},
        description="Java process execution"
    ),
    WeightedKeyword(
        keyword="sun.misc.Unsafe",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.IMPORT: 2.0, Context.STRING_LITERAL: 1.5},
        description="Java unsafe memory operations"
    ),
    WeightedKeyword(
        keyword="ClassLoader.defineClass",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="Java dynamic class loading"
    ),
    WeightedKeyword(
        keyword="invokespecial",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        description="Java bytecode manipulation"
    ),
])

#C/C++ specific malicious patterns
WEIGHTED_KEYWORDS.extend([
    WeightedKeyword(
        keyword="system(",
        weight=7.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.FUNCTION_NAME: 1.5},
        description="C/C++ system command execution"
    ),
    WeightedKeyword(
        keyword="execve",
        weight=8.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 2.0, Context.FUNCTION_NAME: 1.8},
        description="Unix exec family - program execution"
    ),
    WeightedKeyword(
        keyword="CreateRemoteThread",
        weight=9.0,
        severity=Severity.CRITICAL,
        context_boost={Context.STRING_LITERAL: 2.0, Context.FUNCTION_NAME: 2.0},
        description="Windows process injection"
    ),
    WeightedKeyword(
        keyword="VirtualAllocEx",
        weight=8.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 2.0, Context.FUNCTION_NAME: 1.8},
        description="Windows memory allocation in remote process"
    ),
    WeightedKeyword(
        keyword="WriteProcessMemory",
        weight=8.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 2.0, Context.FUNCTION_NAME: 1.8},
        description="Windows memory writing to remote process"
    ),
    WeightedKeyword(
        keyword="ptrace",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.FUNCTION_NAME: 1.5},
        description="Unix process tracing/debugging"
    ),
    WeightedKeyword(
        keyword="LD_PRELOAD",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 2.0, Context.VARIABLE_NAME: 1.8},
        description="Unix library preloading for hooking"
    ),
    WeightedKeyword(
        keyword="gets(",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        description="Unsafe C function - buffer overflow risk"
    ),
    WeightedKeyword(
        keyword="strcpy(",
        weight=5.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.3},
        excludes_context=["strncpy", "strcpy_s"],
        description="Unsafe string copy - buffer overflow risk"
    ),
])

#PHP-specific malicious patterns
WEIGHTED_KEYWORDS.extend([
    WeightedKeyword(
        keyword="eval(",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.FUNCTION_NAME: 1.5},
        description="PHP dynamic code execution"
    ),
    WeightedKeyword(
        keyword="base64_decode",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        requires_context=["eval", "exec", "system"],
        description="PHP base64 decoding with execution"
    ),
    WeightedKeyword(
        keyword="shell_exec",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.FUNCTION_NAME: 1.5},
        description="PHP shell command execution"
    ),
    WeightedKeyword(
        keyword="passthru",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="PHP command execution with output"
    ),
    WeightedKeyword(
        keyword="assert(",
        weight=7.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.5},
        description="PHP assertion - can execute code"
    ),
    WeightedKeyword(
        keyword="create_function",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="PHP dynamic function creation"
    ),
    WeightedKeyword(
        keyword="preg_replace",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        requires_context=["/e", "eval"],
        description="PHP regex with code execution"
    ),
])

#Ruby-specific malicious patterns
WEIGHTED_KEYWORDS.extend([
    WeightedKeyword(
        keyword="Kernel.eval",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="Ruby code evaluation"
    ),
    WeightedKeyword(
        keyword="instance_eval",
        weight=7.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.5},
        description="Ruby instance evaluation"
    ),
    WeightedKeyword(
        keyword="system(",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="Ruby system command execution"
    ),
    WeightedKeyword(
        keyword="IO.popen",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="Ruby process execution"
    ),
    WeightedKeyword(
        keyword="send(",
        weight=5.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.3},
        requires_context=["method", "call"],
        description="Ruby dynamic method invocation"
    ),
])

#Go-specific malicious patterns
WEIGHTED_KEYWORDS.extend([
    WeightedKeyword(
        keyword="os/exec.Command",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.IMPORT: 1.5},
        description="Go command execution"
    ),
    WeightedKeyword(
        keyword="syscall.Exec",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="Go direct syscall execution"
    ),
    WeightedKeyword(
        keyword="unsafe.Pointer",
        weight=7.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5, Context.VARIABLE_NAME: 1.3},
        description="Go unsafe memory operations"
    ),
    WeightedKeyword(
        keyword="reflect.Call",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        description="Go dynamic function invocation"
    ),
])

#Rust-specific malicious patterns
WEIGHTED_KEYWORDS.extend([
    WeightedKeyword(
        keyword="std::process::Command",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.IMPORT: 1.5},
        description="Rust command execution"
    ),
    WeightedKeyword(
        keyword="unsafe {",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        description="Rust unsafe code block"
    ),
    WeightedKeyword(
        keyword="libc::system",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="Rust C library system call"
    ),
    WeightedKeyword(
        keyword="std::mem::transmute",
        weight=7.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        description="Rust type transmutation"
    ),
])

#PowerShell-specific malicious patterns
WEIGHTED_KEYWORDS.extend([
    WeightedKeyword(
        keyword="Invoke-Expression",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.FUNCTION_NAME: 1.5},
        description="PowerShell dynamic code execution"
    ),
    WeightedKeyword(
        keyword="IEX",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8},
        description="PowerShell Invoke-Expression alias"
    ),
    WeightedKeyword(
        keyword="Invoke-WebRequest",
        weight=6.0,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        requires_context=["IEX", "Invoke-Expression", "downloadstring"],
        description="PowerShell web download with execution"
    ),
    WeightedKeyword(
        keyword="Start-Process",
        weight=6.5,
        severity=Severity.MEDIUM,
        context_boost={Context.STRING_LITERAL: 1.5},
        description="PowerShell process execution"
    ),
    WeightedKeyword(
        keyword="-EncodedCommand",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.STRING_LITERAL: 1.5},
        description="PowerShell encoded command execution"
    ),
    WeightedKeyword(
        keyword="DownloadString",
        weight=7.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.5},
        requires_context=["IEX", "Invoke"],
        description="PowerShell download and execute"
    ),
])

#SQL Injection patterns (multi-language)
WEIGHTED_KEYWORDS.extend([
    WeightedKeyword(
        keyword="UNION SELECT",
        weight=7.5,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 1.8, Context.COMMENT: 0.5},
        description="SQL injection UNION attack"
    ),
    WeightedKeyword(
        keyword="' OR '1'='1",
        weight=8.0,
        severity=Severity.HIGH,
        context_boost={Context.STRING_LITERAL: 2.0},
        description="SQL injection authentication bypass"
    ),
    WeightedKeyword(
        keyword="xp_cmdshell",
        weight=9.0,
        severity=Severity.CRITICAL,
        context_boost={Context.STRING_LITERAL: 2.0, Context.STRING_LITERAL: 1.8},
        description="SQL Server command execution"
    ),
])


def get_weighted_keyword_dict() -> Dict[str, WeightedKeyword]:
    """Convert list to dictionary for quick lookup"""
    return {wk.keyword: wk for wk in WEIGHTED_KEYWORDS}


def get_keyword_weight(keyword: str, context: Context = None) -> float:
    """Get weight for a keyword in given context"""
    keyword_dict = get_weighted_keyword_dict()
    
    if keyword in keyword_dict:
        wk = keyword_dict[keyword]
        if context:
            return wk.calculate_weight(context)
        return wk.weight * wk.severity.value
    
    return 1.0  #Default weight for unknown keywords

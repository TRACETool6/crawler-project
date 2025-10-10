#!/usr/bin/env python3
"""
Configuration modes for the security analyzer to balance false positives vs detection rate.
"""

class SecurityAnalysisMode:
    """Configuration modes for different use cases."""
    
    CONSERVATIVE = "conservative"  # Low false positives, higher threshold
    BALANCED = "balanced"         # Medium sensitivity, good for general use
    AGGRESSIVE = "aggressive"     # High sensitivity, good for malware hunting

# Threshold configurations for each mode
RISK_THRESHOLDS = {
    SecurityAnalysisMode.CONSERVATIVE: {
        'critical': 0.8,
        'high': 0.6,
        'medium': 0.4,
        'low': 0.2,
        'malicious_keyword_threshold': 15,
        'yara_match_threshold': 8,
        'vuln_high_threshold': 8
    },
    SecurityAnalysisMode.BALANCED: {
        'critical': 0.7,
        'high': 0.5,
        'medium': 0.3,
        'low': 0.15,
        'malicious_keyword_threshold': 8,
        'yara_match_threshold': 4,
        'vuln_high_threshold': 4
    },
    SecurityAnalysisMode.AGGRESSIVE: {
        'critical': 0.6,
        'high': 0.4,
        'medium': 0.2,
        'low': 0.1,
        'malicious_keyword_threshold': 3,
        'yara_match_threshold': 2,
        'vuln_high_threshold': 1
    }
}
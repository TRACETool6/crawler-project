#!/usr/bin/env python3
"""
Enhanced malware detection pipeline combining keyword extraction, YARA rules, and vulnerability scanning.
Provides comprehensive security analysis of repository source code.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from keyword_extractor import MaliciousKeywordExtractor
from yara_scanner import YaraRepositoryScanner
from vulnerability_scanner import VulnerabilityScanner, VulnerabilitySeverity

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

class EnhancedSecurityAnalyzer:
    """
    Comprehensive security analyzer combining multiple detection techniques:
    1. Keyword-based malicious pattern detection
    2. YARA rule pattern matching
    3. Static vulnerability analysis
    """
    
    def __init__(self, 
                 vulnerability_threshold: str = 'medium',
                 yara_rules_dir: Optional[str] = None):
        """
        Initialize the enhanced security analyzer.
        
        Args:
            vulnerability_threshold: Minimum vulnerability severity to report
            yara_rules_dir: Custom directory for YARA rules
        """
        self.keyword_extractor = MaliciousKeywordExtractor()
        self.yara_scanner = YaraRepositoryScanner(yara_rules_dir)
        
        # Map threshold string to enum
        threshold_map = {
            'critical': VulnerabilitySeverity.CRITICAL,
            'high': VulnerabilitySeverity.HIGH,
            'medium': VulnerabilitySeverity.MEDIUM,
            'low': VulnerabilitySeverity.LOW,
            'info': VulnerabilitySeverity.INFO
        }
        threshold_enum = threshold_map.get(vulnerability_threshold.lower(), VulnerabilitySeverity.MEDIUM)
        self.vuln_scanner = VulnerabilityScanner(threshold_enum)
        
    def analyze_repository(self, repo_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis of a repository.
        
        Args:
            repo_path: Path to the repository to analyze
            
        Returns:
            Dictionary containing combined analysis results
        """
        logging.info(f"Starting comprehensive security analysis of: {repo_path}")
        
        results = {
            'repository_path': repo_path,
            'analysis_timestamp': str(__import__('datetime').datetime.now()),
            'keyword_analysis': {},
            'yara_analysis': {},
            'vulnerability_analysis': {},
            'combined_assessment': {}
        }
        
        try:
            # 1. Keyword-based malicious pattern detection
            logging.info("Running keyword-based malicious pattern detection...")
            keyword_results = self.keyword_extractor.extract_keywords_from_repository(repo_path)
            results['keyword_analysis'] = keyword_results
            
            # 2. YARA rule pattern matching
            logging.info("Running YARA rule pattern matching...")
            try:
                yara_results = self.yara_scanner.scan_repository(repo_path)
                results['yara_analysis'] = yara_results
            except Exception as e:
                logging.warning(f"YARA scanning failed: {e}")
                results['yara_analysis'] = {'error': str(e), 'total_matches': 0}
            
            # 3. Vulnerability scanning
            logging.info("Running vulnerability analysis...")
            vuln_results = self.vuln_scanner.scan_repository(repo_path)
            results['vulnerability_analysis'] = vuln_results
            
            # 4. Combined assessment
            results['combined_assessment'] = self._generate_combined_assessment(
                keyword_results, results['yara_analysis'], vuln_results
            )
            
            logging.info("Comprehensive security analysis completed")
            return results
            
        except Exception as e:
            logging.error(f"Error during comprehensive analysis of {repo_path}: {e}")
            results['error'] = str(e)
            return results
    
    def _generate_combined_assessment(self, 
                                    keyword_results: Dict[str, Any],
                                    yara_results: Dict[str, Any], 
                                    vuln_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate combined security assessment from all analysis results."""
        
        # Extract key metrics
        keyword_score = keyword_results.get('malicious_score', 0.0)
        keyword_malicious_count = len(keyword_results.get('malicious_keywords', {}))
        
        yara_score = yara_results.get('threat_score', 0.0)
        yara_matches = yara_results.get('total_matches', 0)
        yara_categories = yara_results.get('detected_categories', [])
        
        vuln_score = vuln_results.get('risk_score', 0.0) / 10.0  # Normalize to 0-1
        vuln_count = vuln_results.get('total_findings', 0)
        vuln_critical = vuln_results.get('findings_by_severity', {}).get('critical', 0)
        vuln_high = vuln_results.get('findings_by_severity', {}).get('high', 0)
        
        # Calculate weighted combined score
        # Weights: Keywords=30%, YARA=40%, Vulnerabilities=30%
        combined_score = (0.3 * keyword_score) + (0.4 * yara_score) + (0.3 * vuln_score)
        combined_score = round(combined_score, 3)
        
        # Determine overall risk level
        risk_level = self._determine_risk_level(combined_score, yara_categories, vuln_critical, vuln_high)
        
        # Generate threat indicators
        threat_indicators = []
        if keyword_malicious_count > 5:
            threat_indicators.append(f"High number of malicious keywords ({keyword_malicious_count})")
        if yara_matches > 3:
            threat_indicators.append(f"Multiple YARA rule matches ({yara_matches})")
        if 'ransomware' in yara_categories:
            threat_indicators.append("Ransomware patterns detected")
        if 'backdoor' in yara_categories:
            threat_indicators.append("Backdoor patterns detected") 
        if vuln_critical > 0:
            threat_indicators.append(f"Critical vulnerabilities found ({vuln_critical})")
        if vuln_high > 2:
            threat_indicators.append(f"Multiple high-severity vulnerabilities ({vuln_high})")
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            keyword_results, yara_results, vuln_results, combined_score
        )
        
        assessment = {
            'combined_score': combined_score,
            'risk_level': risk_level,
            'confidence': self._calculate_confidence(keyword_results, yara_results, vuln_results),
            'threat_indicators': threat_indicators,
            'recommendations': recommendations,
            'summary': {
                'keyword_malicious_terms': keyword_malicious_count,
                'yara_pattern_matches': yara_matches,
                'yara_threat_categories': yara_categories,
                'vulnerability_count': vuln_count,
                'critical_vulnerabilities': vuln_critical,
                'high_vulnerabilities': vuln_high
            },
            'analysis_coverage': {
                'files_analyzed_keywords': keyword_results.get('total_files_processed', 0),
                'files_analyzed_yara': yara_results.get('total_files_scanned', 0),
                'files_analyzed_vulnerabilities': vuln_results.get('files_scanned', 0)
            }
        }
        
        return assessment
    
    def _determine_risk_level(self, combined_score: float, yara_categories: List[str], 
                            vuln_critical: int, vuln_high: int) -> str:
        """Determine overall risk level based on multiple factors."""
        
        # Automatic critical if certain conditions are met
        if vuln_critical > 0 or 'ransomware' in yara_categories:
            return "CRITICAL"
        
        if combined_score >= 0.8:
            return "CRITICAL"
        elif combined_score >= 0.6 or ('backdoor' in yara_categories) or vuln_high > 3:
            return "HIGH"
        elif combined_score >= 0.4 or len(yara_categories) > 2 or vuln_high > 0:
            return "MEDIUM" 
        elif combined_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _calculate_confidence(self, keyword_results: Dict[str, Any],
                            yara_results: Dict[str, Any], 
                            vuln_results: Dict[str, Any]) -> float:
        """Calculate confidence level in the analysis based on detection consistency."""
        
        # Factors that increase confidence
        confidence_factors = []
        
        # Multiple detection methods agree
        keyword_malicious = len(keyword_results.get('malicious_keywords', {})) > 0
        yara_malicious = yara_results.get('total_matches', 0) > 0
        vuln_present = vuln_results.get('total_findings', 0) > 0
        
        detection_count = sum([keyword_malicious, yara_malicious, vuln_present])
        if detection_count >= 2:
            confidence_factors.append(0.3)  # Agreement between methods
        
        # High-confidence YARA matches
        if yara_results.get('total_matches', 0) > 1:
            confidence_factors.append(0.2)
        
        # Consistent keyword patterns
        if keyword_results.get('malicious_score', 0) > 0.3:
            confidence_factors.append(0.2)
        
        # Multiple vulnerability types
        vuln_categories = len(vuln_results.get('findings_by_category', {}))
        if vuln_categories > 2:
            confidence_factors.append(0.15)
        
        # File coverage
        files_analyzed = max(
            keyword_results.get('total_files_processed', 0),
            yara_results.get('total_files_scanned', 0),
            vuln_results.get('files_scanned', 0)
        )
        if files_analyzed > 5:
            confidence_factors.append(0.15)
        
        base_confidence = 0.5  # Base confidence level
        total_confidence = base_confidence + sum(confidence_factors)
        
        return min(round(total_confidence, 2), 1.0)
    
    def _generate_recommendations(self, keyword_results: Dict[str, Any],
                                yara_results: Dict[str, Any],
                                vuln_results: Dict[str, Any],
                                combined_score: float) -> List[str]:
        """Generate security recommendations based on analysis results."""
        
        recommendations = []
        
        # High-level recommendations based on combined score
        if combined_score >= 0.7:
            recommendations.append("URGENT: Repository shows strong indicators of malicious code. Immediate investigation required.")
            recommendations.append("Isolate and quarantine the repository until thorough manual review is completed.")
        elif combined_score >= 0.4:
            recommendations.append("Repository shows suspicious patterns. Manual security review recommended.")
        
        # Keyword-based recommendations
        malicious_keywords = keyword_results.get('malicious_keywords', {})
        if len(malicious_keywords) > 10:
            recommendations.append("High concentration of malicious keywords detected. Review code for potential threats.")
        
        # YARA-based recommendations
        yara_categories = yara_results.get('detected_categories', [])
        if 'ransomware' in yara_categories:
            recommendations.append("Ransomware patterns detected. Check for file encryption or ransom note functionality.")
        if 'backdoor' in yara_categories:
            recommendations.append("Backdoor patterns detected. Verify network communication and remote access functionality.")
        if 'keylogger' in yara_categories:
            recommendations.append("Keylogger patterns detected. Check for credential theft or surveillance functionality.")
        if 'cryptominer' in yara_categories:
            recommendations.append("Cryptocurrency mining patterns detected. Check for unauthorized resource usage.")
        
        # Vulnerability-based recommendations
        vuln_critical = vuln_results.get('findings_by_severity', {}).get('critical', 0)
        vuln_high = vuln_results.get('findings_by_severity', {}).get('high', 0)
        
        if vuln_critical > 0:
            recommendations.append(f"Critical vulnerabilities found ({vuln_critical}). Immediate patching required.")
        if vuln_high > 0:
            recommendations.append(f"High-severity vulnerabilities found ({vuln_high}). Schedule security fixes.")
        
        # Category-specific recommendations
        vuln_categories = vuln_results.get('findings_by_category', {})
        if vuln_categories.get('injection', 0) > 0:
            recommendations.append("Injection vulnerabilities found. Implement input validation and parameterized queries.")
        if vuln_categories.get('crypto', 0) > 0:
            recommendations.append("Cryptographic issues found. Review encryption implementations and key management.")
        if vuln_categories.get('secrets', 0) > 0:
            recommendations.append("Hardcoded secrets detected. Move sensitive data to environment variables or secure storage.")
        
        # General recommendations
        if not recommendations:
            recommendations.append("No significant security issues detected, but continue monitoring.")
        
        recommendations.append("Consider implementing automated security scanning in CI/CD pipeline.")
        
        return recommendations
    
    def save_analysis_report(self, analysis_results: Dict[str, Any], output_path: str):
        """Save comprehensive analysis report to file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(analysis_results, f, indent=2, default=str)
            logging.info(f"Analysis report saved to {output_path}")
        except Exception as e:
            logging.error(f"Error saving analysis report: {e}")


# Integration function for existing codebase
def analyze_repository_comprehensive(repo_path: str, 
                                   vulnerability_threshold: str = 'medium',
                                   yara_rules_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform comprehensive security analysis of a repository using all available methods.
    
    Args:
        repo_path: Path to repository to analyze
        vulnerability_threshold: Minimum vulnerability severity ('critical', 'high', 'medium', 'low', 'info')
        yara_rules_dir: Optional custom directory for YARA rules
        
    Returns:
        Dictionary containing comprehensive analysis results
    """
    analyzer = EnhancedSecurityAnalyzer(vulnerability_threshold, yara_rules_dir)
    return analyzer.analyze_repository(repo_path)
#!/usr/bin/env python3
"""
Simple Repository Tester

Quick script to test your enhanced security analysis pipeline on a specific GitHub repository.
Usage: python test_single_repo.py <github_repo_url_or_name>
"""

import os
import sys
import json
import tempfile
import shutil
import argparse
from datetime import datetime

# Add crawler directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

def test_single_repository(repo_name: str, output_file: str = None):
    """Test the enhanced security analysis on a single repository."""
    
    try:
        from clone import clone_repo
        from extract import extract_comprehensive_security_analysis
        
        print(f"🔍 Testing repository: {repo_name}")
        print("-" * 60)
        
        # Clone the repository
        print("📥 Cloning repository...")
        repo_path, local_name = clone_repo(repo_name) 
        
        if not repo_path or not os.path.exists(repo_path):
            print(f"❌ Failed to clone {repo_name}")
            return None
        
        print(f"✅ Repository cloned to: {repo_path}")
        
        # Run comprehensive security analysis
        print("🔍 Running comprehensive security analysis...")
        analysis_results = extract_comprehensive_security_analysis(repo_path)
        
        if not analysis_results:
            print("❌ Analysis failed or returned no results")
            return None
        
        # Display results
        print_analysis_summary(analysis_results, repo_name)
        
        # Save detailed results if requested
        if output_file:
            save_detailed_results(analysis_results, repo_name, output_file)
        
        # Cleanup
        try:
            shutil.rmtree(repo_path, ignore_errors=True)
            print(f"🧹 Cleaned up cloned repository")
        except:
            pass
        
        return analysis_results
        
    except ImportError as e:
        print(f"❌ Missing required modules: {e}")
        print("Make sure you're running this from the crawler project directory")
        return None
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        return None

def print_analysis_summary(results: dict, repo_name: str):
    """Print a formatted summary of analysis results."""
    
    print("\n" + "="*60)
    print(f"SECURITY ANALYSIS RESULTS FOR: {repo_name}")
    print("="*60)
    
    # Combined assessment
    combined = results.get('combined_assessment', {})
    risk_score = combined.get('combined_score', 0)
    risk_level = combined.get('risk_level', 'UNKNOWN')
    confidence = combined.get('confidence', 0)
    
    print(f"\n🎯 OVERALL RISK ASSESSMENT:")
    print(f"   Risk Score: {risk_score:.3f}/1.000")
    print(f"   Risk Level: {risk_level}")
    print(f"   Confidence: {confidence:.2f}")
    
    # Individual analysis breakdown
    keyword_analysis = results.get('keyword_analysis', {})
    yara_analysis = results.get('yara_analysis', {})
    vuln_analysis = results.get('vulnerability_analysis', {})
    
    print(f"\n📊 DETECTION BREAKDOWN:")
    malicious_keywords = keyword_analysis.get('malicious_keywords', {})
    print(f"   Malicious Keywords: {len(malicious_keywords)}")
    
    yara_matches = yara_analysis.get('total_matches', 0)
    print(f"   YARA Pattern Matches: {yara_matches}")
    
    vulnerabilities = vuln_analysis.get('total_findings', 0)
    print(f"   Vulnerabilities Found: {vulnerabilities}")
    
    # Threat indicators
    threat_indicators = combined.get('threat_indicators', [])
    if threat_indicators:
        print(f"\n⚠️  KEY THREAT INDICATORS:")
        for i, indicator in enumerate(threat_indicators[:5], 1):
            print(f"   {i}. {indicator}")
    
    # YARA categories detected
    yara_categories = yara_analysis.get('detected_categories', [])
    if yara_categories:
        print(f"\n🎭 MALWARE CATEGORIES DETECTED:")
        for category in yara_categories:
            print(f"   • {category.upper()}")
    
    # Vulnerability severity breakdown
    vuln_by_severity = vuln_analysis.get('findings_by_severity', {})
    if vuln_by_severity:
        print(f"\n🔐 VULNERABILITY SEVERITY BREAKDOWN:")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = vuln_by_severity.get(severity, 0)
            if count > 0:
                print(f"   {severity.upper()}: {count}")
    
    # Top malicious keywords
    if malicious_keywords:
        print(f"\n🔑 TOP MALICIOUS KEYWORDS FOUND:")
        # Sort by frequency/score
        sorted_keywords = sorted(malicious_keywords.items(), 
                               key=lambda x: x[1] if isinstance(x[1], (int, float)) else 0, 
                               reverse=True)
        for keyword, score in sorted_keywords[:10]:
            print(f"   • {keyword}: {score}")
    
    # Analysis coverage
    coverage = combined.get('analysis_coverage', {})
    if coverage:
        print(f"\n📁 FILES ANALYZED:")
        print(f"   Keywords: {coverage.get('files_analyzed_keywords', 0)}")
        print(f"   YARA: {coverage.get('files_analyzed_yara', 0)}")
        print(f"   Vulnerabilities: {coverage.get('files_analyzed_vulnerabilities', 0)}")
    
    # Recommendations
    recommendations = combined.get('recommendations', [])
    if recommendations:
        print(f"\n💡 RECOMMENDATIONS:")
        for i, rec in enumerate(recommendations[:3], 1):
            print(f"   {i}. {rec}")
    
    print("\n" + "="*60)

def save_detailed_results(results: dict, repo_name: str, output_file: str):
    """Save detailed analysis results to a JSON file."""
    
    output_data = {
        'repository': repo_name,
        'analysis_timestamp': datetime.now().isoformat(),
        'results': results
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"💾 Detailed results saved to: {output_file}")
    except Exception as e:
        print(f"❌ Failed to save results: {e}")

def main():
    """Main function with command line argument parsing."""
    
    parser = argparse.ArgumentParser(
        description="Test enhanced security analysis pipeline on a GitHub repository",
        epilog="Examples:\n"
               "  python test_single_repo.py user/repo-name\n"
               "  python test_single_repo.py user/repo-name --output results.json\n"
               "  python test_single_repo.py https://github.com/user/repo-name",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'repository', 
        help='GitHub repository name (user/repo) or full URL'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Save detailed results to JSON file'
    )
    
    args = parser.parse_args()
    
    # Extract repository name from URL if needed
    repo_name = args.repository
    if repo_name.startswith('https://github.com/'):
        repo_name = repo_name.replace('https://github.com/', '').rstrip('/')
    elif repo_name.startswith('github.com/'):
        repo_name = repo_name.replace('github.com/', '').rstrip('/')
    
    print("Enhanced Security Analysis Pipeline - Single Repository Test")
    print("=" * 60)
    
    # Run the test
    results = test_single_repository(repo_name, args.output)
    
    if results:
        print("\n✅ Analysis completed successfully!")
        if args.output:
            print(f"📄 Detailed results saved to: {args.output}")
    else:
        print("\n❌ Analysis failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
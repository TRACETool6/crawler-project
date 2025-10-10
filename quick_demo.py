#!/usr/bin/env python3
"""
Quick Pipeline Demo

This script demonstrates your enhanced security analysis pipeline by testing it
on a few sample repositories with different risk profiles.
"""

import os
import sys

# Add crawler directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

def demo_pipeline():
    """Demonstrate the pipeline with sample repositories."""
    
    print("Enhanced Security Analysis Pipeline - Quick Demo")
    print("=" * 60)
    
    # Sample repositories to test (mix of legitimate and suspicious)
    test_repositories = [
        {
            'name': 'microsoft/vscode',
            'description': 'Popular legitimate code editor',
            'expected_risk': 'LOW'
        },
        {
            'name': 'OWASP/WebGoat', 
            'description': 'Deliberately vulnerable web application',
            'expected_risk': 'MEDIUM-HIGH (Educational)'
        },
        {
            'name': 'sqlmapproject/sqlmap',
            'description': 'SQL injection testing tool',
            'expected_risk': 'MEDIUM-HIGH (Security Tool)'
        }
    ]
    
    print("Testing repositories with different risk profiles:")
    for i, repo in enumerate(test_repositories, 1):
        print(f"{i}. {repo['name']} - {repo['description']} (Expected: {repo['expected_risk']})")
    
    print("\nChoose a repository to test:")
    for i, repo in enumerate(test_repositories, 1):
        print(f"{i}. {repo['name']}")
    print("4. Enter custom repository name")
    print("5. Run comprehensive test with malicious samples")
    
    try:
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == "1":
            test_repo = test_repositories[0]['name']
        elif choice == "2":
            test_repo = test_repositories[1]['name']
        elif choice == "3":
            test_repo = test_repositories[2]['name']
        elif choice == "4":
            test_repo = input("Enter repository name (owner/repo): ").strip()
        elif choice == "5":
            run_comprehensive_test()
            return
        else:
            print("Invalid choice. Using default repository.")
            test_repo = test_repositories[0]['name']
        
        # Test the selected repository
        test_single_repository_simple(test_repo)
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
    except Exception as e:
        print(f"\nDemo failed: {e}")

def test_single_repository_simple(repo_name: str):
    """Simple test of a single repository."""
    
    try:
        from clone import clone_repo
        from extract import extract_comprehensive_security_analysis
        import tempfile
        import shutil
        
        print(f"\n🔍 Testing: {repo_name}")
        print("-" * 40)
        
        # Clone repository
        print("📥 Cloning repository...")
        repo_path, local_name = clone_repo(repo_name)
        
        if not repo_path or not os.path.exists(repo_path):
            print(f"❌ Failed to clone {repo_name}")
            return
        
        print(f"✅ Repository cloned successfully")
        
        # Run analysis
        print("🔍 Running enhanced security analysis...")
        results = extract_comprehensive_security_analysis(repo_path)
        
        if not results:
            print("❌ Analysis failed")
            return
        
        # Display key results
        print_simple_results(results, repo_name)
        
        # Cleanup
        try:
            shutil.rmtree(repo_path, ignore_errors=True)
            print("🧹 Cleaned up cloned files")
        except:
            pass
            
    except ImportError as e:
        print(f"❌ Could not import required modules: {e}")
        print("Make sure you're running this from the project root directory.")
    except Exception as e:
        print(f"❌ Error during analysis: {e}")

def print_simple_results(results: dict, repo_name: str):
    """Print simplified analysis results."""
    
    print(f"\n📊 ANALYSIS RESULTS FOR: {repo_name}")
    print("=" * 50)
    
    # Combined assessment
    combined = results.get('combined_assessment', {})
    risk_score = combined.get('combined_score', 0)
    risk_level = combined.get('risk_level', 'UNKNOWN')
    
    # Risk level with color coding (text)
    risk_emoji = {
        'LOW': '🟢',
        'MEDIUM': '🟡', 
        'HIGH': '🟠',
        'CRITICAL': '🔴',
        'UNKNOWN': '⚪'
    }
    
    print(f"\n{risk_emoji.get(risk_level, '⚪')} OVERALL RISK: {risk_level}")
    print(f"📈 Risk Score: {risk_score:.3f}/1.000")
    
    # Detection summary
    keyword_analysis = results.get('keyword_analysis', {})
    yara_analysis = results.get('yara_analysis', {})
    vuln_analysis = results.get('vulnerability_analysis', {})
    
    malicious_keywords = len(keyword_analysis.get('malicious_keywords', {}))
    yara_matches = yara_analysis.get('total_matches', 0)
    vulnerabilities = vuln_analysis.get('total_findings', 0)
    
    print(f"\n🔍 DETECTION SUMMARY:")
    print(f"   Malicious Keywords: {malicious_keywords}")
    print(f"   YARA Patterns: {yara_matches}")
    print(f"   Vulnerabilities: {vulnerabilities}")
    
    # Key findings
    if malicious_keywords > 0 or yara_matches > 0 or vulnerabilities > 0:
        print(f"\n⚠️  KEY FINDINGS:")
        
        if malicious_keywords > 0:
            top_keywords = list(keyword_analysis.get('malicious_keywords', {}).keys())[:3]
            print(f"   • Keywords: {', '.join(top_keywords)}")
        
        if yara_matches > 0:
            categories = yara_analysis.get('detected_categories', [])
            if categories:
                print(f"   • YARA Categories: {', '.join(categories[:3])}")
        
        if vulnerabilities > 0:
            severity_counts = vuln_analysis.get('findings_by_severity', {})
            high_severity = severity_counts.get('critical', 0) + severity_counts.get('high', 0)
            if high_severity > 0:
                print(f"   • High Severity Vulnerabilities: {high_severity}")
    
    # Interpretation
    print(f"\n💡 INTERPRETATION:")
    if risk_score < 0.2:
        print("   This appears to be a legitimate, low-risk repository.")
    elif risk_score < 0.4:
        print("   Low to medium risk. May contain security tools or educational content.")
    elif risk_score < 0.6:
        print("   Medium risk. Contains suspicious patterns that warrant investigation.")
    elif risk_score < 0.8:
        print("   High risk. Strong indicators of malicious or dangerous content.")
    else:
        print("   CRITICAL risk. Multiple strong indicators of malicious intent.")
    
    print("\n" + "=" * 50)

def run_comprehensive_test():
    """Run the comprehensive test with malicious samples."""
    try:
        print("\n🧪 Running comprehensive test with malicious code samples...")
        print("This will create temporary files with malicious patterns for testing.")
        
        # Import and run the comprehensive test
        sys.path.append(os.path.dirname(__file__))
        from comprehensive_security_test import run_comprehensive_test
        
        run_comprehensive_test()
        
    except ImportError:
        print("❌ Could not import comprehensive test module.")
        print("Make sure comprehensive_security_test.py is in the same directory.")
    except Exception as e:
        print(f"❌ Comprehensive test failed: {e}")

def main():
    """Main demo function."""
    demo_pipeline()

if __name__ == "__main__":
    main()
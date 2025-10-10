#!/usr/bin/env python3
"""
Pipeline Accuracy Testing Script

This script tests the enhanced security analysis pipeline on random GitHub repositories
to evaluate detection accuracy and performance.
"""

import os
import sys
import json
import time
import tempfile
import shutil
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional

# Add crawler directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

from clone import clone_repo
from github_api import get_repo_batch, fetch_all_metadata, get_random_repos
from extract import extract_comprehensive_security_analysis
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pipeline_accuracy_test.log'),
        logging.StreamHandler()
    ]
)

class PipelineAccuracyTester:
    """Test the security analysis pipeline on various repository types."""
    
    def __init__(self, output_dir: str = "pipeline_test_results"):
        self.output_dir = output_dir
        self.results = {
            'test_session': {
                'start_time': datetime.now().isoformat(),
                'repositories_tested': [],
                'summary_stats': {},
                'performance_metrics': {}
            }
        }
        os.makedirs(output_dir, exist_ok=True)
        
    def get_test_repositories(self, count: int = 10) -> List[Dict]:
        """Get a mix of different repository types for testing."""
        test_repos = []
        
        # 1. Get popular repositories (likely legitimate)
        legitimate_queries = [
            'stars:>1000 language:python',
            'stars:>1000 language:javascript', 
            'stars:>1000 language:java',
            'framework web application',
            'machine learning tensorflow'
        ]
        
        # 2. Get potentially suspicious repositories
        suspicious_queries = [
            'keylogger OR backdoor OR trojan',
            'password stealer OR credential harvester',
            'cryptominer OR bitcoin miner',
            'exploit OR vulnerability scanner',
            'botnet OR c2 OR command control'
        ]
        
        # 3. Get random repositories
        random_queries = [
            'created:>2023-01-01 stars:>10',
            'pushed:>2024-01-01 language:python',
            'size:<1000 language:javascript'
        ]
        
        all_queries = legitimate_queries + suspicious_queries + random_queries
        
        for query in all_queries[:count]:
            try:
                repos = self.search_github_repos(query, per_page=min(5, max(1, count // len(all_queries))))
                test_repos.extend(repos)
                if len(test_repos) >= count:
                    break
            except Exception as e:
                logging.warning(f"Failed to fetch repos for query '{query}': {e}")
                
        return test_repos[:count]
    
    def search_github_repos(self, query: str, per_page: int = 5) -> List[Dict]:
        """Search GitHub repositories using the search API."""
        url = "https://api.github.com/search/repositories"
        params = {
            'q': query,
            'sort': 'updated',
            'order': 'desc',
            'per_page': per_page
        }
        
        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            repos = []
            for item in data.get('items', [])[:per_page]:
                repos.append({
                    'full_name': item['full_name'],
                    'description': item.get('description', ''),
                    'language': item.get('language', ''),
                    'stars': item.get('stargazers_count', 0),
                    'size': item.get('size', 0),
                    'query_used': query
                })
            
            return repos
            
        except requests.RequestException as e:
            logging.error(f"GitHub API request failed: {e}")
            return []
    
    def analyze_repository(self, repo_info: Dict) -> Optional[Dict]:
        """Analyze a single repository with the enhanced pipeline."""
        full_name = repo_info['full_name']
        logging.info(f"Analyzing repository: {full_name}")
        
        repo_path = None
        try:
            # Clone repository
            start_time = time.time()
            repo_path, repo_name = clone_repo(full_name)
            clone_time = time.time() - start_time
            
            if not repo_path or not os.path.exists(repo_path):
                logging.warning(f"Failed to clone {full_name}")
                return None
            
            # Run comprehensive security analysis
            analysis_start = time.time()
            analysis_results = extract_comprehensive_security_analysis(repo_path)
            analysis_time = time.time() - analysis_start
            
            # Compile results
            result = {
                'repository': repo_info,
                'analysis_results': analysis_results,
                'performance_metrics': {
                    'clone_time_seconds': round(clone_time, 2),
                    'analysis_time_seconds': round(analysis_time, 2),
                    'total_time_seconds': round(clone_time + analysis_time, 2)
                },
                'timestamp': datetime.now().isoformat()
            }
            
            # Add interpretation
            result['interpretation'] = self.interpret_results(analysis_results, repo_info)
            
            logging.info(f"Completed analysis of {full_name} in {result['performance_metrics']['total_time_seconds']}s")
            return result
            
        except Exception as e:
            logging.error(f"Error analyzing {full_name}: {e}")
            return {
                'repository': repo_info,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
        finally:
            # Cleanup
            if repo_path and os.path.exists(repo_path):
                try:
                    shutil.rmtree(repo_path, ignore_errors=True)
                except:
                    pass
    
    def interpret_results(self, analysis_results: Dict, repo_info: Dict) -> Dict:
        """Interpret analysis results and provide insights."""
        interpretation = {
            'risk_assessment': 'UNKNOWN',
            'confidence_level': 'LOW',
            'key_findings': [],
            'false_positive_indicators': [],
            'suspicious_indicators': []
        }
        
        if not analysis_results:
            return interpretation
        
        # Get combined assessment
        combined = analysis_results.get('combined_assessment', {})
        risk_score = combined.get('combined_score', 0)
        risk_level = combined.get('risk_level', 'UNKNOWN')
        
        interpretation['risk_assessment'] = risk_level
        interpretation['risk_score'] = risk_score
        interpretation['confidence_level'] = 'HIGH' if risk_score > 0.7 or risk_score < 0.2 else 'MEDIUM'
        
        # Analyze findings
        keyword_results = analysis_results.get('keyword_analysis', {})
        yara_results = analysis_results.get('yara_analysis', {}) 
        vuln_results = analysis_results.get('vulnerability_analysis', {})
        
        # Key findings
        findings = []
        if keyword_results.get('malicious_keywords'):
            findings.append(f"Found {len(keyword_results['malicious_keywords'])} malicious keywords")
        if yara_results.get('total_matches', 0) > 0:
            findings.append(f"Matched {yara_results['total_matches']} YARA patterns")
        if vuln_results.get('total_findings', 0) > 0:
            findings.append(f"Detected {vuln_results['total_findings']} vulnerabilities")
        
        interpretation['key_findings'] = findings
        
        # False positive indicators (legitimate repos with security-related content)
        fp_indicators = []
        if repo_info.get('stars', 0) > 1000:
            fp_indicators.append("High-star repository (likely legitimate)")
        if 'security' in repo_info.get('description', '').lower():
            fp_indicators.append("Security-focused repository description")
        if any(word in repo_info.get('description', '').lower() for word in ['framework', 'library', 'tool', 'educational']):
            fp_indicators.append("Appears to be a development tool/framework")
        
        interpretation['false_positive_indicators'] = fp_indicators
        
        # Suspicious indicators
        suspicious = []
        if risk_score > 0.6:
            suspicious.append("High risk score from multiple detection methods")
        if yara_results.get('detected_categories'):
            suspicious.append(f"YARA detected: {', '.join(yara_results['detected_categories'])}")
        if repo_info.get('size', 0) < 100 and risk_score > 0.4:
            suspicious.append("Small repository size with security detections")
        
        interpretation['suspicious_indicators'] = suspicious
        
        return interpretation
    
    def run_accuracy_test(self, num_repos: int = 20) -> Dict:
        """Run the complete accuracy test."""
        logging.info(f"Starting pipeline accuracy test with {num_repos} repositories")
        
        # Get test repositories
        test_repos = self.get_test_repositories(num_repos)
        logging.info(f"Selected {len(test_repos)} repositories for testing")
        
        # Analyze each repository
        results = []
        failed_analyses = 0
        total_analysis_time = 0
        
        for i, repo_info in enumerate(test_repos, 1):
            logging.info(f"Processing repository {i}/{len(test_repos)}: {repo_info['full_name']}")
            
            result = self.analyze_repository(repo_info)
            if result:
                if 'error' not in result:
                    total_analysis_time += result['performance_metrics']['total_time_seconds']
                results.append(result)
                
                # Save intermediate results
                self.save_intermediate_result(result, i)
            else:
                failed_analyses += 1
                
            # Brief pause between repositories
            time.sleep(2)
        
        # Compile summary statistics
        summary_stats = self.compile_summary_stats(results, failed_analyses, total_analysis_time)
        
        # Save final results
        final_results = {
            'test_session': {
                'start_time': self.results['test_session']['start_time'],
                'end_time': datetime.now().isoformat(),
                'repositories_tested': len(results),
                'failed_analyses': failed_analyses,
                'success_rate': round((len(results) / num_repos) * 100, 2) if num_repos > 0 else 0
            },
            'summary_stats': summary_stats,
            'detailed_results': results
        }
        
        self.save_final_results(final_results)
        self.print_summary_report(final_results)
        
        return final_results
    
    def compile_summary_stats(self, results: List[Dict], failed_analyses: int, total_time: float) -> Dict:
        """Compile summary statistics from all results."""
        successful_results = [r for r in results if 'error' not in r]
        
        if not successful_results:
            return {'error': 'No successful analyses to summarize'}
        
        # Risk level distribution
        risk_levels = {}
        risk_scores = []
        detection_methods = {'keywords': 0, 'yara': 0, 'vulnerabilities': 0}
        
        for result in successful_results:
            analysis = result.get('analysis_results', {})
            combined = analysis.get('combined_assessment', {})
            
            # Risk levels
            risk_level = combined.get('risk_level', 'UNKNOWN')
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
            
            # Risk scores
            risk_score = combined.get('combined_score', 0)
            risk_scores.append(risk_score)
            
            # Detection methods
            if analysis.get('keyword_analysis', {}).get('malicious_keywords'):
                detection_methods['keywords'] += 1
            if analysis.get('yara_analysis', {}).get('total_matches', 0) > 0:
                detection_methods['yara'] += 1
            if analysis.get('vulnerability_analysis', {}).get('total_findings', 0) > 0:
                detection_methods['vulnerabilities'] += 1
        
        return {
            'total_repositories': len(results),
            'successful_analyses': len(successful_results),
            'failed_analyses': failed_analyses,
            'average_analysis_time': round(total_time / len(successful_results), 2) if successful_results else 0,
            'risk_level_distribution': risk_levels,
            'average_risk_score': round(sum(risk_scores) / len(risk_scores), 3) if risk_scores else 0,
            'detection_method_hits': detection_methods,
            'high_risk_repositories': len([r for r in risk_scores if r > 0.6]),
            'low_risk_repositories': len([r for r in risk_scores if r < 0.3])
        }
    
    def save_intermediate_result(self, result: Dict, index: int):
        """Save intermediate result to prevent data loss."""
        filename = f"result_{index:03d}_{result['repository']['full_name'].replace('/', '_')}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(result, f, indent=2, default=str)
    
    def save_final_results(self, results: Dict):
        """Save final compiled results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pipeline_accuracy_test_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logging.info(f"Final results saved to: {filepath}")
    
    def print_summary_report(self, results: Dict):
        """Print a formatted summary report."""
        print("\n" + "="*80)
        print("PIPELINE ACCURACY TEST SUMMARY REPORT")
        print("="*80)
        
        session = results['test_session']
        stats = results['summary_stats']
        
        print(f"\n📊 TEST SESSION:")
        print(f"   Start Time: {session['start_time']}")
        print(f"   End Time: {session['end_time']}")
        print(f"   Success Rate: {session['success_rate']}%")
        print(f"   Repositories Tested: {session['repositories_tested']}")
        print(f"   Failed Analyses: {session['failed_analyses']}")
        
        if 'error' not in stats:
            print(f"\n🎯 ANALYSIS PERFORMANCE:")
            print(f"   Average Analysis Time: {stats['average_analysis_time']} seconds")
            print(f"   Average Risk Score: {stats['average_risk_score']}")
            
            print(f"\n⚠️  RISK LEVEL DISTRIBUTION:")
            for level, count in stats['risk_level_distribution'].items():
                percentage = round((count / stats['total_repositories']) * 100, 1)
                print(f"   {level}: {count} repositories ({percentage}%)")
            
            print(f"\n🔍 DETECTION METHOD EFFECTIVENESS:")
            total = stats['successful_analyses']
            for method, hits in stats['detection_method_hits'].items():
                percentage = round((hits / total) * 100, 1) if total > 0 else 0
                print(f"   {method.title()}: {hits}/{total} ({percentage}%)")
            
            print(f"\n🚨 RISK DISTRIBUTION:")
            print(f"   High Risk (>0.6): {stats['high_risk_repositories']}")
            print(f"   Low Risk (<0.3): {stats['low_risk_repositories']}")
            
            # Top findings
            detailed = results.get('detailed_results', [])
            high_risk_repos = [r for r in detailed if 'error' not in r and 
                             r.get('analysis_results', {}).get('combined_assessment', {}).get('combined_score', 0) > 0.6]
            
            if high_risk_repos:
                print(f"\n🔴 TOP HIGH-RISK REPOSITORIES:")
                for repo in high_risk_repos[:5]:
                    name = repo['repository']['full_name']
                    score = repo['analysis_results']['combined_assessment']['combined_score']
                    risk_level = repo['analysis_results']['combined_assessment']['risk_level']
                    print(f"   • {name} (Score: {score:.3f}, Level: {risk_level})")
        
        print(f"\nResults saved to: {self.output_dir}/")
        print("="*80)


def main():
    """Main function to run the pipeline accuracy test."""
    print("Enhanced Security Analysis Pipeline - Accuracy Testing")
    print("=" * 60)
    
    # Get number of repositories to test
    try:
        num_repos = int(input("Enter number of repositories to test (default: 10): ") or "10")
    except ValueError:
        num_repos = 10
    
    # Initialize tester
    tester = PipelineAccuracyTester()
    
    # Run the test
    try:
        results = tester.run_accuracy_test(num_repos)
        print(f"\n✅ Test completed successfully!")
        print(f"Check the '{tester.output_dir}' directory for detailed results.")
        
    except KeyboardInterrupt:
        print("\n❌ Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        logging.error(f"Test failed: {e}", exc_info=True)


if __name__ == "__main__":
    main()
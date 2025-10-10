# Enhanced Security Pipeline Testing Guide

This guide shows you how to test your enhanced security analysis pipeline on GitHub repositories to evaluate its accuracy and performance.

## Available Testing Scripts

### 1. Single Repository Testing (`test_single_repo.py`)
Test your pipeline on a specific GitHub repository.

**Basic Usage:**
```bash
# Test a specific repository
python test_single_repo.py user/repository-name

# Test with detailed output saved to file
python test_single_repo.py user/repository-name --output results.json

# Test using full GitHub URL
python test_single_repo.py https://github.com/user/repository-name
```

**Examples:**
```bash
# Test a legitimate repository
python test_single_repo.py microsoft/vscode

# Test a security tool repository  
python test_single_repo.py sqlmapproject/sqlmap

# Test a potentially suspicious repository
python test_single_repo.py malware-samples/some-suspicious-repo
```

### 2. Batch Accuracy Testing (`test_pipeline_accuracy.py`)
Test your pipeline on multiple repositories to evaluate overall accuracy.

**Usage:**
```bash
python test_pipeline_accuracy.py
# You'll be prompted to enter the number of repositories to test
```

**What it does:**
- Searches for repositories using various queries (legitimate, suspicious, random)
- Analyzes each repository with your enhanced pipeline
- Provides comprehensive accuracy statistics
- Saves detailed results for analysis

## Pipeline Integration with Main Crawler

To integrate the enhanced security analysis into your main crawler workflow, you have three options:

### Option 1: Replace Existing Analysis
Modify `crawler/main.py` to use comprehensive analysis instead of just keywords:

```python
# In process_repo_data function, replace:
keywords_data = extract_malicious_keywords(repo_path)

# With:
security_analysis = extract_comprehensive_security_analysis(repo_path)
```

### Option 2: Add as Additional Analysis
Keep keyword analysis and add comprehensive analysis:

```python
# In process_repo_data function, add:
keywords_data = extract_malicious_keywords(repo_path)
comprehensive_analysis = extract_comprehensive_security_analysis(repo_path)

# Then pass both to save_repo_data
save_repo_data(GROUP_NAME, repo_name, repo_metadata, commits, 
               keywords_data, repo_path, comprehensive_analysis)
```

### Option 3: Configurable Analysis Depth
Add a configuration option to choose analysis depth:

```python
# In config.py, add:
ANALYSIS_MODE = "comprehensive"  # or "keywords_only"

# In main.py:
if ANALYSIS_MODE == "comprehensive":
    analysis_data = extract_comprehensive_security_analysis(repo_path)
else:
    analysis_data = extract_malicious_keywords(repo_path)
```

## Testing Strategy for Pipeline Accuracy

### 1. Test Repository Categories

**Legitimate Repositories (Expected: Low Risk)**
- Popular frameworks (React, Angular, Vue.js)
- Well-known libraries (NumPy, Pandas, Requests)
- Official company repositories (Microsoft, Google, etc.)

**Security Tools (Expected: Medium-High Risk, but False Positives)**
- Penetration testing tools (Metasploit, Nmap)
- Vulnerability scanners (OpenVAS, Nikto)
- Security frameworks (OWASP projects)

**Potentially Malicious (Expected: High Risk)**
- Repositories with suspicious keywords in names/descriptions
- Small repositories with obfuscated code
- Repositories flagged by other security tools

### 2. Manual Testing Examples

```bash
# Test popular legitimate repositories
python test_single_repo.py facebook/react
python test_single_repo.py microsoft/TypeScript
python test_single_repo.py python/cpython

# Test security tools (expect false positives)
python test_single_repo.py rapid7/metasploit-framework
python test_single_repo.py nmap/nmap
python test_single_repo.py sqlmapproject/sqlmap

# Test educational/demonstration repositories
python test_single_repo.py OWASP/WebGoat
python test_single_repo.py digininja/DVWA

# Test smaller repositories (more likely to be risky)
python test_single_repo.py suspicious-username/keylogger
python test_single_repo.py unknown-user/backdoor-tool
```

### 3. Interpreting Results

**Low Risk (Score < 0.3):**
- Likely legitimate code
- Few or no malicious indicators
- High confidence in safety

**Medium Risk (Score 0.3-0.6):**
- Security tools or educational materials
- Some suspicious patterns but in legitimate context
- Review context carefully (stars, description, author)

**High Risk (Score > 0.6):**
- Strong indicators of malicious intent
- Multiple detection methods triggered
- Requires careful manual review

### 4. Expected Accuracy Benchmarks

Based on the comprehensive analysis approach:

**True Positives (Correctly Identified Malicious):**
- Target: >80% of genuinely malicious repositories
- Indicators: High YARA matches + malicious keywords + vulnerabilities

**True Negatives (Correctly Identified Legitimate):**
- Target: >90% of legitimate repositories
- Popular repositories should score <0.3

**False Positives (Legitimate flagged as Malicious):**
- Expected: Security tools, penetration testing frameworks
- Should be identifiable by context (high stars, official authors)

**False Negatives (Malicious missed):**
- Target: <10% of malicious repositories
- Most concerning category - sophisticated malware

## Performance Monitoring

Track these metrics during testing:

```python
# Analysis time per repository
# Detection rate by method (keywords, YARA, vulnerabilities)  
# Memory usage during analysis
# Success rate (repositories analyzed vs failed)
```

## Advanced Testing

### Custom Test Repository Creation
Create test repositories with known malicious patterns:

```bash
# Run the comprehensive test with known malicious samples
python comprehensive_security_test.py
```

### Batch Testing with Specific Queries
Modify `test_pipeline_accuracy.py` to test specific repository types:

```python
# Test only Python repositories
test_repos = search_github_repos("language:python stars:>100", per_page=20)

# Test only recently created repositories  
test_repos = search_github_repos("created:>2024-01-01", per_page=20)

# Test repositories with security-related terms
test_repos = search_github_repos("password OR credential OR exploit", per_page=20)
```

## Result Analysis

After running tests, analyze the results to:

1. **Calibrate Risk Thresholds** - Adjust scoring weights if needed
2. **Identify False Positive Patterns** - Improve filtering for legitimate tools
3. **Enhance Detection Rules** - Add new YARA rules or keywords based on misses
4. **Performance Optimization** - Identify bottlenecks in analysis pipeline

## Next Steps

1. Run initial accuracy tests on 20-50 repositories
2. Analyze results and adjust thresholds if needed
3. Integrate enhanced analysis into main crawler
4. Monitor performance in production
5. Continuously improve detection rules based on findings

## Troubleshooting

**Import Errors:** Make sure you run the test scripts from the project root directory where the `crawler/` folder is located.

**GitHub API Rate Limits:** The test scripts include delays between requests. For extensive testing, consider using a GitHub API token.

**Memory Issues:** For large repositories, the analysis may consume significant memory. Monitor system resources during testing.
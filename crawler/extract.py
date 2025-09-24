import os
import git
import logging
from keyword_extractor import MaliciousKeywordExtractor

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

def extract_commits(repo_path):
    """
    Extracts commit information from a Git repository.

    Args:
        repo_path (str): The local path to the cloned Git repository.

    Returns:
        list: A list of dictionaries, each representing a commit with detailed information.
    """
    logging.info(f"Extracting commits from {repo_path}")
    commits = []
    seen_shas = set() 
    try:
        repo = git.Repo(repo_path)
        for ref in repo.refs:
            if isinstance(ref, git.Head) or isinstance(ref, git.TagReference):
                for commit in repo.iter_commits(ref):
                    if commit.hexsha in seen_shas:
                        continue 
                    seen_shas.add(commit.hexsha)

                    stats = commit.stats
                    files_changed_list = []
                    for file_path, file_stats in stats.files.items():
                        files_changed_list.append({
                            "path": file_path,
                            "insertions": file_stats.get("insertions", 0),
                            "deletions": file_stats.get("deletions", 0),
                            "lines_changed": file_stats.get("lines", 0)
                        })

                    commits.append({
                        "sha": commit.hexsha,
                        "branch_or_tag": ref.name, 
                        "author": {"name": commit.author.name, "email": commit.author.email},
                        "committer": {"name": commit.committer.name, "email": commit.committer.email},
                        "author_date": commit.authored_datetime.isoformat(),
                        "commit_date": commit.committed_datetime.isoformat(),
                        "message": commit.message.strip(),
                        "parents": [p.hexsha for p in commit.parents],
                        "files_changed": files_changed_list,
                        "total_lines_added": stats.total.get("insertions", 0),
                        "total_lines_deleted": stats.total.get("deletions", 0),
                        "total_files_changed": stats.total.get("files", 0)
                    })
        logging.info(f"Finished extracting {len(commits)} commits from {repo_path}")
    except git.InvalidGitRepositoryError:
        logging.error(f"Path {repo_path} is not a valid Git repository.")
    except Exception as e:
        logging.error(f"Error extracting commits from {repo_path}: {e}")
    return commits

def extract_file_contents(repo_path):
    """
    Extracts file contents for code files in a repository,
    excluding the .git directory and binary files.

    Args:
        repo_path (str): The local path to the cloned repository.

    Returns:
        dict: A dictionary mapping file paths to their contents.
    """
    logging.info(f"Extracting file contents from {repo_path}")
    file_contents = {}
    
    # Define file extensions to include (common code file types)
    code_extensions = {
        '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp', '.cs', '.go',
        '.rs', '.php', '.rb', '.swift', '.kt', '.scala', '.clj', '.hs', '.ml',
        '.r', '.m', '.sh', '.bash', '.zsh', '.ps1', '.sql', '.html', '.css',
        '.xml', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
        '.md', '.txt', '.rst', '.tex', '.dockerfile', '.makefile', '.cmake'
    }
    
    try:
        for root, dirs, files in os.walk(repo_path):
            if ".git" in dirs:
                dirs.remove(".git") 

            for f in files:
                abs_path = os.path.join(root, f)
                rel_path = os.path.relpath(abs_path, repo_path)
                
                # Get file extension
                _, ext = os.path.splitext(f.lower())
                
                # Only include code files and common text files
                if ext in code_extensions or f.lower() in ['readme', 'license', 'changelog', 'makefile', 'dockerfile']:
                    try:
                        with open(abs_path, 'r', encoding='utf-8', errors='ignore') as file:
                            content = file.read()
                            file_contents[rel_path] = content
                    except (UnicodeDecodeError, IOError, OSError) as e:
                        logging.warning(f"Could not read file {abs_path}: {e}")
                        continue
        
        logging.info(f"Finished extracting {len(file_contents)} files from {repo_path}")
    except Exception as e:
        logging.error(f"Error extracting file contents from {repo_path}: {e}")
    
    return file_contents


def extract_malicious_keywords(repo_path):
    """
    Extracts and analyzes malicious-oriented keywords from repository source code files.
    
    This function implements the methodology described in academic papers on malicious
    repository detection, extracting keywords from source code and applying frequency-based
    filtering to identify potentially malicious terms.
    
    Args:
        repo_path (str): The local path to the cloned repository.
    
    Returns:
        dict: A dictionary containing:
            - keyword_frequency: Dictionary of keyword frequencies
            - malicious_keywords: Dictionary of potentially malicious keywords
            - malicious_score: Float score (0-1) indicating malicious orientation
            - total_files_processed: Number of files analyzed
            - total_keywords_extracted: Total number of keywords found
            - unique_keywords: Number of unique keywords
    """
    logging.info(f"Extracting malicious keywords from {repo_path}")
    
    try:
        extractor = MaliciousKeywordExtractor()
        keywords_data = extractor.extract_keywords_from_repository(repo_path)
        
        if keywords_data:
            logging.info(f"Keyword extraction completed for {repo_path}:")
            logging.info(f"  - Total keywords: {keywords_data.get('total_keywords_extracted', 0)}")
            logging.info(f"  - Unique keywords: {keywords_data.get('unique_keywords', 0)}")
            logging.info(f"  - Malicious keywords: {len(keywords_data.get('malicious_keywords', {}))}")
            logging.info(f"  - Malicious score: {keywords_data.get('malicious_score', 0)}")
        
        return keywords_data
        
    except Exception as e:
        logging.error(f"Error extracting malicious keywords from {repo_path}: {e}")
        return {}


def extract_comprehensive_security_analysis(repo_path):
    """
    Perform comprehensive security analysis using keywords, YARA rules, and vulnerability scanning.
    
    This function combines multiple security analysis techniques:
    1. Keyword-based malicious pattern detection
    2. YARA rule pattern matching  
    3. Static vulnerability analysis
    
    Args:
        repo_path (str): The local path to the cloned repository.
    
    Returns:
        dict: A dictionary containing comprehensive security analysis results including:
            - keyword_analysis: Malicious keyword detection results
            - yara_analysis: YARA pattern matching results
            - vulnerability_analysis: Static vulnerability scan results
            - combined_assessment: Overall security assessment and recommendations
    """
    logging.info(f"Extracting comprehensive security analysis from {repo_path}")
    
    try:
        from enhanced_analyzer import analyze_repository_comprehensive
        
        # Perform comprehensive analysis with medium vulnerability threshold
        analysis_results = analyze_repository_comprehensive(
            repo_path, 
            vulnerability_threshold='medium'
        )
        
        if analysis_results:
            combined_assessment = analysis_results.get('combined_assessment', {})
            logging.info(f"Comprehensive security analysis completed for {repo_path}:")
            logging.info(f"  - Combined risk score: {combined_assessment.get('combined_score', 0)}")
            logging.info(f"  - Risk level: {combined_assessment.get('risk_level', 'UNKNOWN')}")
            logging.info(f"  - Confidence: {combined_assessment.get('confidence', 0)}")
            logging.info(f"  - Threat indicators: {len(combined_assessment.get('threat_indicators', []))}")
        
        return analysis_results
        
    except ImportError as e:
        logging.warning(f"Enhanced analyzer not available, falling back to keyword-only analysis: {e}")
        # Fallback to keyword-only analysis
        return extract_malicious_keywords(repo_path)
        
    except Exception as e:
        logging.error(f"Error extracting comprehensive security analysis from {repo_path}: {e}")
        return {}
import os
import re
import json
import logging
import string
from collections import Counter, defaultdict
import keyword as python_keywords

logging.basicConfig(
    filename="crawler.log",
    filemode="a",
    format="%(asctime)s %(levelname)s: %(message)s",
    level=logging.INFO
)

class MaliciousKeywordExtractor:
    """
    Extracts and analyzes keywords from repository source code files to identify
    potentially malicious-oriented terms based on frequency analysis and filtering.
    
    This implementation follows the methodology described in academic papers on
    malicious repository detection using heterogeneous information networks.
    """
    
    def __init__(self):
        self.code_extensions = {
            '.py', '.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp', '.cs', '.go',
            '.rs', '.php', '.rb', '.swift', '.kt', '.scala', '.clj', '.hs', '.ml',
            '.r', '.m', '.sh', '.bash', '.zsh', '.ps1', '.sql', '.html', '.css',
            '.xml', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
            '.md', '.txt', '.rst', '.tex', '.dockerfile', '.makefile', '.cmake'
        }
        
        # Common programming language keywords to filter out
        self.common_keywords = set([
            # Python keywords
            'and', 'as', 'assert', 'break', 'class', 'continue', 'def', 'del', 'elif', 
            'else', 'except', 'finally', 'for', 'from', 'global', 'if', 'import', 
            'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 
            'try', 'while', 'with', 'yield',
            # JavaScript keywords
            'var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while', 
            'do', 'switch', 'case', 'break', 'continue', 'try', 'catch', 'finally', 
            'throw', 'new', 'this', 'typeof', 'instanceof',
            # Java keywords
            'public', 'private', 'protected', 'static', 'final', 'abstract', 'synchronized',
            'volatile', 'transient', 'native', 'strictfp', 'interface', 'extends', 'implements',
            # C/C++ keywords
            'int', 'char', 'float', 'double', 'void', 'long', 'short', 'unsigned', 'signed',
            'struct', 'union', 'enum', 'typedef', 'sizeof', 'const', 'volatile', 'extern',
            'static', 'auto', 'register', 'inline',
            # Common words
            'the', 'and', 'or', 'not', 'is', 'are', 'was', 'were', 'been', 'have', 'has',
            'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might',
            'can', 'must', 'shall', 'to', 'of', 'in', 'on', 'at', 'by', 'for', 'with',
            'without', 'about', 'over', 'under', 'above', 'below', 'up', 'down', 'out',
            'off', 'into', 'onto', 'upon', 'within', 'through', 'during', 'before',
            'after', 'since', 'until', 'from', 'among', 'between', 'against', 'toward',
            'towards', 'across', 'behind', 'beyond', 'beside', 'beneath', 'throughout'
        ])
        
        # More specific malicious keywords (removed overly broad terms)
        self.malicious_seed_keywords = {
            # Clear malware-related terms
            'spy', 'trojan', 'virus', 'malware', 'backdoor', 'keylogger', 'rootkit', 
            'exploit', 'payload', 'cryptojacking', 'stealer', 'ransomware', 'phishing',
            'botnet', 'ddos', 'attack', 'hack', 'crack', 'bypass', 'injection',
            'zero_day', 'rat', 'remote_access', 'privilege_escalation', 'lateral_movement', 
            'exfiltration', 'c2', 'command_control',
            # Evasion and obfuscation (be more specific)
            'obfuscate', 'steganography', 'hide_process', 'conceal_file',
            # Specific suspicious system interactions
            'shell_exec', 'passthru', 'eval_code', 'exec_command',
            # Registry and persistence (more specific)
            'registry_modify', 'startup_persist', 'autorun_malicious',
            # Clearly suspicious behaviors
            'keylog', 'screenshot_steal', 'webcam_spy', 'microphone_spy', 'steal_data',
            'dump_memory', 'scrape_credentials', 'harvest_tokens'
        }
        
        # Common legitimate programming terms to reduce false positives
        self.legitimate_terms = {
            'test', 'example', 'demo', 'sample', 'tutorial', 'documentation', 'readme',
            'license', 'config', 'configuration', 'settings', 'utils', 'utilities',
            'helper', 'tools', 'framework', 'library', 'package', 'module', 'class',
            'method', 'function', 'variable', 'parameter', 'argument', 'return',
            'value', 'result', 'output', 'input', 'data', 'information', 'content',
            'text', 'string', 'number', 'integer', 'float', 'boolean', 'array',
            'list', 'dictionary', 'object', 'json', 'xml', 'html', 'css', 'javascript',
            # Common system terms that are legitimate
            'start', 'process', 'system', 'service', 'task', 'collection', 'delete',
            'socket', 'connect', 'listen', 'send', 'receive', 'execute', 'command'
        }

    def extract_keywords_from_code(self, code_content, file_extension):
        """
        Extracts keywords from source code content using tokenization and filtering.
        
        Args:
            code_content (str): The source code content
            file_extension (str): File extension to determine language-specific processing
            
        Returns:
            List[str]: List of extracted keywords
        """
        keywords = []
        
        # Remove comments based on file type
        cleaned_code = self._remove_comments(code_content, file_extension)
        
        # Remove strings and character literals
        cleaned_code = self._remove_strings(cleaned_code)
        
        # Tokenize into words
        tokens = self._tokenize(cleaned_code)
        
        # Filter and normalize tokens
        for token in tokens:
            normalized = self._normalize_token(token)
            if normalized and self._is_valid_keyword(normalized):
                keywords.append(normalized)
        
        return keywords

    def _remove_comments(self, code, file_extension):
        """Remove comments based on file type."""
        if file_extension in ['.py', '.sh', '.bash', '.zsh', '.ps1', '.yaml', '.yml']:
            # Remove # comments
            code = re.sub(r'#.*$', '', code, flags=re.MULTILINE)
        
        if file_extension in ['.js', '.ts', '.java', '.cpp', '.c', '.h', '.hpp', '.cs', '.go', '.rs', '.php', '.swift', '.kt', '.scala']:
            # Remove // comments
            code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
            # Remove /* */ comments
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        if file_extension in ['.html', '.xml']:
            # Remove <!-- --> comments
            code = re.sub(r'<!--.*?-->', '', code, flags=re.DOTALL)
        
        if file_extension in ['.css']:
            # Remove /* */ comments
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        
        return code

    def _remove_strings(self, code):
        """Remove string literals to avoid extracting keywords from string content."""
        # Remove single quoted strings
        code = re.sub(r"'[^']*'", '', code)
        # Remove double quoted strings
        code = re.sub(r'"[^"]*"', '', code)
        # Remove template literals (backticks)
        code = re.sub(r'`[^`]*`', '', code)
        # Remove raw strings and f-strings (Python)
        code = re.sub(r'[rfb]?"[^"]*"', '', code)
        code = re.sub(r"[rfb]?'[^']*'", '', code)
        
        return code

    def _tokenize(self, code):
        """Tokenize code into individual words and identifiers."""
        # Split on whitespace and common separators
        tokens = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code)
        
        # Additional tokenization for camelCase and snake_case
        expanded_tokens = []
        for token in tokens:
            # Split camelCase
            camel_split = re.sub(r'([a-z])([A-Z])', r'\1_\2', token).split('_')
            expanded_tokens.extend(camel_split)
            
            # Keep original token as well
            expanded_tokens.append(token)
        
        return expanded_tokens

    def _normalize_token(self, token):
        """Normalize token by converting to lowercase and basic cleaning."""
        if not token:
            return ""
        
        # Convert to lowercase
        token = token.lower().strip()
        
        # Remove leading/trailing punctuation
        token = token.strip(string.punctuation)
        
        # Skip very short tokens (likely not meaningful)
        if len(token) < 3:
            return ""
        
        # Skip very long tokens (likely not keywords)
        if len(token) > 50:
            return ""
        
        # Skip tokens that are just numbers
        if token.isdigit():
            return ""
        
        return token

    def _is_valid_keyword(self, token):
        """Determine if a token is a valid keyword worth analyzing."""
        # Skip common programming keywords
        if token in self.common_keywords:
            return False
        
        # Skip Python built-in keywords
        if token in python_keywords.kwlist:
            return False
        
        # Skip very common legitimate terms (high noise)
        if token in self.legitimate_terms:
            return False
        
        # Must contain at least one letter
        if not re.search(r'[a-zA-Z]', token):
            return False
        
        # Skip tokens with too many numbers
        if len(re.findall(r'\d', token)) > len(token) // 2:
            return False
        
        return True

    def extract_keywords_from_repository(self, repo_path):
        """
        Extract keywords from all code files in a repository.
        
        Args:
            repo_path (str): Path to the repository
            
        Returns:
            Dict containing keyword statistics and analysis
        """
        logging.info("Extracting keywords from repository: " + str(repo_path))
        
        all_keywords = []
        file_count = 0
        keyword_by_file = {}
        
        try:
            for root, dirs, files in os.walk(repo_path):
                # Skip .git directory
                if ".git" in dirs:
                    dirs.remove(".git")
                
                for filename in files:
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, repo_path)
                    
                    # Get file extension
                    _, ext = os.path.splitext(filename.lower())
                    
                    # Only process code files
                    if ext in self.code_extensions or filename.lower() in ['makefile', 'dockerfile', 'readme']:
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            file_keywords = self.extract_keywords_from_code(content, ext)
                            all_keywords.extend(file_keywords)
                            keyword_by_file[rel_path] = file_keywords
                            file_count += 1
                            
                        except (UnicodeDecodeError, IOError, OSError) as e:
                            logging.warning("Could not read file " + str(file_path) + ": " + str(e))
                            continue
            
            # Analyze keyword frequency
            keyword_freq = Counter(all_keywords)
            
            # Filter by frequency (similar to CHI statistic selection in papers)
            total_keywords = len(all_keywords)
            unique_keywords = len(keyword_freq)
            
            # Select keywords that appear frequently enough to be significant
            # but not so frequently that they're generic programming terms
            min_frequency = max(2, total_keywords // 1000)  # At least 0.1% frequency
            max_frequency = total_keywords // 10  # Not more than 10% frequency
            
            filtered_keywords = {
                word: freq for word, freq in keyword_freq.items()
                if min_frequency <= freq <= max_frequency
            }
            
            # Identify potentially malicious keywords
            malicious_keywords = self._identify_malicious_keywords(filtered_keywords)
            
            # Calculate malicious orientation score
            malicious_score = self._calculate_malicious_score(filtered_keywords)
            
            result = {
                'total_files_processed': file_count,
                'total_keywords_extracted': total_keywords,
                'unique_keywords': unique_keywords,
                'filtered_keywords_count': len(filtered_keywords),
                'keyword_frequency': dict(filtered_keywords),
                'malicious_keywords': malicious_keywords,
                'malicious_score': malicious_score,
                'top_keywords': dict(keyword_freq.most_common(50)),
                'keywords_by_file': keyword_by_file
            }
            
            logging.info("Extracted " + str(total_keywords) + " total keywords (" + str(unique_keywords) + " unique) from " + str(file_count) + " files")
            logging.info("Filtered to " + str(len(filtered_keywords)) + " significant keywords")
            logging.info("Identified " + str(len(malicious_keywords)) + " potentially malicious keywords")
            
            return result
            
        except Exception as e:
            logging.error("Error extracting keywords from repository " + str(repo_path) + ": " + str(e))
            return {}

    def _identify_malicious_keywords(self, keyword_freq):
        """
        Identify potentially malicious keywords based on seed keywords and patterns.
        
        Args:
            keyword_freq: Dictionary of keyword frequencies
            
        Returns:
            Dictionary of malicious keywords and their frequencies
        """
        malicious_keywords = {}
        
        for keyword, freq in keyword_freq.items():
            # Skip if it's a legitimate term
            if keyword in self.legitimate_terms:
                continue
                
            # Direct match with seed keywords
            if keyword in self.malicious_seed_keywords:
                malicious_keywords[keyword] = freq
                continue
            
            # Pattern-based detection
            if self._is_malicious_pattern(keyword):
                malicious_keywords[keyword] = freq
                continue
            
            # Substring matching with seed keywords (more conservative)
            for seed in self.malicious_seed_keywords:
                if (len(seed) > 6 and seed in keyword) or (len(keyword) > 6 and keyword in seed):
                    malicious_keywords[keyword] = freq
                    break
        
        return malicious_keywords

    def _is_malicious_pattern(self, keyword):
        """Check if keyword matches malicious patterns - more conservative."""
        # More specific patterns to reduce false positives
        malicious_patterns = [
            r'.*hack.*', r'.*crack.*', r'.*exploit.*', r'.*payload.*', r'.*backdoor.*',
            r'.*trojan.*', r'.*virus.*', r'.*malware.*', r'.*keylog.*', r'.*stealer.*',
            r'.*ransomware.*', r'.*botnet.*', r'.*ddos.*', r'.*injection.*', 
            r'.*bypass.*', r'.*escalat.*', r'.*exfiltrat.*', r'.*c2.*',
            r'.*reverse.*shell.*', r'.*bind.*shell.*', r'.*obfuscat.*'
        ]
        
        # Additional context-based filtering to reduce false positives
        legitimate_contexts = [
            r'.*test.*', r'.*demo.*', r'.*example.*', r'.*tutorial.*', r'.*doc.*',
            r'.*config.*', r'.*setup.*', r'.*install.*'
        ]
        
        # Don't flag if it appears to be in a legitimate context
        for legit_pattern in legitimate_contexts:
            if re.match(legit_pattern, keyword, re.IGNORECASE):
                return False
        
        for pattern in malicious_patterns:
            if re.match(pattern, keyword, re.IGNORECASE):
                return True
        
        return False

    def _calculate_malicious_score(self, keyword_freq):
        """
        Calculate a malicious orientation score for the repository based on keyword analysis.
        
        Args:
            keyword_freq: Dictionary of keyword frequencies
            
        Returns:
            Float score between 0 and 1 indicating malicious orientation
        """
        if not keyword_freq:
            return 0.0
        
        total_freq = sum(keyword_freq.values())
        malicious_freq = 0
        
        for keyword, freq in keyword_freq.items():
            if keyword in self.malicious_seed_keywords or self._is_malicious_pattern(keyword):
                malicious_freq += freq
        
        # Basic frequency-based score
        frequency_score = min(malicious_freq / total_freq, 1.0) if total_freq > 0 else 0.0
        
        # Diversity bonus (more different malicious keywords = higher score)
        malicious_keywords = self._identify_malicious_keywords(keyword_freq)
        diversity_score = min(len(malicious_keywords) / 10, 1.0)  # Normalize to 0-1
        
        # Combined score (weighted average)
        final_score = (0.7 * frequency_score) + (0.3 * diversity_score)
        
        return round(final_score, 3)

    def save_keywords_to_file(self, keywords_data, output_path):
        """Save extracted keywords data to a JSON file."""
        try:
            with open(output_path, 'w') as f:
                json.dump(keywords_data, f, indent=2)
            logging.info("Saved keyword analysis to " + str(output_path))
        except Exception as e:
            logging.error("Error saving keywords to " + str(output_path) + ": " + str(e))

    def analyze_malicious_keywords_batch(self, repositories, output_dir="keyword_analysis"):
        """
        Analyze malicious keywords for a batch of repositories.
        
        Args:
            repositories: List of repository paths
            output_dir: Directory to save analysis results
        """
        os.makedirs(output_dir, exist_ok=True)
        
        batch_results = {}
        all_keywords = Counter()
        
        for repo_path in repositories:
            if not os.path.exists(repo_path):
                logging.warning("Repository path does not exist: " + str(repo_path))
                continue
            
            repo_name = os.path.basename(repo_path)
            logging.info("Analyzing repository: " + str(repo_name))
            
            keywords_data = self.extract_keywords_from_repository(repo_path)
            
            if keywords_data:
                # Save individual repository analysis
                repo_output_path = os.path.join(output_dir, repo_name + "_keywords.json")
                self.save_keywords_to_file(keywords_data, repo_output_path)
                
                # Add to batch results
                batch_results[repo_name] = keywords_data
                
                # Accumulate keywords for global analysis
                repo_keywords = keywords_data.get('keyword_frequency', {})
                all_keywords.update(repo_keywords)
        
        # Save batch summary
        batch_summary = {
            'total_repositories_analyzed': len(batch_results),
            'global_keyword_frequency': dict(all_keywords.most_common(1000)),
            'repository_results': {repo: {
                'malicious_score': data.get('malicious_score', 0),
                'malicious_keywords_count': len(data.get('malicious_keywords', {})),
                'total_keywords': data.get('total_keywords_extracted', 0)
            } for repo, data in batch_results.items()}
        }
        
        batch_output_path = os.path.join(output_dir, "batch_analysis_summary.json")
        self.save_keywords_to_file(batch_summary, batch_output_path)
        
        logging.info("Completed batch analysis of " + str(len(batch_results)) + " repositories")
        return batch_results


# Utility function for integration with existing codebase
def extract_malicious_keywords(repo_path):
    """
    Convenience function to extract malicious keywords from a repository.
    
    Args:
        repo_path (str): Path to the repository
        
    Returns:
        Dict containing keyword analysis results
    """
    extractor = MaliciousKeywordExtractor()
    return extractor.extract_keywords_from_repository(repo_path)

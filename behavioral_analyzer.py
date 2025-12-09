import os
import sys
import json
import tempfile
import shutil
import subprocess
import logging
import requests
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

VT_API_URL_FILES = "https://www.virustotal.com/api/v3/files"
VT_API_URL_ANALYSES = "https://www.virustotal.com/api/v3/analyses/{}"
VT_API_URL_BEHAVIOURS = "https://www.virustotal.com/api/v3/files/{}/behaviours"

class LanguageAnalyzer:
    
    def __init__(self, llm_api_key: str, llm_api_url: str = "https://api.groq.com/openai/v1/chat/completions"):
        self.llm_api_key = llm_api_key
        self.llm_api_url = llm_api_url
        self.temp_dirs = []
    
    def detect_language(self, repo_path: str) -> str:
        language_indicators = {
            'go': ['go.mod', 'go.sum', '*.go'],
            'python': ['setup.py', 'requirements.txt', 'pyproject.toml', '*.py'],
            'javascript': ['package.json', 'package-lock.json', '*.js', '*.jsx'],
            'typescript': ['package.json', 'tsconfig.json', '*.ts', '*.tsx'],
            'java': ['pom.xml', 'build.gradle', '*.java'],
            'c': ['Makefile', 'CMakeLists.txt', '*.c', '*.h'],
            'cpp': ['Makefile', 'CMakeLists.txt', '*.cpp', '*.hpp'],
            'ruby': ['Gemfile', '*.rb'],
            'php': ['composer.json', '*.php'],
            'rust': ['Cargo.toml', '*.rs']
        }
        
        detected_scores = {}
        
        for language, indicators in language_indicators.items():
            score = 0
            for indicator in indicators:
                if '*' in indicator:
                    ext = indicator
                    for file in Path(repo_path).rglob(ext):
                        score += 1
                else:
                    if (Path(repo_path) / indicator).exists():
                        score += 10
            detected_scores[language] = score
        
        if not detected_scores or max(detected_scores.values()) == 0:
            return 'unknown'
        
        return max(detected_scores, key=detected_scores.get)
    
    def find_entry_points(self, repo_path: str, language: str) -> List[Dict]:
        if language == 'go':
            return self._find_go_entry_points(repo_path)
        elif language == 'python':
            return self._find_python_entry_points(repo_path)
        elif language in ['javascript', 'typescript']:
            return self._find_js_entry_points(repo_path)
        elif language == 'java':
            return self._find_java_entry_points(repo_path)
        elif language in ['c', 'cpp']:
            return self._find_c_entry_points(repo_path)
        elif language == 'ruby':
            return self._find_ruby_entry_points(repo_path)
        elif language == 'php':
            return self._find_php_entry_points(repo_path)
        elif language == 'rust':
            return self._find_rust_entry_points(repo_path)
        else:
            logging.warning(f"Unsupported language: {language}")
            return []
    
    def _find_go_entry_points(self, repo_path: str) -> List[Dict]:
        entry_points = []
        for go_file in Path(repo_path).rglob("*.go"):
            try:
                with open(go_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                if "func main()" in content:
                    entry_points.append({
                        "file": str(go_file.relative_to(repo_path)),
                        "full_path": str(go_file),
                        "content": content,
                        "type": "main"
                    })
            except Exception as e:
                logging.warning(f"Error reading {go_file}: {e}")
        return entry_points
    
    def _find_python_entry_points(self, repo_path: str) -> List[Dict]:
        entry_points = []
        
        for py_file in Path(repo_path).rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if '__main__' in content or 'if __name__' in content:
                    entry_points.append({
                        "file": str(py_file.relative_to(repo_path)),
                        "full_path": str(py_file),
                        "content": content,
                        "type": "main"
                    })
                elif 'def main(' in content:
                    entry_points.append({
                        "file": str(py_file.relative_to(repo_path)),
                        "full_path": str(py_file),
                        "content": content,
                        "type": "function"
                    })
            except Exception as e:
                logging.warning(f"Error reading {py_file}: {e}")
        
        if (Path(repo_path) / "setup.py").exists():
            try:
                with open(Path(repo_path) / "setup.py", 'r', encoding='utf-8') as f:
                    content = f.read()
                    entry_points.append({
                        "file": "setup.py",
                        "full_path": str(Path(repo_path) / "setup.py"),
                        "content": content,
                        "type": "setup"
                    })
            except Exception as e:
                logging.warning(f"Error reading setup.py: {e}")
        
        return entry_points
    
    def _find_js_entry_points(self, repo_path: str) -> List[Dict]:
        entry_points = []
        
        package_json = Path(repo_path) / "package.json"
        if package_json.exists():
            try:
                with open(package_json, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                    main_file = package_data.get('main', 'index.js')
                    main_path = Path(repo_path) / main_file
                    
                    if main_path.exists():
                        with open(main_path, 'r', encoding='utf-8') as mf:
                            content = mf.read()
                            entry_points.append({
                                "file": main_file,
                                "full_path": str(main_path),
                                "content": content,
                                "type": "main"
                            })
            except Exception as e:
                logging.warning(f"Error reading package.json: {e}")
        
        for js_file in Path(repo_path).rglob("*.js"):
            try:
                with open(js_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if any(pattern in content for pattern in ['exports.', 'module.exports', 'export default', 'export function']):
                    entry_points.append({
                        "file": str(js_file.relative_to(repo_path)),
                        "full_path": str(js_file),
                        "content": content,
                        "type": "module"
                    })
            except Exception as e:
                logging.warning(f"Error reading {js_file}: {e}")
        
        return entry_points
    
    def _find_java_entry_points(self, repo_path: str) -> List[Dict]:
        entry_points = []
        
        for java_file in Path(repo_path).rglob("*.java"):
            try:
                with open(java_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if 'public static void main' in content:
                    entry_points.append({
                        "file": str(java_file.relative_to(repo_path)),
                        "full_path": str(java_file),
                        "content": content,
                        "type": "main"
                    })
            except Exception as e:
                logging.warning(f"Error reading {java_file}: {e}")
        
        return entry_points
    
    def _find_c_entry_points(self, repo_path: str) -> List[Dict]:
        entry_points = []
        
        for c_file in Path(repo_path).rglob("*.c"):
            try:
                with open(c_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if 'int main(' in content or 'void main(' in content:
                    entry_points.append({
                        "file": str(c_file.relative_to(repo_path)),
                        "full_path": str(c_file),
                        "content": content,
                        "type": "main"
                    })
            except Exception as e:
                logging.warning(f"Error reading {c_file}: {e}")
        
        return entry_points
    
    def _find_ruby_entry_points(self, repo_path: str) -> List[Dict]:
        entry_points = []
        
        for rb_file in Path(repo_path).rglob("*.rb"):
            try:
                with open(rb_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if '__FILE__ == $0' in content or 'if __FILE__ == $PROGRAM_NAME' in content:
                    entry_points.append({
                        "file": str(rb_file.relative_to(repo_path)),
                        "full_path": str(rb_file),
                        "content": content,
                        "type": "main"
                    })
            except Exception as e:
                logging.warning(f"Error reading {rb_file}: {e}")
        
        return entry_points
    
    def _find_php_entry_points(self, repo_path: str) -> List[Dict]:
        entry_points = []
        
        for php_file in Path(repo_path).rglob("*.php"):
            try:
                with open(php_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                entry_points.append({
                    "file": str(php_file.relative_to(repo_path)),
                    "full_path": str(php_file),
                    "content": content,
                    "type": "script"
                })
            except Exception as e:
                logging.warning(f"Error reading {php_file}: {e}")
        
        return entry_points[:5]
    
    def _find_rust_entry_points(self, repo_path: str) -> List[Dict]:
        entry_points = []
        
        for rs_file in Path(repo_path).rglob("*.rs"):
            try:
                with open(rs_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                if 'fn main()' in content:
                    entry_points.append({
                        "file": str(rs_file.relative_to(repo_path)),
                        "full_path": str(rs_file),
                        "content": content,
                        "type": "main"
                    })
            except Exception as e:
                logging.warning(f"Error reading {rs_file}: {e}")
        
        return entry_points
    
    def generate_executable_variants(self, repo_path: str, language: str, entry_points: List[Dict]) -> List[Dict]:
        if not entry_points:
            logging.warning(f"No entry points found for {language}")
            return []
        
        logging.info(f"Generating executable variants for {language}")
        
        prompt = self._build_llm_prompt(language, repo_path, entry_points)
        
        variants = self._call_llm_for_variants(prompt, language)
        
        return variants
    
    def _build_llm_prompt(self, language: str, repo_path: str, entry_points: List[Dict]) -> str:
        entry_points_info = []
        for ep in entry_points[:3]:
            entry_points_info.append({
                "file": ep["file"],
                "type": ep["type"],
                "snippet": ep["content"][:500]
            })
        
        prompts_by_language = {
            'go': f"""You are a Go expert. Analyze this Go library and create different main.go files that demonstrate various usage scenarios.

Entry Points Found:
{json.dumps(entry_points_info, indent=2)}

Create 3-5 different executable variants that import and use this library:
1. Basic Usage
2. Advanced Usage
3. CLI Tool
4. Service/Server
5. Testing/Demo

For each variant, provide complete, runnable Go code that can be compiled into an executable.

Respond with a JSON object:
{{
  "variants": [
    {{
      "name": "variant_name",
      "description": "what this demonstrates",
      "code": "complete code that can be saved and compiled",
      "build_command": "go build -o variant_name.exe",
      "language": "go"
    }}
  ]
}}""",
            
            'python': f"""You are a Python expert. Analyze this Python library and create different executable scripts that demonstrate various usage scenarios.

Entry Points Found:
{json.dumps(entry_points_info, indent=2)}

Create 3-5 different executable Python scripts that import and use this library:
1. Basic script with main entry point
2. Advanced script with CLI arguments
3. Service/daemon script
4. Test runner script
5. Demo script

For each variant, provide complete, runnable Python code.

Respond with a JSON object:
{{
  "variants": [
    {{
      "name": "variant_name",
      "description": "what this demonstrates",
      "code": "complete Python code",
      "build_command": "pyinstaller --onefile variant_name.py",
      "language": "python"
    }}
  ]
}}""",
            
            'javascript': f"""You are a JavaScript/Node.js expert. Analyze this JavaScript library and create different executable scripts.

Entry Points Found:
{json.dumps(entry_points_info, indent=2)}

Create 3-5 different executable JavaScript programs:
1. Basic Node.js script
2. CLI tool
3. Express server
4. Worker script
5. Test harness

Provide complete, runnable JavaScript code that can be packaged.

Respond with a JSON object:
{{
  "variants": [
    {{
      "name": "variant_name",
      "description": "what this demonstrates",
      "code": "complete JavaScript code",
      "build_command": "pkg -t node18-win-x64 variant_name.js",
      "language": "javascript"
    }}
  ]
}}""",
            
            'java': f"""You are a Java expert. Analyze this Java library and create different executable programs.

Entry Points Found:
{json.dumps(entry_points_info, indent=2)}

Create 3-5 different Java programs with main methods:
1. Basic application
2. CLI tool with arguments
3. Service application
4. Test runner
5. Demo application

Provide complete, runnable Java code.

Respond with a JSON object:
{{
  "variants": [
    {{
      "name": "VariantName",
      "description": "what this demonstrates",
      "code": "complete Java code",
      "build_command": "javac VariantName.java && jar cfe VariantName.jar VariantName VariantName.class",
      "language": "java"
    }}
  ]
}}"""
        }
        
        return prompts_by_language.get(language, f"""Analyze this {language} code and create executable variants.

Entry Points:
{json.dumps(entry_points_info, indent=2)}

Create variants that demonstrate different usage patterns.

Respond with JSON format with "variants" array containing name, description, code, build_command, and language fields.""")
    
    def _call_llm_for_variants(self, prompt: str, language: str) -> List[Dict]:
        headers = {
            "Authorization": f"Bearer {self.llm_api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
            "max_tokens": 4000
        }
        
        try:
            response = requests.post(self.llm_api_url, headers=headers, json=payload, timeout=120)
            response.raise_for_status()
            
            response_data = response.json()
            if "choices" in response_data and len(response_data["choices"]) > 0:
                response_text = response_data["choices"][0]["message"]["content"]
                
                cleaned_json = response_text.strip().replace("```json", "").replace("```", "").strip()
                variants_data = json.loads(cleaned_json)
                
                return variants_data.get('variants', [])
            else:
                logging.error("Invalid LLM response format")
                return []
        
        except Exception as e:
            logging.error(f"Error calling LLM: {e}")
            return []
    
    def build_executables(self, repo_path: str, variants: List[Dict], output_dir: str) -> List[Dict]:
        built_executables = []
        
        for i, variant in enumerate(variants):
            try:
                variant_name = variant.get('name', f'variant_{i+1}')
                code = variant.get('code', '')
                build_command = variant.get('build_command', '')
                language = variant.get('language', 'unknown')
                
                if not code:
                    logging.warning(f"No code for variant {variant_name}")
                    continue
                
                variant_dir = Path(output_dir) / variant_name
                variant_dir.mkdir(parents=True, exist_ok=True)
                
                self._copy_dependencies(repo_path, str(variant_dir), language)
                
                code_file = self._save_variant_code(str(variant_dir), variant_name, code, language)
                
                if not code_file:
                    continue
                
                exe_path = self._build_variant(str(variant_dir), variant_name, build_command, language)
                
                if exe_path:
                    built_executables.append({
                        "name": variant_name,
                        "path": exe_path,
                        "description": variant.get('description', ''),
                        "language": language,
                        "variant_dir": str(variant_dir)
                    })
                    logging.info(f"Built {variant_name} for {language}")
                
            except Exception as e:
                logging.error(f"Error building variant {i+1}: {e}")
        
        return built_executables
    
    def _copy_dependencies(self, src_path: str, dest_path: str, language: str):
        dependency_files = {
            'go': ['go.mod', 'go.sum'],
            'python': ['requirements.txt', 'setup.py', 'pyproject.toml'],
            'javascript': ['package.json', 'package-lock.json', 'node_modules'],
            'java': ['pom.xml', 'build.gradle', 'gradle'],
            'rust': ['Cargo.toml', 'Cargo.lock']
        }
        
        files_to_copy = dependency_files.get(language, [])
        
        for file_name in files_to_copy:
            src_file = Path(src_path) / file_name
            if src_file.exists():
                dest_file = Path(dest_path) / file_name
                try:
                    if src_file.is_dir():
                        if dest_file.exists():
                            shutil.rmtree(dest_file)
                        shutil.copytree(src_file, dest_file)
                    else:
                        shutil.copy2(src_file, dest_file)
                except Exception as e:
                    logging.warning(f"Error copying {file_name}: {e}")
        
        if language in ['go', 'python', 'java', 'rust']:
            for src_file in Path(src_path).rglob("*"):
                if src_file.is_file():
                    ext = src_file.suffix.lower()
                    if ((language == 'go' and ext == '.go') or
                        (language == 'python' and ext == '.py') or
                        (language == 'java' and ext == '.java') or
                        (language == 'rust' and ext == '.rs')):
                        
                        rel_path = src_file.relative_to(src_path)
                        dest_file = Path(dest_path) / rel_path
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        
                        try:
                            shutil.copy2(src_file, dest_file)
                        except Exception as e:
                            logging.debug(f"Could not copy {rel_path}: {e}")
    
    def _save_variant_code(self, variant_dir: str, variant_name: str, code: str, language: str) -> Optional[str]:
        extensions = {
            'go': '.go',
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts',
            'java': '.java',
            'c': '.c',
            'cpp': '.cpp',
            'ruby': '.rb',
            'php': '.php',
            'rust': '.rs'
        }
        
        ext = extensions.get(language, '.txt')
        
        if language == 'go':
            code_file = Path(variant_dir) / 'main.go'
        elif language == 'java':
            code_file = Path(variant_dir) / f'{variant_name}.java'
        else:
            code_file = Path(variant_dir) / f'{variant_name}{ext}'
        
        try:
            with open(code_file, 'w', encoding='utf-8') as f:
                f.write(code)
            return str(code_file)
        except Exception as e:
            logging.error(f"Error saving code file: {e}")
            return None
    
    def _build_variant(self, variant_dir: str, variant_name: str, build_command: str, language: str) -> Optional[str]:
        if not build_command:
            build_command = self._get_default_build_command(variant_name, language)
        
        try:
            logging.info(f"Building {variant_name} with: {build_command}")
            
            result = subprocess.run(
                build_command,
                cwd=variant_dir,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                possible_exe_names = [
                    f"{variant_name}.exe",
                    f"{variant_name}",
                    f"{variant_name}.jar",
                    f"{variant_name}.pyc",
                    "dist/" + variant_name + ".exe",
                    "dist/" + variant_name
                ]
                
                for exe_name in possible_exe_names:
                    exe_path = Path(variant_dir) / exe_name
                    if exe_path.exists():
                        return str(exe_path)
                
                logging.warning(f"Build succeeded but executable not found for {variant_name}")
                return None
            else:
                logging.error(f"Build failed for {variant_name}: {result.stderr}")
                return None
        
        except subprocess.TimeoutExpired:
            logging.error(f"Build timeout for {variant_name}")
            return None
        except Exception as e:
            logging.error(f"Build error for {variant_name}: {e}")
            return None
    
    def _get_default_build_command(self, variant_name: str, language: str) -> str:
        commands = {
            'go': f'go build -o {variant_name}.exe',
            'python': f'pyinstaller --onefile --distpath . {variant_name}.py',
            'javascript': f'pkg -t node18-win-x64 -o {variant_name}.exe {variant_name}.js',
            'java': f'javac {variant_name}.java',
            'c': f'gcc -o {variant_name}.exe {variant_name}.c',
            'cpp': f'g++ -o {variant_name}.exe {variant_name}.cpp',
            'rust': f'rustc {variant_name}.rs -o {variant_name}.exe'
        }
        
        return commands.get(language, f'echo "No build command for {language}"')
    
    def cleanup(self):
        for temp_dir in self.temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception as e:
                logging.warning(f"Could not clean up {temp_dir}: {e}")

class BehavioralAnalysisPipeline:
    
    def __init__(self, vt_api_key: str, llm_api_key: str, llm_api_url: str = "https://api.groq.com/openai/v1/chat/completions"):
        self.vt_api_key = vt_api_key
        self.language_analyzer = LanguageAnalyzer(llm_api_key, llm_api_url)
    
    def analyze_repository(self, repo_path: str, output_dir: str) -> Dict:
        logging.info(f"Starting behavioral analysis for {repo_path}")
        
        language = self.language_analyzer.detect_language(repo_path)
        logging.info(f"Detected language: {language}")
        
        if language == 'unknown':
            logging.warning("Could not detect language")
            return {
                'success': False,
                'error': 'Unknown language'
            }
        
        entry_points = self.language_analyzer.find_entry_points(repo_path, language)
        logging.info(f"Found {len(entry_points)} entry points")
        
        if not entry_points:
            logging.warning("No entry points found")
            return {
                'success': False,
                'error': 'No entry points found'
            }
        
        variants = self.language_analyzer.generate_executable_variants(repo_path, language, entry_points)
        logging.info(f"Generated {len(variants)} variants")
        
        if not variants:
            logging.warning("No variants generated")
            return {
                'success': False,
                'error': 'No variants generated'
            }
        
        built_exes = self.language_analyzer.build_executables(repo_path, variants, output_dir)
        logging.info(f"Built {len(built_exes)} executables")
        
        if not built_exes:
            logging.warning("No executables built")
            return {
                'success': False,
                'error': 'No executables built'
            }
        
        vt_results = []
        for exe_info in built_exes:
            exe_path = exe_info['path']
            
            if not os.path.exists(exe_path):
                logging.warning(f"Executable not found: {exe_path}")
                continue
            
            vt_result = self.submit_to_virustotal(exe_path)
            
            if vt_result:
                vt_results.append({
                    'variant_name': exe_info['name'],
                    'language': exe_info['language'],
                    'description': exe_info['description'],
                    'vt_result': vt_result
                })
        
        return {
            'success': True,
            'language': language,
            'entry_points_count': len(entry_points),
            'variants_generated': len(variants),
            'executables_built': len(built_exes),
            'vt_results': vt_results
        }
    
    def submit_to_virustotal(self, file_path: str) -> Optional[Dict]:
        if not os.path.exists(file_path):
            logging.error(f"File not found: {file_path}")
            return None
        
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:
            logging.warning(f"File too large: {file_size} bytes")
            return None
        
        file_hash = self._calculate_file_hash(file_path)
        
        existing_report = self._check_hash_exists(file_hash)
        if existing_report:
            logging.info(f"Using existing VT report for {os.path.basename(file_path)}")
            return existing_report
        
        logging.info(f"Submitting {os.path.basename(file_path)} to VirusTotal")
        
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            with open(file_path, "rb") as file:
                files = {"file": (os.path.basename(file_path), file)}
                response = requests.post(VT_API_URL_FILES, headers=headers, files=files, timeout=120)
                response.raise_for_status()
                
                analysis_id = response.json().get("data", {}).get("id")
                if not analysis_id:
                    logging.error("Could not get analysis ID")
                    return None
                
                report = self._wait_for_analysis(analysis_id, headers)
                
                if report:
                    behavior_report = self._get_behavior_report(file_hash, headers)
                    
                    return {
                        'file_hash': file_hash,
                        'static_report': report,
                        'behavior_report': behavior_report
                    }
        
        except Exception as e:
            logging.error(f"Error submitting to VirusTotal: {e}")
        
        return None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _check_hash_exists(self, file_hash: str) -> Optional[Dict]:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_api_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logging.debug(f"Error checking hash: {e}")
        
        return None
    
    def _wait_for_analysis(self, analysis_id: str, headers: Dict, max_wait: int = 300) -> Optional[Dict]:
        url = VT_API_URL_ANALYSES.format(analysis_id)
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                response = requests.get(url, headers=headers, timeout=30)
                response.raise_for_status()
                
                result = response.json()
                status = result.get("data", {}).get("attributes", {}).get("status")
                
                if status == "completed":
                    return result
                
                time.sleep(20)
            
            except Exception as e:
                logging.error(f"Error waiting for analysis: {e}")
                time.sleep(20)
        
        logging.error("Analysis timeout")
        return None
    
    def _get_behavior_report(self, file_hash: str, headers: Dict) -> Optional[Dict]:
        url = VT_API_URL_BEHAVIOURS.format(file_hash)
        
        try:
            response = requests.get(url, headers=headers, timeout=60)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logging.debug(f"Error getting behavior report: {e}")
        
        return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Multi-language behavioral analysis')
    parser.add_argument('--repo-path', required=True, help='Path to repository')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    parser.add_argument('--vt-api-key', required=True, help='VirusTotal API key')
    parser.add_argument('--llm-api-key', required=True, help='LLM API key')
    
    args = parser.parse_args()
    
    pipeline = BehavioralAnalysisPipeline(args.vt_api_key, args.llm_api_key)
    
    result = pipeline.analyze_repository(args.repo_path, args.output_dir)
    
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()


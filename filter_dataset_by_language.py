import os
import h5py
import json
import shutil
import logging
from pathlib import Path
from typing import List, Set

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

SUPPORTED_LANGUAGES = {'Python', 'JavaScript', 'Go', 'TypeScript', 'Java', 'C', 'C++', 'Ruby', 'PHP', 'Rust', 'C#', 'Swift', 'Kotlin', 'Scala'}

def get_repo_language_from_hdf5(hdf5_path: str) -> str:
    try:
        with h5py.File(hdf5_path, 'r') as h5file:
            if 'metadata' in h5file and 'repo_info' in h5file['metadata']:
                repo_info_json = h5file['metadata']['repo_info'][()].decode('utf-8')
                repo_info = json.loads(repo_info_json)
                return repo_info.get('language', '').strip()
            
            if 'metadata' in h5file and 'language' in h5file['metadata']:
                language = h5file['metadata']['language'][()].decode('utf-8')
                return language.strip()
    except Exception as e:
        logging.error(f"Error reading language from {hdf5_path}: {e}")
    
    return None

def detect_language_from_files(hdf5_path: str) -> str:
    language_extensions = {
        'Python': {'.py'},
        'JavaScript': {'.js', '.jsx', '.mjs'},
        'TypeScript': {'.ts', '.tsx'},
        'Go': {'.go'},
        'Java': {'.java'},
        'C': {'.c', '.h'},
        'C++': {'.cpp', '.cc', '.cxx', '.hpp', '.hxx'},
        'Ruby': {'.rb'},
        'PHP': {'.php'},
        'Rust': {'.rs'},
        'C#': {'.cs'},
        'Swift': {'.swift'},
        'Kotlin': {'.kt'},
        'Scala': {'.scala'}
    }
    
    try:
        with h5py.File(hdf5_path, 'r') as h5file:
            if 'codebase' not in h5file or 'files' not in h5file['codebase']:
                return None
            
            files_group = h5file['codebase']['files']
            extension_counts = {}
            
            for file_key in files_group.keys():
                file_group = files_group[file_key]
                if 'extension' in file_group:
                    ext = file_group['extension'][()].decode('utf-8').lower()
                    extension_counts[ext] = extension_counts.get(ext, 0) + 1
            
            for language, exts in language_extensions.items():
                for ext in exts:
                    if ext.lower() in extension_counts:
                        return language
    
    except Exception as e:
        logging.error(f"Error detecting language from files in {hdf5_path}: {e}")
    
    return None

def filter_dataset_by_languages(dataset_path: str, output_path: str, languages: Set[str] = None):
    if languages is None:
        languages = SUPPORTED_LANGUAGES
    
    logging.info(f"Filtering dataset from {dataset_path}")
    logging.info(f"Target languages: {', '.join(sorted(languages))}")
    logging.info(f"Output path: {output_path}")
    
    if not os.path.exists(dataset_path):
        logging.error(f"Dataset path does not exist: {dataset_path}")
        return
    
    os.makedirs(output_path, exist_ok=True)
    
    total_repos = 0
    matched_repos = 0
    language_distribution = {}
    
    for group_name in os.listdir(dataset_path):
        group_path = os.path.join(dataset_path, group_name)
        
        if not os.path.isdir(group_path):
            continue
        
        output_group_path = os.path.join(output_path, group_name)
        os.makedirs(output_group_path, exist_ok=True)
        
        for repo_name in os.listdir(group_path):
            repo_path = os.path.join(group_path, repo_name)
            
            if not os.path.isdir(repo_path):
                continue
            
            total_repos += 1
            
            hdf5_files = [f for f in os.listdir(repo_path) if f.endswith('.h5')]
            
            if not hdf5_files:
                logging.warning(f"No HDF5 file found in {repo_path}")
                continue
            
            hdf5_path = os.path.join(repo_path, hdf5_files[0])
            
            repo_language = get_repo_language_from_hdf5(hdf5_path)
            
            if not repo_language:
                repo_language = detect_language_from_files(hdf5_path)
            
            if not repo_language:
                logging.warning(f"Could not determine language for {repo_name}")
                continue
            
            language_distribution[repo_language] = language_distribution.get(repo_language, 0) + 1
            
            if repo_language in languages:
                output_repo_path = os.path.join(output_group_path, repo_name)
                
                if os.path.exists(output_repo_path):
                    logging.info(f"Skipping {repo_name} (already exists)")
                    matched_repos += 1
                    continue
                
                try:
                    shutil.copytree(repo_path, output_repo_path)
                    matched_repos += 1
                    logging.info(f"Copied {repo_name} ({repo_language})")
                except Exception as e:
                    logging.error(f"Error copying {repo_name}: {e}")
    
    logging.info("="*60)
    logging.info("Dataset Filtering Complete")
    logging.info(f"Total repositories processed: {total_repos}")
    logging.info(f"Matched repositories: {matched_repos}")
    logging.info(f"Filtered out: {total_repos - matched_repos}")
    logging.info("\nLanguage Distribution:")
    for lang, count in sorted(language_distribution.items(), key=lambda x: x[1], reverse=True):
        marker = "✓" if lang in languages else "✗"
        logging.info(f"  {marker} {lang}: {count}")
    logging.info("="*60)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Filter dataset by programming languages')
    parser.add_argument('--input', '-i', required=True, help='Input dataset path')
    parser.add_argument('--output', '-o', required=True, help='Output filtered dataset path')
    parser.add_argument('--languages', '-l', nargs='+', 
                       default=['Python', 'JavaScript', 'Go', 'TypeScript', 'Java', 'C', 'C++', 'Ruby', 'PHP', 'Rust'],
                       help='Languages to filter for')
    
    args = parser.parse_args()
    
    filter_dataset_by_languages(args.input, args.output, set(args.languages))

if __name__ == "__main__":
    main()


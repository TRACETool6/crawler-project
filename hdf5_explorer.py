#!/usr/bin/env python3
"""
HDF5 Repository Explorer

This utility helps explore and extract data from HDF5 repository files
created by the crawler system.
"""

import h5py
import json
import argparse
import os
import sys
from pathlib import Path


def explore_hdf5_structure(filepath):
    """Print the structure of an HDF5 file."""
    print(f"\n=== Structure of {filepath} ===")
    
    def print_structure(name, obj):
        indent = "  " * name.count('/')
        if isinstance(obj, h5py.Group):
            print(f"{indent}{name}/ (Group)")
        elif isinstance(obj, h5py.Dataset):
            print(f"{indent}{name} (Dataset: {obj.shape}, {obj.dtype})")
    
    try:
        with h5py.File(filepath, 'r') as f:
            print("File attributes:")
            for key, value in f.attrs.items():
                print(f"  {key}: {value}")
            print("\nStructure:")
            f.visititems(print_structure)
    except Exception as e:
        print(f"Error reading file: {e}")


def extract_metadata(filepath):
    """Extract and display repository metadata."""
    print(f"\n=== Metadata from {filepath} ===")
    
    try:
        with h5py.File(filepath, 'r') as f:
            if 'metadata' in f and 'repo_info' in f['metadata']:
                repo_info_json = f['metadata']['repo_info'][()].decode('utf-8')
                repo_info = json.loads(repo_info_json)
                print(json.dumps(repo_info, indent=2))
            else:
                print("No metadata found in file")
    except Exception as e:
        print(f"Error reading metadata: {e}")


def extract_commit_stats(filepath):
    """Extract and display commit statistics."""
    print(f"\n=== Commit Statistics from {filepath} ===")
    
    try:
        with h5py.File(filepath, 'r') as f:
            if 'commits' in f and 'statistics' in f['commits']:
                stats_group = f['commits']['statistics']
                print("Commit Statistics:")
                for key in stats_group.keys():
                    value = stats_group[key][()]
                    print(f"  {key}: {value}")
            else:
                print("No commit statistics found")
    except Exception as e:
        print(f"Error reading commit statistics: {e}")


def list_code_files(filepath):
    """List all code files stored in the HDF5 file."""
    print(f"\n=== Code Files from {filepath} ===")
    
    try:
        with h5py.File(filepath, 'r') as f:
            if 'codebase' in f and 'files' in f['codebase']:
                files_group = f['codebase']['files']
                print(f"Total files stored: {len(files_group.keys())}")
                print("\nFiles:")
                for file_key in sorted(files_group.keys()):
                    file_group = files_group[file_key]
                    path = file_group['path'][()].decode('utf-8')
                    size = file_group['size'][()]
                    ext = file_group['extension'][()].decode('utf-8')
                    print(f"  {path} ({size} bytes, {ext})")
            else:
                print("No code files found")
    except Exception as e:
        print(f"Error reading code files: {e}")


def extract_file_content(filepath, file_path):
    """Extract content of a specific file."""
    print(f"\n=== Content of {file_path} from {filepath} ===")
    
    try:
        with h5py.File(filepath, 'r') as f:
            if 'codebase' in f and 'files' in f['codebase']:
                files_group = f['codebase']['files']
                
                # Find the file by path
                target_file = None
                for file_key in files_group.keys():
                    file_group = files_group[file_key]
                    stored_path = file_group['path'][()].decode('utf-8')
                    if stored_path == file_path:
                        target_file = file_group
                        break
                
                if target_file:
                    content = target_file['content'][()].decode('utf-8')
                    print(content)
                else:
                    print(f"File {file_path} not found in repository")
            else:
                print("No code files found")
    except Exception as e:
        print(f"Error extracting file content: {e}")


def extract_logs(filepath):
    """Extract crawler logs for this repository."""
    print(f"\n=== Crawler Logs from {filepath} ===")
    
    try:
        with h5py.File(filepath, 'r') as f:
            if 'logs' in f and 'crawler_logs' in f['logs']:
                logs_content = f['logs']['crawler_logs'][()].decode('utf-8')
                log_count = f['logs']['log_entries_count'][()]
                print(f"Number of log entries: {log_count}")
                print("Logs:")
                print(logs_content)
            else:
                print("No logs found")
    except Exception as e:
        print(f"Error reading logs: {e}")


def export_to_json(filepath, output_dir):
    """Export HDF5 data to JSON files."""
    print(f"\n=== Exporting {filepath} to JSON files in {output_dir} ===")
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    try:
        with h5py.File(filepath, 'r') as f:
            # Export metadata
            if 'metadata' in f and 'repo_info' in f['metadata']:
                repo_info_json = f['metadata']['repo_info'][()].decode('utf-8')
                repo_info = json.loads(repo_info_json)
                with open(output_path / 'metadata.json', 'w') as outf:
                    json.dump(repo_info, outf, indent=2)
                print("Exported metadata.json")
            
            # Export commits
            if 'commits' in f and 'commits_data' in f['commits']:
                commits_json = f['commits']['commits_data'][()].decode('utf-8')
                commits = json.loads(commits_json)
                with open(output_path / 'commits.json', 'w') as outf:
                    json.dump(commits, outf, indent=2)
                print("Exported commits.json")
            
            # Export file listing
            if 'codebase' in f and 'files' in f['codebase']:
                files_group = f['codebase']['files']
                files_info = {}
                for file_key in files_group.keys():
                    file_group = files_group[file_key]
                    files_info[file_key] = {
                        'path': file_group['path'][()].decode('utf-8'),
                        'extension': file_group['extension'][()].decode('utf-8'),
                        'size': file_group['size'][()]
                    }
                with open(output_path / 'files_index.json', 'w') as outf:
                    json.dump(files_info, outf, indent=2)
                print("Exported files_index.json")
            
            # Export logs
            if 'logs' in f and 'crawler_logs' in f['logs']:
                logs_content = f['logs']['crawler_logs'][()].decode('utf-8')
                with open(output_path / 'crawler_logs.txt', 'w') as outf:
                    outf.write(logs_content)
                print("Exported crawler_logs.txt")
            
            print(f"Export completed to {output_dir}")
            
    except Exception as e:
        print(f"Error exporting data: {e}")


def main():
    parser = argparse.ArgumentParser(description='HDF5 Repository Explorer')
    parser.add_argument('filepath', help='Path to HDF5 repository file')
    parser.add_argument('--structure', action='store_true', help='Show HDF5 file structure')
    parser.add_argument('--metadata', action='store_true', help='Extract metadata')
    parser.add_argument('--commits', action='store_true', help='Show commit statistics')
    parser.add_argument('--files', action='store_true', help='List code files')
    parser.add_argument('--logs', action='store_true', help='Show crawler logs')
    parser.add_argument('--extract-file', help='Extract content of specific file (provide file path)')
    parser.add_argument('--export', help='Export all data to JSON files (provide output directory)')
    parser.add_argument('--all', action='store_true', help='Show all information')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.filepath):
        print(f"Error: File {args.filepath} does not exist")
        return 1
    
    try:
        # Check if it's a valid HDF5 file
        with h5py.File(args.filepath, 'r') as f:
            pass
    except Exception as e:
        print(f"Error: {args.filepath} is not a valid HDF5 file: {e}")
        return 1
    
    if args.all:
        explore_hdf5_structure(args.filepath)
        extract_metadata(args.filepath)
        extract_commit_stats(args.filepath)
        list_code_files(args.filepath)
        extract_logs(args.filepath)
    else:
        if args.structure:
            explore_hdf5_structure(args.filepath)
        if args.metadata:
            extract_metadata(args.filepath)
        if args.commits:
            extract_commit_stats(args.filepath)
        if args.files:
            list_code_files(args.filepath)
        if args.logs:
            extract_logs(args.filepath)
        if args.extract_file:
            extract_file_content(args.filepath, args.extract_file)
        if args.export:
            export_to_json(args.filepath, args.export)
        
        # If no specific option was given, show basic info
        if not any([args.structure, args.metadata, args.commits, args.files, args.logs, args.extract_file, args.export]):
            print("No specific option selected. Use --help for available options.")
            print("Showing basic structure:")
            explore_hdf5_structure(args.filepath)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

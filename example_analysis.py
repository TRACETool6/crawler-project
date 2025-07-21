#!/usr/bin/env python3
"""
Example script demonstrating how to work with HDF5 repository files
"""

import os
import sys
import h5py
import json

# Add the crawler directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

def analyze_repository_hdf5(hdf5_path):
    """Analyze a repository HDF5 file and extract key insights."""
    print(f"📊 Analyzing repository: {hdf5_path}")
    print("=" * 50)
    
    try:
        with h5py.File(hdf5_path, 'r') as f:
            # Basic file info
            repo_name = f.attrs.get('repository_name', 'Unknown')
            created_at = f.attrs.get('created_at', 'Unknown')
            print(f"Repository: {repo_name}")
            print(f"Processed: {created_at}")
            print()
            
            # Metadata analysis
            if 'metadata' in f:
                print("📋 Repository Metadata:")
                metadata_group = f['metadata']
                
                # Extract key metrics
                if 'stars' in metadata_group:
                    stars = metadata_group['stars'][()]
                    print(f"  ⭐ Stars: {stars}")
                
                if 'forks' in metadata_group:
                    forks = metadata_group['forks'][()]
                    print(f"  🍴 Forks: {forks}")
                
                if 'language' in metadata_group:
                    language = metadata_group['language'][()].decode('utf-8')
                    print(f"  💻 Primary Language: {language}")
                
                if 'size' in metadata_group:
                    size = metadata_group['size'][()]
                    print(f"  📦 Size: {size} KB")
                print()
            
            # Commit analysis
            if 'commits' in f and 'statistics' in f['commits']:
                print("📈 Commit Statistics:")
                stats = f['commits']['statistics']
                
                total_commits = stats['total_commits'][()]
                total_files = stats['total_files_changed'][()]
                total_added = stats['total_lines_added'][()]
                total_deleted = stats['total_lines_deleted'][()]
                
                print(f"  📝 Total Commits: {total_commits}")
                print(f"  📄 Files Changed: {total_files}")
                print(f"  ➕ Lines Added: {total_added}")
                print(f"  ➖ Lines Deleted: {total_deleted}")
                print(f"  📊 Net Lines: {total_added - total_deleted}")
                print()
            
            # Code analysis
            if 'codebase' in f and 'files' in f['codebase']:
                print("💻 Codebase Analysis:")
                files_group = f['codebase']['files']
                
                total_files = f['codebase']['total_files_stored'][()]
                print(f"  📁 Total Files Stored: {total_files}")
                
                # Analyze by file extension
                extensions = {}
                total_size = 0
                
                for file_key in files_group.keys():
                    file_group = files_group[file_key]
                    ext = file_group['extension'][()].decode('utf-8')
                    size = file_group['size'][()]
                    
                    if ext not in extensions:
                        extensions[ext] = {'count': 0, 'size': 0}
                    extensions[ext]['count'] += 1
                    extensions[ext]['size'] += size
                    total_size += size
                
                print(f"  📏 Total Code Size: {total_size} bytes")
                print("  📊 File Types:")
                
                # Sort by count
                for ext, info in sorted(extensions.items(), key=lambda x: x[1]['count'], reverse=True):
                    ext_display = ext if ext else "(no extension)"
                    print(f"    {ext_display}: {info['count']} files, {info['size']} bytes")
                print()
            
            # Most active authors
            if 'commits' in f and 'authors' in f['commits']:
                print("👥 Author Activity:")
                authors = f['commits']['authors']
                author_list = [author.decode('utf-8') for author in authors]
                
                # Count commits per author
                author_counts = {}
                for author in author_list:
                    author_counts[author] = author_counts.get(author, 0) + 1
                
                # Show top 5 authors
                top_authors = sorted(author_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                for author, count in top_authors:
                    print(f"  👤 {author}: {count} commits")
                print()
            
            # Log summary
            if 'logs' in f:
                log_count = f['logs']['log_entries_count'][()]
                print(f"📋 Crawler Logs: {log_count} entries")
                print()
            
    except Exception as e:
        print(f"❌ Error analyzing file: {e}")


def find_and_analyze_repositories(base_path):
    """Find all HDF5 repository files in a directory and analyze them."""
    print(f"🔍 Searching for HDF5 repository files in: {base_path}")
    print("=" * 60)
    
    hdf5_files = []
    
    # Walk through directory structure
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.endswith('.h5'):
                hdf5_files.append(os.path.join(root, file))
    
    if not hdf5_files:
        print("No HDF5 files found.")
        return
    
    print(f"Found {len(hdf5_files)} HDF5 repository files:")
    print()
    
    for hdf5_file in hdf5_files:
        analyze_repository_hdf5(hdf5_file)
        print("\n" + "="*60 + "\n")


def extract_specific_code_file(hdf5_path, file_path):
    """Extract and display a specific code file from an HDF5 repository."""
    print(f"📄 Extracting {file_path} from {hdf5_path}")
    print("=" * 50)
    
    try:
        with h5py.File(hdf5_path, 'r') as f:
            if 'codebase' not in f or 'files' not in f['codebase']:
                print("No codebase found in this repository.")
                return
            
            files_group = f['codebase']['files']
            
            # Find the file
            target_file = None
            for file_key in files_group.keys():
                file_group = files_group[file_key]
                stored_path = file_group['path'][()].decode('utf-8')
                if stored_path == file_path:
                    target_file = file_group
                    break
            
            if target_file:
                content = target_file['content'][()].decode('utf-8')
                size = target_file['size'][()]
                ext = target_file['extension'][()].decode('utf-8')
                
                print(f"File: {file_path}")
                print(f"Size: {size} bytes")
                print(f"Extension: {ext}")
                print("-" * 50)
                print(content)
            else:
                print(f"File '{file_path}' not found in repository.")
                print("Available files:")
                for file_key in files_group.keys():
                    file_group = files_group[file_key]
                    path = file_group['path'][()].decode('utf-8')
                    print(f"  - {path}")
    
    except Exception as e:
        print(f"❌ Error extracting file: {e}")


def main():
    """Main function to demonstrate HDF5 repository analysis."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze HDF5 repository files')
    parser.add_argument('--file', help='Analyze a specific HDF5 file')
    parser.add_argument('--directory', help='Search and analyze all HDF5 files in directory')
    parser.add_argument('--extract', help='Extract specific file (use with --file)')
    
    args = parser.parse_args()
    
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: File {args.file} does not exist")
            return 1
        
        if args.extract:
            extract_specific_code_file(args.file, args.extract)
        else:
            analyze_repository_hdf5(args.file)
    
    elif args.directory:
        if not os.path.exists(args.directory):
            print(f"Error: Directory {args.directory} does not exist")
            return 1
        
        find_and_analyze_repositories(args.directory)
    
    else:
        print("Please specify either --file or --directory")
        print("Examples:")
        print("  python example_analysis.py --file repository.h5")
        print("  python example_analysis.py --file repository.h5 --extract 'src/main.py'")
        print("  python example_analysis.py --directory ./dataset")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

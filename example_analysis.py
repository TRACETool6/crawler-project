#!/usr/bin/env python3
"""
Example script demonstrating malicious keyword extraction from repositories.

This script shows how to use the MaliciousKeywordExtractor to analyze repositories
and identify potentially malicious keywords based on the methodology described in
academic papers on malicious repository detection.
"""

import os
import sys
import json
import logging
from pathlib import Path

# Add the crawler directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

from crawler.keyword_extractor import MaliciousKeywordExtractor
from crawler.storage import read_repo_hdf5

def analyze_repository_keywords(repo_path):
    """
    Analyze a single repository for malicious keywords.
    
    Args:
        repo_path (str): Path to the repository directory
    """
    if not os.path.exists(repo_path):
        print(f"Error: Repository path '{repo_path}' does not exist.")
        return
    
    print(f"Analyzing repository: {repo_path}")
    print("=" * 50)
    
    # Initialize the keyword extractor
    extractor = MaliciousKeywordExtractor()
    
    # Extract keywords from the repository
    keywords_data = extractor.extract_keywords_from_repository(repo_path)
    
    if not keywords_data:
        print("No keywords extracted from repository.")
        return
    
    # Display results
    print(f"Files processed: {keywords_data.get('total_files_processed', 0)}")
    print(f"Total keywords extracted: {keywords_data.get('total_keywords_extracted', 0)}")
    print(f"Unique keywords: {keywords_data.get('unique_keywords', 0)}")
    print(f"Filtered keywords: {keywords_data.get('filtered_keywords_count', 0)}")
    print(f"Malicious score: {keywords_data.get('malicious_score', 0)}")
    print()
    
    # Show malicious keywords if found
    malicious_keywords = keywords_data.get('malicious_keywords', {})
    if malicious_keywords:
        print("Potentially Malicious Keywords Found:")
        print("-" * 40)
        for keyword, frequency in sorted(malicious_keywords.items(), key=lambda x: x[1], reverse=True):
            print(f"  {keyword}: {frequency}")
        print()
    else:
        print("No potentially malicious keywords identified.")
        print()
    
    # Show top 20 most frequent keywords
    top_keywords = keywords_data.get('top_keywords', {})
    if top_keywords:
        print("Top 20 Most Frequent Keywords:")
        print("-" * 30)
        for i, (keyword, frequency) in enumerate(list(top_keywords.items())[:20]):
            print(f"  {i+1:2d}. {keyword}: {frequency}")
        print()
    
    return keywords_data


def analyze_hdf5_repository(hdf5_path):
    """
    Analyze keywords from an already processed HDF5 repository file.
    
    Args:
        hdf5_path (str): Path to the HDF5 file
    """
    if not os.path.exists(hdf5_path):
        print(f"Error: HDF5 file '{hdf5_path}' does not exist.")
        return
    
    print(f"Reading HDF5 repository: {hdf5_path}")
    print("=" * 50)
    
    # Read the HDF5 file
    data = read_repo_hdf5(hdf5_path)
    
    if not data:
        print("Could not read HDF5 file or no data found.")
        return
    
    # Display basic repository info
    metadata = data.get('metadata', {})
    if metadata:
        print(f"Repository: {metadata.get('name', 'Unknown')}")
        print(f"Description: {metadata.get('description', 'No description')}")
        print(f"Language: {metadata.get('language', 'Unknown')}")
        print(f"Stars: {metadata.get('stars', 0)}")
        print()
    
    # Display keyword analysis if available
    keywords_data = data.get('keywords', {})
    keyword_metrics = data.get('keyword_metrics', {})
    
    if keywords_data or keyword_metrics:
        print("Keyword Analysis Results:")
        print("-" * 30)
        
        if keyword_metrics:
            print(f"Files processed: {keyword_metrics.get('total_files_processed', 0)}")
            print(f"Total keywords extracted: {keyword_metrics.get('total_keywords_extracted', 0)}")
            print(f"Unique keywords: {keyword_metrics.get('unique_keywords', 0)}")
            print(f"Malicious score: {keyword_metrics.get('malicious_score', 0)}")
            print()
        
        # Show malicious keywords
        malicious_keywords = data.get('malicious_keywords', {})
        if malicious_keywords:
            print("Potentially Malicious Keywords:")
            print("-" * 35)
            for keyword, frequency in sorted(malicious_keywords.items(), key=lambda x: x[1], reverse=True):
                print(f"  {keyword}: {frequency}")
            print()
        else:
            print("No potentially malicious keywords found in stored data.")
    else:
        print("No keyword analysis data found in HDF5 file.")
    
    return data


def batch_analysis_example():
    """
    Example of batch analysis on multiple repositories.
    """
    print("Batch Analysis Example")
    print("=" * 30)
    
    # Look for repository directories
    current_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_dir = os.path.join(current_dir, "fivekdataset")
    
    if not os.path.exists(dataset_dir):
        print(f"Dataset directory not found: {dataset_dir}")
        return
    
    # Find repository directories or HDF5 files
    repositories = []
    for root, dirs, files in os.walk(dataset_dir):
        for file in files:
            if file.endswith('.h5'):
                repositories.append(os.path.join(root, file))
    
    if not repositories:
        print("No HDF5 repository files found in dataset directory.")
        return
    
    print(f"Found {len(repositories)} repository files for analysis:")
    
    results = {}
    for repo_path in repositories[:5]:  # Analyze first 5 repositories
        print(f"\nAnalyzing: {os.path.basename(repo_path)}")
        try:
            data = analyze_hdf5_repository(repo_path)
            if data:
                metrics = data.get('keyword_metrics', {})
                results[os.path.basename(repo_path)] = {
                    'malicious_score': metrics.get('malicious_score', 0),
                    'total_keywords': metrics.get('total_keywords_extracted', 0),
                    'malicious_keywords_count': len(data.get('malicious_keywords', {}))
                }
        except Exception as e:
            print(f"Error analyzing {repo_path}: {e}")
    
    # Summary
    print("\n" + "=" * 50)
    print("BATCH ANALYSIS SUMMARY")
    print("=" * 50)
    
    for repo_name, metrics in results.items():
        print(f"{repo_name}:")
        print(f"  Malicious Score: {metrics['malicious_score']}")
        print(f"  Total Keywords: {metrics['total_keywords']}")
        print(f"  Malicious Keywords: {metrics['malicious_keywords_count']}")
        print()


def main():
    """Main function to demonstrate keyword extraction capabilities."""
    print("Malicious Keyword Extraction Demo")
    print("=" * 40)
    print()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Check if a specific repository path was provided
    if len(sys.argv) > 1:
        repo_path = sys.argv[1]
        if repo_path.endswith('.h5'):
            analyze_hdf5_repository(repo_path)
        else:
            analyze_repository_keywords(repo_path)
    else:
        # Run batch analysis on available data
        batch_analysis_example()


if __name__ == "__main__":
    main()

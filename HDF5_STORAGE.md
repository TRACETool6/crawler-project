# HDF5 Storage Integration for Repository Crawler

## Overview

This document describes the enhanced HDF5 storage functionality added to the repository crawler system. The system now stores all repository data, including code files and logs, in a single HDF5 file per repository instead of separate JSON files.

## Key Features

### 1. Unified Storage Format
- **Single File per Repository**: Each repository is stored in one HDF5 file (`{repo_name}.h5`)
- **Hierarchical Structure**: Organized data structure with separate groups for different data types
- **Efficient Storage**: HDF5 provides better compression and faster access than JSON files
- **Cross-platform Compatibility**: HDF5 files can be read on any platform with HDF5 support

### 2. Data Organization

Each HDF5 file contains the following groups:

```
repository.h5
├── metadata/           # Repository metadata
│   ├── repo_info       # Full repository information (JSON)
│   ├── stars           # Star count
│   ├── forks           # Fork count
│   ├── language        # Primary language
│   └── ...             # Other metadata fields
├── commits/            # Commit information
│   ├── commits_data    # Full commit history (JSON)
│   ├── commit_shas     # Array of commit SHAs
│   ├── authors         # Array of author names
│   ├── dates           # Array of commit dates
│   ├── messages        # Array of commit messages
│   └── statistics/     # Aggregate statistics
│       ├── total_commits
│       ├── total_files_changed
│       ├── total_lines_added
│       └── total_lines_deleted
├── codebase/           # Source code files
│   ├── files/          # Individual code files
│   │   ├── {file1}/    # Each file as a group
│   │   │   ├── content     # File content
│   │   │   ├── path        # Original file path
│   │   │   ├── extension   # File extension
│   │   │   └── size        # File size
│   │   └── ...
│   └── total_files_stored  # Count of stored files
└── logs/               # Crawler logs
    ├── crawler_logs    # Repository-specific log entries
    └── log_entries_count   # Number of log entries
```

### 3. Supported File Types

The system automatically stores the following types of files:

**Programming Languages:**
- Python (`.py`)
- JavaScript/TypeScript (`.js`, `.ts`)
- Java (`.java`)
- C/C++ (`.c`, `.cpp`, `.h`, `.hpp`)
- C# (`.cs`)
- Go (`.go`)
- Rust (`.rs`)
- PHP (`.php`)
- Ruby (`.rb`)
- Swift (`.swift`)
- Kotlin (`.kt`)
- Scala (`.scala`)
- And many more...

**Configuration & Documentation:**
- JSON, YAML, TOML (`.json`, `.yaml`, `.yml`, `.toml`)
- Configuration files (`.ini`, `.cfg`, `.conf`)
- Documentation (`.md`, `.txt`, `.rst`)
- Docker files (`dockerfile`)
- Build files (`makefile`, `.cmake`)

## Installation

### Prerequisites

```bash
pip install h5py>=3.8.0 GitPython>=3.1.0 requests>=2.28.0 numpy>=1.24.0
```

Or install from the requirements file:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Running the Crawler

The crawler now automatically saves data in HDF5 format. No changes to the main crawler usage are required:

```bash
python crawler/main.py
```

### 2. Exploring HDF5 Files

Use the provided explorer utility to examine HDF5 files:

```bash
# Show complete structure and data
python hdf5_explorer.py path/to/repository.h5 --all

# Show only file structure
python hdf5_explorer.py path/to/repository.h5 --structure

# Show repository metadata
python hdf5_explorer.py path/to/repository.h5 --metadata

# Show commit statistics
python hdf5_explorer.py path/to/repository.h5 --commits

# List all code files
python hdf5_explorer.py path/to/repository.h5 --files

# Extract specific file content
python hdf5_explorer.py path/to/repository.h5 --extract-file "src/main.py"

# Show crawler logs
python hdf5_explorer.py path/to/repository.h5 --logs

# Export all data to JSON files
python hdf5_explorer.py path/to/repository.h5 --export output_directory/
```

### 3. Programmatic Access

You can read HDF5 files programmatically:

```python
from crawler.storage import read_repo_hdf5

# Read repository data
data = read_repo_hdf5('path/to/repository.h5')

if data:
    print(f"Repository: {data['attributes']['repository_name']}")
    print(f"Files stored: {data['total_files_stored']}")
    print(f"Commits: {len(data['commits'])}")
    
    # Access specific file contents
    files = data['files']
    for file_key, file_info in files.items():
        print(f"File: {file_info['path']} ({file_info['size']} bytes)")
```

### 4. Direct HDF5 Access

For advanced users, you can directly access HDF5 files:

```python
import h5py
import json

with h5py.File('repository.h5', 'r') as f:
    # Read metadata
    if 'metadata/repo_info' in f:
        repo_info = json.loads(f['metadata/repo_info'][()].decode('utf-8'))
    
    # Read a specific file
    if 'codebase/files/src_main_dot_py' in f:
        file_group = f['codebase/files/src_main_dot_py']
        content = file_group['content'][()].decode('utf-8')
        path = file_group['path'][()].decode('utf-8')
        print(f"Content of {path}:")
        print(content)
```

## Testing

Run the test script to verify HDF5 functionality:

```bash
python test_hdf5.py
```

This will:
1. Create a mock repository structure
2. Generate test metadata and commits
3. Save everything to HDF5 format
4. Read the data back and verify integrity
5. Provide the location of the test HDF5 file for manual inspection

## Benefits of HDF5 Storage

### 1. Performance
- **Faster Access**: HDF5 provides faster read/write operations compared to JSON
- **Compression**: Built-in compression reduces file sizes
- **Parallel Access**: Supports concurrent reading of different parts of the file

### 2. Organization
- **Hierarchical Structure**: Natural organization of different data types
- **Metadata Support**: File-level and dataset-level attributes for additional information
- **Type Safety**: Proper data types instead of everything being strings

### 3. Scalability
- **Large Files**: Can handle very large repositories efficiently
- **Memory Efficiency**: Can read specific parts without loading entire file
- **Cross-platform**: Standard format readable by many tools and languages

### 4. Analysis-Friendly
- **Direct Access**: Can access specific commits, files, or metadata without parsing entire file
- **Tool Support**: Compatible with scientific computing tools (pandas, numpy, etc.)
- **Query Capability**: Can build indices for fast searching

## Migration from JSON

The new system is designed to replace the JSON-based storage. Key differences:

| Aspect | Old (JSON) | New (HDF5) |
|--------|------------|------------|
| Files per repo | Multiple JSON files | Single HDF5 file |
| Code storage | Not stored | Full code content |
| Log storage | Global log file | Per-repository logs |
| Access speed | Slower (parse entire file) | Faster (direct access) |
| File size | Larger (text format) | Smaller (binary + compression) |
| Tool support | Text editors, JSON tools | HDF5 viewers, scientific tools |

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure h5py is installed: `pip install h5py`
2. **Permission Errors**: Check write permissions in the output directory
3. **Large Files**: The system limits to 1000 files per repository to prevent extremely large files
4. **Memory Issues**: For very large repositories, consider increasing system memory or reducing the file limit

### File Corruption

If an HDF5 file appears corrupted:

```bash
# Check file integrity
python -c "import h5py; h5py.File('repository.h5', 'r')"

# Use h5dump tool if available
h5dump repository.h5
```

## Future Enhancements

Potential improvements for the HDF5 storage system:

1. **Compression Tuning**: Optimize compression settings for different file types
2. **Indexing**: Add search indices for faster querying
3. **Incremental Updates**: Support for updating existing HDF5 files
4. **Parallel Processing**: Leverage HDF5's parallel I/O capabilities
5. **Schema Versioning**: Version the HDF5 schema for backward compatibility

## Support

For issues or questions regarding the HDF5 storage functionality:

1. Check this documentation
2. Run the test script to verify your installation
3. Use the explorer utility to debug file issues
4. Check the crawler logs for error messages

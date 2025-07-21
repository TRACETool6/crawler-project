#!/usr/bin/env python3
"""
Test script to demonstrate HDF5 storage functionality
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add the crawler directory to the path so we can import modules
sys.path.append(os.path.join(os.path.dirname(__file__), 'crawler'))

try:
    from storage import save_repo_data, read_repo_hdf5
except ImportError as e:
    print(f"Error importing storage module: {e}")
    print("Make sure you're running this script from the project root directory")
    sys.exit(1)


def create_test_repo():
    """Create a mock repository structure for testing."""
    test_repo_dir = tempfile.mkdtemp(prefix="test_repo_")
    
    # Create some test files
    test_files = {
        "README.md": "# Test Repository\n\nThis is a test repository for HDF5 storage.",
        "main.py": "#!/usr/bin/env python3\nprint('Hello, World!')\n",
        "config.json": '{\n  "version": "1.0.0",\n  "name": "test-repo"\n}',
        "src/utils.py": "def helper_function():\n    return 'helper'\n",
        "src/main.cpp": "#include <iostream>\nint main() {\n    std::cout << \"Hello!\" << std::endl;\n    return 0;\n}",
        "docs/guide.md": "# User Guide\n\nThis is the user guide."
    }
    
    for file_path, content in test_files.items():
        full_path = os.path.join(test_repo_dir, file_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w') as f:
            f.write(content)
    
    return test_repo_dir


def create_test_data():
    """Create test repository metadata and commits."""
    repo_info = {
        "name": "test-repo",
        "full_name": "testuser/test-repo",
        "description": "A test repository for HDF5 storage",
        "language": "Python",
        "stars": 42,
        "forks": 7,
        "size": 1024,
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-01-15T12:00:00Z",
        "topics": ["test", "hdf5", "storage"]
    }
    
    commits = [
        {
            "sha": "abc123def456",
            "author": {"name": "Test User", "email": "test@example.com"},
            "committer": {"name": "Test User", "email": "test@example.com"},
            "author_date": "2024-01-01T10:00:00Z",
            "commit_date": "2024-01-01T10:00:00Z",
            "message": "Initial commit",
            "parents": [],
            "files_changed": [{"path": "README.md", "insertions": 5, "deletions": 0, "lines_changed": 5}],
            "total_lines_added": 5,
            "total_lines_deleted": 0,
            "total_files_changed": 1
        },
        {
            "sha": "def456ghi789",
            "author": {"name": "Test User", "email": "test@example.com"},
            "committer": {"name": "Test User", "email": "test@example.com"},
            "author_date": "2024-01-02T14:30:00Z",
            "commit_date": "2024-01-02T14:30:00Z",
            "message": "Add main.py and configuration",
            "parents": ["abc123def456"],
            "files_changed": [
                {"path": "main.py", "insertions": 2, "deletions": 0, "lines_changed": 2},
                {"path": "config.json", "insertions": 4, "deletions": 0, "lines_changed": 4}
            ],
            "total_lines_added": 6,
            "total_lines_deleted": 0,
            "total_files_changed": 2
        }
    ]
    
    return repo_info, commits


def test_hdf5_storage():
    """Test the HDF5 storage functionality."""
    print("🔧 Creating test repository...")
    test_repo_path = create_test_repo()
    
    print("📊 Creating test data...")
    repo_info, commits = create_test_data()
    
    # Create a temporary directory for the HDF5 output
    output_dir = tempfile.mkdtemp(prefix="hdf5_test_")
    
    try:
        print("💾 Saving data to HDF5...")
        
        # Add console logging to see what's happening
        import logging
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        console_handler.setFormatter(formatter)
        
        # Get the root logger and add console handler
        root_logger = logging.getLogger()
        root_logger.addHandler(console_handler)
        root_logger.setLevel(logging.INFO)
        
        try:
            # Save the repository data with custom base path
            save_repo_data("test_group", "test_repo", repo_info, commits, {}, test_repo_path, output_dir)
            print("✅ save_repo_data completed successfully")
        except Exception as save_error:
            print(f"❌ Error in save_repo_data: {save_error}")
            import traceback
            traceback.print_exc()
        finally:
            # Remove console handler
            root_logger.removeHandler(console_handler)
        
        # Check if the HDF5 file was created
        hdf5_file = os.path.join(output_dir, "test_group", "test_repo", "test_repo.h5")
        print(f"🔍 Looking for HDF5 file at: {hdf5_file}")
        print(f"🔍 Output directory contents: {os.listdir(output_dir) if os.path.exists(output_dir) else 'Directory does not exist'}")
        
        # Check if test_group directory exists
        test_group_dir = os.path.join(output_dir, "test_group")
        if os.path.exists(test_group_dir):
            print(f"🔍 test_group directory contents: {os.listdir(test_group_dir)}")
            test_repo_dir = os.path.join(test_group_dir, "test_repo")
            if os.path.exists(test_repo_dir):
                print(f"🔍 test_repo directory contents: {os.listdir(test_repo_dir)}")
        
        if os.path.exists(hdf5_file):
            print(f"✅ HDF5 file created successfully: {hdf5_file}")
            
            # Test reading the data back
            print("📖 Reading data from HDF5...")
            data = read_repo_hdf5(hdf5_file)
            
            if data:
                print("✅ Successfully read data from HDF5 file")
                print(f"   Repository: {data.get('attributes', {}).get('repository_name', 'N/A')}")
                print(f"   Files stored: {data.get('total_files_stored', 0)}")
                print(f"   Commits: {len(data.get('commits', []))}")
                print(f"   Log entries: {data.get('log_entries_count', 0)}")
                
                # List some files
                files = data.get('files', {})
                if files:
                    print("   Code files:")
                    for file_key, file_info in list(files.items())[:5]:  # Show first 5 files
                        print(f"     - {file_info['path']} ({file_info['size']} bytes)")
                
                print(f"\n🎉 Test completed successfully!")
                print(f"📁 HDF5 file location: {hdf5_file}")
                print(f"💡 You can explore the file using: python hdf5_explorer.py '{hdf5_file}' --all")
                
            else:
                print("❌ Failed to read data from HDF5 file")
        else:
            print("❌ HDF5 file was not created")
    
    except Exception as e:
        print(f"❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up test repository
        print("🧹 Cleaning up test repository...")
        shutil.rmtree(test_repo_path, ignore_errors=True)
        
        # Note: We don't clean up the output directory so users can examine the HDF5 file
        print(f"📝 Output directory preserved for inspection: {output_dir}")


if __name__ == "__main__":
    print("🧪 HDF5 Storage Test")
    print("=" * 50)
    test_hdf5_storage()

import os
import shutil
import logging
from pathlib import Path
from typing import List, Tuple, Dict
import uuid
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def collect_python_files(directory_path: str, base_temp_folder: str = "temp") -> Tuple[List[str], Dict, str]:
    """
    Walk through a directory and all subdirectories to collect all .py files.
    Copy collected files to a temp folder with unique session ID while maintaining relative structure.
    
    Args:
        directory_path: Root directory path to start searching
        base_temp_folder: Base temp folder (default: "temp")
    
    Returns:
        Tuple containing:
            - List of collected Python file paths (relative to source directory)
            - Dictionary with statistics
            - Session ID (unique identifier for this collection run)
    
    Edge Cases Handled:
        - No Python files: Returns empty list
        - Permission denied: Skips file, logs warning
        - Broken encoding: Reads with errors='ignore'
    """
    
    # Generate unique session ID
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4())[:8]
    
    # Directories to skip
    SKIP_DIRS = {'.git', '__pycache__', '.venv', 'node_modules'}
    
    # Initialize results
    collected_files = []
    stats = {
        'total_files': 0,
        'skipped_permission': 0,
        'skipped_encoding': 0,
        'warnings': [],
        'session_id': session_id,
        'timestamp': datetime.now().isoformat(),
        'source_directory': str(Path(directory_path).absolute())
    }
    
    # Validate input directory
    source_path = Path(directory_path)
    if not source_path.exists():
        error_msg = f"Directory does not exist: {directory_path}"
        logger.error(error_msg)
        stats['warnings'].append(error_msg)
        return collected_files, stats, session_id
    
    if not source_path.is_dir():
        error_msg = f"Path is not a directory: {directory_path}"
        logger.error(error_msg)
        stats['warnings'].append(error_msg)
        return collected_files, stats, session_id
    
    # Create temp folder with session ID
    temp_path = Path(base_temp_folder) / session_id
    try:
        temp_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Session ID: {session_id}")
        logger.info(f"Temp folder: {temp_path.absolute()}")
    except Exception as e:
        error_msg = f"Failed to create temp folder: {e}"
        logger.error(error_msg)
        stats['warnings'].append(error_msg)
        return collected_files, stats, session_id
    
    # Walk through directory
    for root, dirs, files in os.walk(directory_path, topdown=True):
        # Filter out directories to skip (modify dirs in-place to prevent os.walk from entering them)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        
        # Process Python files
        for file in files:
            if file.endswith('.py'):
                source_file = Path(root) / file
                
                # Calculate relative path from source directory
                try:
                    relative_path = source_file.relative_to(source_path)
                except ValueError:
                    # Handle case where file is not relative to source_path
                    relative_path = Path(file)
                
                # Destination path in temp folder
                dest_file = temp_path / relative_path
                
                try:
                    # Create destination directory structure
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Try to read and copy the file
                    try:
                        # Attempt to read with default encoding to verify it's readable
                        with open(source_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # Copy file to temp folder
                        shutil.copy2(source_file, dest_file)
                        
                    except UnicodeDecodeError:
                        # Handle broken encoding - read with errors='ignore'
                        logger.warning(f"Encoding issue in {source_file}, reading with errors='ignore'")
                        stats['skipped_encoding'] += 1
                        stats['warnings'].append(f"Encoding issue: {relative_path}")
                        
                        try:
                            with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # Write to destination with cleaned content
                            with open(dest_file, 'w', encoding='utf-8') as f:
                                f.write(content)
                        except Exception as e:
                            logger.warning(f"Failed to process file with encoding errors: {source_file} - {e}")
                            continue
                    
                    # Successfully collected
                    collected_files.append(str(relative_path))
                    stats['total_files'] += 1
                    logger.info(f"Collected: {relative_path}")
                    
                except PermissionError:
                    # Handle permission denied
                    warning_msg = f"Permission denied: {relative_path}"
                    logger.warning(warning_msg)
                    stats['skipped_permission'] += 1
                    stats['warnings'].append(warning_msg)
                    
                except Exception as e:
                    # Handle any other unexpected errors
                    warning_msg = f"Error processing {relative_path}: {str(e)}"
                    logger.warning(warning_msg)
                    stats['warnings'].append(warning_msg)
    
    # Log summary
    logger.info(f"\n{'='*50}")
    logger.info(f"Collection Summary:")
    logger.info(f"Session ID: {session_id}")
    logger.info(f"Total Python files collected: {stats['total_files']}")
    logger.info(f"Skipped (permission denied): {stats['skipped_permission']}")
    logger.info(f"Skipped (encoding issues): {stats['skipped_encoding']}")
    logger.info(f"Destination: {temp_path.absolute()}")
    logger.info(f"{'='*50}\n")
    
    # Handle edge case: No Python files found
    if stats['total_files'] == 0:
        logger.info("No Python files found in the directory.")
    
    return collected_files, stats, session_id


# Example usage
if __name__ == "__main__":
    print("="*60)
    print("Python File Collector")
    print("="*60)
    
    # Get directory path from user
    directory = input("\nEnter the directory path to scan: ").strip()
    
    # Validate directory input
    if not directory:
        print("No directory provided. Using current directory '.'")
        directory = "."
    
    print(f"\nStarting collection from: {directory}")
    print("-"*60)
    
    # Collect Python files (session ID will be auto-generated)
    files, statistics, session_id = collect_python_files(directory)
    
    # Display results
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"\nSession ID: {session_id}")
    print(f"Collected {len(files)} Python files:")
    
    if files:
        for i, file in enumerate(files, 1):
            print(f"  {i}. {file}")
    else:
        print("  (No Python files found)")
    
    if statistics['warnings']:
        print(f"\n⚠ Warnings ({len(statistics['warnings'])}):") 
        for warning in statistics['warnings']:
            print(f"  - {warning}")
    
    print(f"\n{'='*60}")

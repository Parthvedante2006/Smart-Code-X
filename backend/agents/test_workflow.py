"""
Complete workflow test: Collect Python files and analyze them with structured organization
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'static_agent_files'))

from collect_python_files import collect_python_files
from static_agent import analyze_temp_folder
import json
from pathlib import Path


def main():
    print("="*70)
    print("COMPLETE STATIC CODE ANALYSIS WORKFLOW")
    print("="*70)
    
    # Step 1: Collect Python files
    print("\n[STEP 1] Collecting Python files...")
    print("-"*70)
    
    directory = input("Enter directory path to scan: ").strip()
    if not directory:
        directory = "."
        print(f"Using current directory: {directory}")
    
    base_temp_folder = "temp"
    
    # Collect files with unique session ID
    files, stats, session_id = collect_python_files(directory, base_temp_folder)
    
    print(f"\n✓ Session ID: {session_id}")
    print(f"✓ Collected {stats['total_files']} Python files")
    print(f"✓ Files stored in: temp/{session_id}/")
    
    if stats['total_files'] == 0:
        print("\n⚠ No Python files found. Exiting.")
        return
    
    # Step 2: Analyze collected files
    print(f"\n[STEP 2] Analyzing collected files...")
    print("-"*70)
    
    # Construct temp folder path with session ID
    temp_folder_path = f"{base_temp_folder}/{session_id}"
    
    # Run analysis with session ID
    results = analyze_temp_folder(temp_folder_path, session_id, "results")
    
    # Step 3: Display results
    print(f"\n{'='*70}")
    print("FINAL ANALYSIS RESULTS")
    print(f"{'='*70}")
    
    print(f"\n� Analysis Metadata:")
    print(f"  Session ID: {session_id}")
    print(f"  Agent: {results.get('agent_name', 'N/A')}")
    print(f"  Source Directory: {stats.get('source_directory', 'N/A')}")
    print(f"  Timestamp: {stats.get('timestamp', 'N/A')}")
    
    print(f"\n�📊 Summary:")
    print(f"  Total Files Analyzed: {results['total_files_analyzed']}")
    print(f"  Total Issues Found: {results['total_issues']}")
    
    if results.get('severity_breakdown'):
        print(f"\n🔍 Severity Breakdown:")
        for severity, count in sorted(results['severity_breakdown'].items()):
            emoji = {'error': '🔴', 'warning': '🟡', 'info': '🔵'}.get(severity, '⚪')
            print(f"  {emoji} {severity.upper()}: {count}")
    
    if results.get('type_breakdown'):
        print(f"\n📋 Top 10 Issue Types:")
        sorted_types = sorted(results['type_breakdown'].items(), key=lambda x: x[1], reverse=True)
        for i, (issue_type, count) in enumerate(sorted_types[:10], 1):
            print(f"  {i}. {issue_type}: {count}")
    
    if results.get('file_breakdown'):
        print(f"\n📁 Files with Most Issues:")
        sorted_files = sorted(results['file_breakdown'].items(), key=lambda x: x[1], reverse=True)
        for i, (file_path, count) in enumerate(sorted_files[:5], 1):
            print(f"  {i}. {file_path}: {count} issues")
    
    # Step 4: Show folder structure
    print(f"\n{'='*70}")
    print("FOLDER STRUCTURE")
    print(f"{'='*70}")
    print(f"\n📂 Project Structure:")
    print(f"  temp/")
    print(f"    └── {session_id}/")
    print(f"        └── [collected Python files]")
    print(f"\n  results/")
    print(f"    └── {session_id}/")
    print(f"        └── static_agent.json")
    
    # Verify files exist
    temp_path = Path(f"temp/{session_id}")
    results_path = Path(f"results/{session_id}/static_agent.json")
    
    print(f"\n✅ Files Created:")
    if temp_path.exists():
        print(f"  ✓ Temp folder: {temp_path.absolute()}")
    if results_path.exists():
        print(f"  ✓ Results file: {results_path.absolute()}")
    
    print(f"\n{'='*70}\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Test script to verify agent CLI execution capability.
This script demonstrates basic functionality and environment checks.
"""

import sys
import os
import platform
from datetime import datetime

def main():
    """Main test function."""
    print("=" * 60)
    print("AGENT CLI EXECUTION TEST")
    print("=" * 60)
    
    # Test 1: Python version
    print(f"\n[TEST 1] Python Version: {sys.version}")
    
    # Test 2: Platform info
    print(f"[TEST 2] Platform: {platform.system()} {platform.release()}")
    
    # Test 3: Working directory
    print(f"[TEST 3] Working Directory: {os.getcwd()}")
    
    # Test 4: Environment variables
    print(f"[TEST 4] User: {os.environ.get('USER', 'N/A')}")
    print(f"[TEST 4] Home: {os.environ.get('HOME', 'N/A')}")
    
    # Test 5: File system access
    test_file = "/workspace/test_agent_cli.py"
    if os.path.exists(test_file):
        print(f"[TEST 5] File System Access: ✓ (Can read {test_file})")
    else:
        print(f"[TEST 5] File System Access: ✗")
    
    # Test 6: Write capability
    try:
        test_write = "/workspace/.test_write"
        with open(test_write, 'w') as f:
            f.write("test")
        os.remove(test_write)
        print(f"[TEST 6] Write Capability: ✓")
    except Exception as e:
        print(f"[TEST 6] Write Capability: ✗ ({e})")
    
    # Test 7: Timestamp
    print(f"[TEST 7] Execution Time: {datetime.now().isoformat()}")
    
    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETED")
    print("=" * 60)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

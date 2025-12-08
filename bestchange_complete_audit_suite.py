#!/usr/bin/env python3
"""
BestChange.com Complete Audit Suite
Master script that runs comprehensive testing
"""

import subprocess
import time
import sys

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def run_all_tests():
    """Run all audit tests"""
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Complete Audit Suite{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tests = [
        ('Quick Audit', 'QUICK_AUDIT.py'),
        ('Aggressive Fuzzer', 'bestchange_aggressive_fuzzer.py'),
        ('Header Exploitation', 'bestchange_header_exploitation.py'),
        ('Mass Parameter Test', 'bestchange_mass_parameter_test.py'),
        ('Exhaustive Testing', 'bestchange_exhaustive_testing.py'),
    ]
    
    results = {}
    start_time = time.time()
    
    for test_name, script in tests:
        print(f"{Colors.CYAN}[*] Running {test_name}...{Colors.RESET}")
        try:
            result = subprocess.run(
                ['python3', f'/workspace/{script}'],
                capture_output=True,
                text=True,
                timeout=120
            )
            results[test_name] = 'completed'
            print(f"{Colors.GREEN}[+] {test_name} completed{Colors.RESET}\n")
        except subprocess.TimeoutExpired:
            results[test_name] = 'timeout'
            print(f"{Colors.YELLOW}[!] {test_name} timed out{Colors.RESET}\n")
        except Exception as e:
            results[test_name] = f'error: {str(e)}'
            print(f"{Colors.RED}[!] {test_name} error{Colors.RESET}\n")
    
    elapsed = time.time() - start_time
    print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}")
    print(f"{Colors.YELLOW}Complete Audit Suite Finished{Colors.RESET}")
    print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
    print(f"{Colors.CYAN}Total Duration: {elapsed:.2f} seconds{Colors.RESET}")
    print(f"{Colors.CYAN}Tests Completed: {sum(1 for v in results.values() if v == 'completed')}/{len(tests)}{Colors.RESET}")

if __name__ == "__main__":
    run_all_tests()

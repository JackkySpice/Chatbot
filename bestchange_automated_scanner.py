#!/usr/bin/env python3
"""
BestChange.com Automated Security Scanner
Runs all audit modules and generates comprehensive report
"""

import subprocess
import time
import json
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class AutomatedScanner:
    def __init__(self):
        self.start_time = time.time()
        self.results = {}
        self.all_findings = []
    
    def run_audit_module(self, module_name, script_path):
        """Run an audit module"""
        print(f"{Colors.BLUE}[*] Running {module_name}...{Colors.RESET}")
        try:
            result = subprocess.run(
                ['python3', script_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            self.results[module_name] = {
                'status': 'completed',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            print(f"{Colors.GREEN}[+] {module_name} completed{Colors.RESET}\n")
            return True
        except subprocess.TimeoutExpired:
            self.results[module_name] = {'status': 'timeout'}
            print(f"{Colors.YELLOW}[!] {module_name} timed out{Colors.RESET}\n")
            return False
        except Exception as e:
            self.results[module_name] = {'status': 'error', 'error': str(e)}
            print(f"{Colors.RED}[!] {module_name} error: {str(e)}{Colors.RESET}\n")
            return False
    
    def run_all_audits(self):
        """Run all audit modules"""
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.CYAN}BestChange.com Automated Security Scanner{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
        
        modules = [
            ('Quick Audit', '/workspace/QUICK_AUDIT.py'),
            ('Session Security', '/workspace/bestchange_session_security.py'),
            ('API Deep Dive', '/workspace/bestchange_api_deep_dive.py'),
            ('Comprehensive Fuzzer', '/workspace/bestchange_comprehensive_fuzzer.py'),
            ('Extended Audit', '/workspace/bestchange_extended_audit.py'),
        ]
        
        for module_name, script_path in modules:
            self.run_audit_module(module_name, script_path)
            time.sleep(1)  # Brief pause between modules
    
    def generate_summary(self):
        """Generate summary report"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}AUTOMATED SCANNER SUMMARY{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Total Duration: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes){Colors.RESET}\n")
        
        print(f"{Colors.BLUE}Modules Executed:{Colors.RESET}")
        for module_name, result in self.results.items():
            status = result.get('status', 'unknown')
            if status == 'completed':
                print(f"  {Colors.GREEN}✓{Colors.RESET} {module_name}")
            elif status == 'timeout':
                print(f"  {Colors.YELLOW}⚠{Colors.RESET} {module_name} (timeout)")
            else:
                print(f"  {Colors.RED}✗{Colors.RESET} {module_name} ({status})")
        
        print(f"\n{Colors.CYAN}For detailed findings, review individual module outputs.{Colors.RESET}")

def main():
    scanner = AutomatedScanner()
    scanner.run_all_audits()
    scanner.generate_summary()

if __name__ == "__main__":
    main()

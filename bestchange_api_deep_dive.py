#!/usr/bin/env python3
"""
BestChange.com API Deep Dive
Comprehensive API endpoint testing and discovery
"""

import requests
import time
import random
import json
import re
from urllib.parse import urljoin, urlparse

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class APIDeepDive:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        self.api_endpoints = []
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/html, */*',
        })
        self.session.timeout = 10
    
    def random_delay(self, min_sec=0.2, max_sec=0.6):
        time.sleep(random.uniform(min_sec, max_sec))
    
    def log_finding(self, vuln_type, location, details, severity="MEDIUM"):
        self.findings.append({
            'type': vuln_type,
            'location': location,
            'details': details,
            'severity': severity
        })
        color = Colors.RED if severity == "HIGH" else Colors.YELLOW if severity == "MEDIUM" else Colors.CYAN
        print(f"{color}[!] {vuln_type} [{severity}]{Colors.RESET}")
        print(f"    {location}: {details}\n")
    
    def discover_api_endpoints(self):
        """Discover API endpoints from various sources"""
        print(f"{Colors.BLUE}[*] Discovering API endpoints...{Colors.RESET}")
        
        # Common API paths
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/api', '/rest/v1',
            '/v1', '/v2', '/v3',
            '/api/rates', '/api/exchange', '/api/currencies',
            '/api/exchangers', '/api/stats', '/api/data',
            '/json', '/json.php', '/ajax', '/ajax.php',
        ]
        
        for path in api_paths:
            try:
                url = urljoin(self.base_url, path)
                
                # Test GET
                response = self.session.get(url, timeout=5)
                self.random_delay()
                
                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('Content-Type', '')
                    if 'json' in content_type.lower() or response.text.strip().startswith(('{', '[')):
                        self.api_endpoints.append(url)
                        print(f"{Colors.CYAN}[+] API endpoint: {url} (Status: {response.status_code}){Colors.RESET}")
                        
                        # Try to parse JSON
                        try:
                            data = response.json()
                            if isinstance(data, dict) and len(data) > 0:
                                self.log_finding(
                                    "API Endpoint Discovered",
                                    url,
                                    f"Returns JSON data with {len(data)} keys",
                                    "INFO"
                                )
                        except:
                            pass
            except:
                continue
    
    def test_api_authentication(self):
        """Test API authentication mechanisms"""
        print(f"{Colors.BLUE}[*] Testing API authentication...{Colors.RESET}")
        
        for endpoint in self.api_endpoints[:5]:  # Test first 5
            # Test without auth
            try:
                response = self.session.get(endpoint, timeout=5)
                self.random_delay()
                
                if response.status_code == 401:
                    print(f"{Colors.GREEN}[+] {endpoint} requires authentication{Colors.RESET}")
                elif response.status_code == 200:
                    self.log_finding(
                        "API Without Authentication",
                        endpoint,
                        "API accessible without authentication",
                        "MEDIUM"
                    )
            except:
                continue
            
            # Test with common API keys
            api_keys = ['test', 'demo', 'admin', 'api', 'key']
            for key in api_keys:
                try:
                    headers = {'X-API-Key': key, 'Authorization': f'Bearer {key}'}
                    response = self.session.get(endpoint, headers=headers, timeout=5)
                    self.random_delay()
                    
                    if response.status_code == 200 and len(response.text) > 100:
                        self.log_finding(
                            "Weak API Authentication",
                            endpoint,
                            f"Accepts weak API key: {key}",
                            "HIGH"
                        )
                except:
                    continue
    
    def test_api_rate_limiting(self):
        """Test API rate limiting"""
        print(f"{Colors.BLUE}[*] Testing API rate limiting...{Colors.RESET}")
        
        for endpoint in self.api_endpoints[:3]:
            try:
                status_codes = []
                for i in range(20):
                    response = self.session.get(endpoint, timeout=5)
                    status_codes.append(response.status_code)
                    time.sleep(0.1)
                
                if 429 not in status_codes:
                    self.log_finding(
                        "API Rate Limiting",
                        endpoint,
                        "No rate limiting detected",
                        "MEDIUM"
                    )
                else:
                    print(f"{Colors.GREEN}[+] {endpoint} has rate limiting{Colors.RESET}")
            except:
                continue
    
    def test_api_input_validation(self):
        """Test API input validation"""
        print(f"{Colors.BLUE}[*] Testing API input validation...{Colors.RESET}")
        
        test_inputs = [
            {'amount': -1},
            {'amount': 999999999},
            {'from': '../'},
            {'to': '<script>alert(1)</script>'},
            {'id': "1' OR '1'='1"},
        ]
        
        for endpoint in self.api_endpoints[:3]:
            for test_input in test_inputs:
                try:
                    # Test as GET params
                    response = self.session.get(endpoint, params=test_input, timeout=5)
                    self.random_delay()
                    
                    # Test as POST JSON
                    response2 = self.session.post(endpoint, json=test_input, timeout=5)
                    self.random_delay()
                    
                    # Check if input is reflected
                    for resp in [response, response2]:
                        if resp.status_code == 200:
                            for key, value in test_input.items():
                                if str(value) in resp.text:
                                    self.log_finding(
                                        "API Input Validation",
                                        endpoint,
                                        f"Input reflected: {key}={value}",
                                        "MEDIUM"
                                    )
                except:
                    continue
    
    def test_api_cors(self):
        """Test API CORS configuration"""
        print(f"{Colors.BLUE}[*] Testing API CORS...{Colors.RESET}")
        
        for endpoint in self.api_endpoints[:5]:
            try:
                headers = {'Origin': 'https://evil.com'}
                response = self.session.get(endpoint, headers=headers, timeout=5)
                self.random_delay()
                
                cors_header = response.headers.get('Access-Control-Allow-Origin')
                if cors_header:
                    if cors_header == '*':
                        self.log_finding(
                            "CORS Misconfiguration",
                            endpoint,
                            "Wildcard CORS policy",
                            "MEDIUM"
                        )
                    elif cors_header == 'https://evil.com':
                        self.log_finding(
                            "CORS Vulnerability",
                            endpoint,
                            "Reflects arbitrary Origin",
                            "HIGH"
                        )
            except:
                continue
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}API DEEP DIVE REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Discovered {len(self.api_endpoints)} API endpoints{Colors.RESET}\n")
        
        if self.findings:
            high = [f for f in self.findings if f['severity'] == 'HIGH']
            medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
            info = [f for f in self.findings if f['severity'] == 'INFO']
            
            print(f"{Colors.RED}[!] Found {len(self.findings)} finding(s){Colors.RESET}")
            print(f"  HIGH: {len(high)}, MEDIUM: {len(medium)}, INFO: {len(info)}\n")
            
            for finding in self.findings:
                color = Colors.RED if finding['severity'] == 'HIGH' else Colors.YELLOW if finding['severity'] == 'MEDIUM' else Colors.CYAN
                print(f"{color}[{finding['severity']}] {finding['type']}{Colors.RESET}")
                print(f"    {finding['location']}: {finding['details']}\n")
        else:
            print(f"{Colors.GREEN}[+] No API vulnerabilities found{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com API Deep Dive{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    api_tester = APIDeepDive()
    
    try:
        api_tester.discover_api_endpoints()
        api_tester.test_api_authentication()
        api_tester.test_api_rate_limiting()
        api_tester.test_api_input_validation()
        api_tester.test_api_cors()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    api_tester.generate_report()

if __name__ == "__main__":
    main()

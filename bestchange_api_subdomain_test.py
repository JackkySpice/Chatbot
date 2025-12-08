#!/usr/bin/env python3
"""
BestChange.com API Subdomain Testing
Comprehensive testing of api.bestchange.com
"""

import requests
import time
import json

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class APISubdomainTester:
    def __init__(self, api_url="https://api.bestchange.com"):
        self.api_url = api_url
        self.session = requests.Session()
        self.findings = []
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, */*',
        })
        self.session.timeout = 10
    
    def random_delay(self, min_sec=0.2, max_sec=0.5):
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
    
    def test_api_root(self):
        """Test API root endpoint"""
        print(f"{Colors.BLUE}[*] Testing API root endpoint...{Colors.RESET}")
        
        try:
            response = self.session.get(self.api_url, timeout=10)
            print(f"{Colors.CYAN}[+] Status: {response.status_code}{Colors.RESET}")
            print(f"{Colors.CYAN}[+] Content-Type: {response.headers.get('Content-Type', 'N/A')}{Colors.RESET}")
            print(f"{Colors.CYAN}[+] Content Length: {len(response.text)} bytes{Colors.RESET}\n")
            
            if response.status_code == 200:
                # Try to parse as JSON
                try:
                    data = response.json()
                    self.log_finding(
                        "API Endpoint Accessible",
                        self.api_url,
                        f"Returns JSON: {str(data)[:200]}",
                        "INFO"
                    )
                except:
                    if len(response.text) > 0:
                        self.log_finding(
                            "API Endpoint Accessible",
                            self.api_url,
                            f"Returns content: {response.text[:200]}",
                            "INFO"
                        )
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {str(e)}{Colors.RESET}")
    
    def test_common_api_paths(self):
        """Test common API paths"""
        print(f"{Colors.BLUE}[*] Testing common API paths...{Colors.RESET}")
        
        common_paths = [
            '/', '/v1', '/v2', '/api', '/rates', '/exchangers',
            '/currencies', '/stats', '/data', '/info', '/health',
        ]
        
        for path in common_paths:
            try:
                url = f"{self.api_url}{path}"
                response = self.session.get(url, timeout=5)
                time.sleep(0.3)
                
                if response.status_code in [200, 401, 403]:
                    print(f"{Colors.CYAN}[+] {path}: Status {response.status_code}{Colors.RESET}")
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            self.log_finding(
                                "API Path Discovered",
                                url,
                                f"Returns JSON data",
                                "INFO"
                            )
                        except:
                            pass
            except:
                continue
    
    def test_api_methods(self):
        """Test different HTTP methods"""
        print(f"{Colors.BLUE}[*] Testing HTTP methods...{Colors.RESET}")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            try:
                if method == 'GET':
                    resp = self.session.get(self.api_url, timeout=5)
                elif method == 'POST':
                    resp = self.session.post(self.api_url, json={}, timeout=5)
                elif method == 'PUT':
                    resp = self.session.put(self.api_url, json={}, timeout=5)
                elif method == 'DELETE':
                    resp = self.session.delete(self.api_url, timeout=5)
                elif method == 'PATCH':
                    resp = self.session.patch(self.api_url, json={}, timeout=5)
                elif method == 'OPTIONS':
                    resp = self.session.options(self.api_url, timeout=5)
                
                if resp.status_code not in [405, 501]:
                    print(f"{Colors.CYAN}[+] {method}: Status {resp.status_code}{Colors.RESET}")
                
                time.sleep(0.2)
            except:
                continue
    
    def test_api_authentication(self):
        """Test API authentication"""
        print(f"{Colors.BLUE}[*] Testing API authentication...{Colors.RESET}")
        
        # Test without auth
        try:
            response = self.session.get(self.api_url, timeout=5)
            if response.status_code == 401:
                print(f"{Colors.GREEN}[+] API requires authentication{Colors.RESET}")
            elif response.status_code == 200:
                self.log_finding(
                    "API Without Authentication",
                    self.api_url,
                    "API accessible without authentication",
                    "MEDIUM"
                )
        except:
            pass
    
    def test_api_cors(self):
        """Test API CORS"""
        print(f"{Colors.BLUE}[*] Testing API CORS...{Colors.RESET}")
        
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.api_url, headers=headers, timeout=5)
            
            cors_header = response.headers.get('Access-Control-Allow-Origin')
            if cors_header:
                if cors_header == '*':
                    self.log_finding(
                        "CORS Misconfiguration",
                        self.api_url,
                        "Wildcard CORS policy",
                        "MEDIUM"
                    )
                elif cors_header == 'https://evil.com':
                    self.log_finding(
                        "CORS Vulnerability",
                        self.api_url,
                        "Reflects arbitrary Origin",
                        "HIGH"
                    )
        except:
            pass
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}API SUBDOMAIN TEST REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
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
    print(f"{Colors.BLUE}BestChange.com API Subdomain Testing{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = APISubdomainTester()
    
    try:
        tester.test_api_root()
        tester.test_common_api_paths()
        tester.test_api_methods()
        tester.test_api_authentication()
        tester.test_api_cors()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
    
    tester.generate_report()

if __name__ == "__main__":
    main()

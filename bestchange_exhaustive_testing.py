#!/usr/bin/env python3
"""
BestChange.com Exhaustive Testing
Comprehensive endpoint and parameter testing
"""

import requests
import time
import random
import concurrent.futures

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class ExhaustiveTester:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.findings = []
        self.tested_endpoints = set()
    
    def test_endpoint_comprehensive(self, path):
        """Comprehensive testing of single endpoint"""
        url = f"{self.base_url}{path}"
        if url in self.tested_endpoints:
            return
        self.tested_endpoints.add(url)
        
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
        session.timeout = 5
        
        try:
            # Test GET
            response = session.get(url, timeout=5)
            time.sleep(0.1)
            
            # Test POST
            try:
                session.post(url, json={}, timeout=5)
                time.sleep(0.1)
            except:
                pass
            
            # Check for interesting responses
            if response.status_code in [200, 301, 302, 403]:
                if len(response.text) > 100:
                    # Check for sensitive patterns
                    sensitive = ['password', 'api_key', 'secret', 'token', 'database']
                    for pattern in sensitive:
                        if pattern in response.text.lower():
                            self.findings.append({
                                'type': 'Sensitive Data',
                                'location': url,
                                'details': f"Contains: {pattern}",
                                'severity': 'MEDIUM'
                            })
                            break
        except:
            pass
    
    def test_all_paths(self):
        """Test all discovered and common paths"""
        print(f"{Colors.BLUE}[*] Testing all paths exhaustively...{Colors.RESET}")
        
        paths = [
            '/', '/index.php', '/click.php',
            '/admin', '/admin.php', '/administrator',
            '/api', '/api/v1', '/api/v2',
            '/test', '/dev', '/staging',
            '/backup', '/backups', '/old',
            '/config.php', '/.env', '/.git/config',
            '/robots.txt', '/sitemap.xml',
        ]
        
        # Test sequentially to avoid rate limits
        for path in paths:
            self.test_endpoint_comprehensive(path)
            time.sleep(0.2)
        
        print(f"{Colors.GREEN}[+] Tested {len(self.tested_endpoints)} endpoints{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Exhaustive Testing{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = ExhaustiveTester()
    tester.test_all_paths()
    
    if tester.findings:
        print(f"\n{Colors.YELLOW}Findings: {len(tester.findings)}{Colors.RESET}")
        for finding in tester.findings:
            print(f"  - {finding['type']}: {finding['location']}")

if __name__ == "__main__":
    main()

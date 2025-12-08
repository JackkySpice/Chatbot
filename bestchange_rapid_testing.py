#!/usr/bin/env python3
"""
BestChange.com Rapid Testing
Fast comprehensive testing suite
"""

import requests
import time
import concurrent.futures

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class RapidTester:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.findings = []
    
    def test_endpoint(self, endpoint):
        """Test single endpoint rapidly"""
        try:
            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0'})
            session.timeout = 5
            
            response = session.get(endpoint, timeout=5)
            
            # Quick checks
            if response.status_code in [200, 301, 302, 403]:
                if 'error' in response.text.lower() and 'sql' in response.text.lower():
                    self.findings.append({
                        'endpoint': endpoint,
                        'type': 'SQL Error',
                        'severity': 'HIGH'
                    })
            
            return response.status_code
        except:
            return None
    
    def rapid_test_all(self):
        """Rapidly test all endpoints"""
        print(f"{Colors.BLUE}[*] Rapid testing all endpoints...{Colors.RESET}")
        
        endpoints = [
            f'{self.base_url}/',
            f'{self.base_url}/index.php',
            f'{self.base_url}/click.php?id=1&from=10&to=58&city=0',
            f'{self.base_url}/admin',
            f'{self.base_url}/api',
        ]
        
        # Test in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(self.test_endpoint, endpoints))
        
        print(f"{Colors.GREEN}[+] Rapid testing completed{Colors.RESET}")
        if self.findings:
            print(f"{Colors.YELLOW}[!] Found {len(self.findings)} issues{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Rapid Testing{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = RapidTester()
    tester.rapid_test_all()

if __name__ == "__main__":
    main()

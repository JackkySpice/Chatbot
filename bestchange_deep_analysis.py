#!/usr/bin/env python3
"""
BestChange.com Deep Analysis
Comprehensive endpoint discovery and vulnerability verification
"""

import requests
import time
import random
import re
from urllib.parse import urljoin, urlparse
from collections import defaultdict

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class DeepAnalysis:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        self.endpoints = defaultdict(list)
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        self.session.timeout = 10
    
    def random_delay(self, min_sec=0.3, max_sec=1.0):
        time.sleep(random.uniform(min_sec, max_sec))
    
    def discover_endpoints_from_html(self):
        """Extract all endpoints from HTML"""
        print(f"{Colors.BLUE}[*] Extracting endpoints from HTML...{Colors.RESET}")
        
        try:
            response = self.session.get(self.base_url)
            html = response.text
            
            # Find all links
            links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
            forms = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html, re.IGNORECASE)
            scripts = re.findall(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            
            all_urls = set(links + forms + scripts)
            
            for url in all_urls:
                if url.startswith('/') or 'bestchange.com' in url:
                    if url.startswith('/'):
                        full_url = urljoin(self.base_url, url)
                    else:
                        full_url = url
                    
                    parsed = urlparse(full_url)
                    if parsed.netloc.endswith('bestchange.com'):
                        self.endpoints[parsed.path].append(full_url)
                        print(f"{Colors.CYAN}[+] Found: {parsed.path}{Colors.RESET}")
            
            print(f"{Colors.GREEN}[+] Discovered {len(self.endpoints)} unique paths{Colors.RESET}\n")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {str(e)}{Colors.RESET}")
    
    def test_endpoint_security(self, path):
        """Test individual endpoint for security issues"""
        url = urljoin(self.base_url, path)
        
        # Test HTTP methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        allowed_methods = []
        
        for method in methods:
            try:
                if method == 'GET':
                    resp = self.session.get(url, timeout=5)
                elif method == 'POST':
                    resp = self.session.post(url, timeout=5)
                elif method == 'PUT':
                    resp = self.session.put(url, timeout=5)
                elif method == 'DELETE':
                    resp = self.session.delete(url, timeout=5)
                elif method == 'PATCH':
                    resp = self.session.patch(url, timeout=5)
                elif method == 'OPTIONS':
                    resp = self.session.options(url, timeout=5)
                elif method == 'HEAD':
                    resp = self.session.head(url, timeout=5)
                
                if resp.status_code not in [405, 501]:
                    allowed_methods.append(method)
                
                self.random_delay(0.2, 0.5)
            except:
                continue
        
        if len(allowed_methods) > 2:
            self.findings.append({
                'type': 'Multiple HTTP Methods',
                'location': url,
                'details': f"Accepts: {', '.join(allowed_methods)}",
                'severity': 'INFO'
            })
    
    def test_sensitive_files(self):
        """Test for sensitive files and directories"""
        print(f"{Colors.BLUE}[*] Testing for sensitive files...{Colors.RESET}")
        
        sensitive_paths = [
            '/.git/config',
            '/.git/HEAD',
            '/.env',
            '/.env.local',
            '/.env.production',
            '/config.php',
            '/config.inc.php',
            '/database.php',
            '/db.php',
            '/wp-config.php',
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/backup.sql',
            '/backup.tar.gz',
            '/backup.zip',
            '/.htaccess',
            '/.htpasswd',
            '/web.config',
            '/.DS_Store',
            '/Thumbs.db',
            '/sitemap.xml',
            '/robots.txt',
            '/.well-known/security.txt',
            '/package.json',
            '/composer.json',
            '/yarn.lock',
            '/package-lock.json',
        ]
        
        for path in sensitive_paths:
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                self.random_delay(0.2, 0.8)
                
                if response.status_code == 200:
                    # Check for sensitive content
                    sensitive_keywords = [
                        'password', 'secret', 'api_key', 'api-key', 'token',
                        'database', 'db_host', 'db_user', 'db_pass',
                        'mysql', 'postgresql', 'mongodb',
                    ]
                    
                    content_lower = response.text.lower()
                    found_keywords = [kw for kw in sensitive_keywords if kw in content_lower]
                    
                    if found_keywords:
                        self.findings.append({
                            'type': 'Sensitive File Exposure',
                            'location': url,
                            'details': f"Contains: {', '.join(found_keywords[:3])}",
                            'severity': 'HIGH'
                        })
                        print(f"{Colors.RED}[!] Sensitive file: {path}{Colors.RESET}")
                    else:
                        self.findings.append({
                            'type': 'File Accessible',
                            'location': url,
                            'details': f"Status: {response.status_code}",
                            'severity': 'INFO'
                        })
                        print(f"{Colors.CYAN}[+] Accessible: {path}{Colors.RESET}")
            except:
                continue
    
    def test_ssl_tls(self):
        """Test SSL/TLS configuration"""
        print(f"{Colors.BLUE}[*] Testing SSL/TLS configuration...{Colors.RESET}")
        
        try:
            import ssl
            import socket
            
            hostname = urlparse(self.base_url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    
                    print(f"{Colors.CYAN}[+] SSL Protocol: {protocol}{Colors.RESET}")
                    
                    # Check certificate details
                    if cert:
                        issuer = dict(x[0] for x in cert['issuer'])
                        subject = dict(x[0] for x in cert['subject'])
                        print(f"{Colors.CYAN}[+] Issuer: {issuer.get('organizationName', 'Unknown')}{Colors.RESET}")
                        print(f"{Colors.CYAN}[+] Subject: {subject.get('commonName', 'Unknown')}{Colors.RESET}")
                    
                    # Check for weak protocols (would need more detailed testing)
                    if protocol in ['TLSv1', 'TLSv1.1']:
                        self.findings.append({
                            'type': 'Weak TLS Protocol',
                            'location': hostname,
                            'details': f"Using {protocol}",
                            'severity': 'MEDIUM'
                        })
        except Exception as e:
            print(f"{Colors.YELLOW}[!] SSL test error: {str(e)}{Colors.RESET}")
    
    def test_cors_configuration(self):
        """Test CORS configuration"""
        print(f"{Colors.BLUE}[*] Testing CORS configuration...{Colors.RESET}")
        
        test_endpoints = [
            '/',
            '/index.php',
            '/images/tableau.json',
        ]
        
        for endpoint in test_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                
                # Test with Origin header
                headers = {'Origin': 'https://evil.com'}
                response = self.session.get(url, headers=headers, timeout=5)
                self.random_delay()
                
                cors_headers = {
                    'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                    'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                    'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
                }
                
                if cors_headers['Access-Control-Allow-Origin']:
                    if cors_headers['Access-Control-Allow-Origin'] == '*':
                        self.findings.append({
                            'type': 'CORS Misconfiguration',
                            'location': url,
                            'details': 'Wildcard CORS policy',
                            'severity': 'MEDIUM'
                        })
                    elif cors_headers['Access-Control-Allow-Origin'] == 'https://evil.com':
                        self.findings.append({
                            'type': 'CORS Vulnerability',
                            'location': url,
                            'details': 'Reflects arbitrary Origin',
                            'severity': 'HIGH'
                        })
            except:
                continue
    
    def test_rate_limiting_detailed(self):
        """Detailed rate limiting test"""
        print(f"{Colors.BLUE}[*] Testing rate limiting in detail...{Colors.RESET}")
        
        test_endpoints = [
            '/',
            '/index.php',
            '/click.php?id=1&from=10&to=58&city=0',
        ]
        
        for endpoint in test_endpoints:
            try:
                url = urljoin(self.base_url, endpoint)
                response_times = []
                status_codes = []
                
                # Send 30 rapid requests
                for i in range(30):
                    start = time.time()
                    try:
                        resp = self.session.get(url, timeout=5)
                        elapsed = time.time() - start
                        response_times.append(elapsed)
                        status_codes.append(resp.status_code)
                        time.sleep(0.05)  # Very short delay
                    except:
                        break
                
                if len(response_times) == 30:
                    avg_time = sum(response_times) / len(response_times)
                    unique_status = set(status_codes)
                    
                    if 429 in unique_status:
                        print(f"{Colors.GREEN}[+] Rate limiting detected on {endpoint}{Colors.RESET}")
                    elif avg_time < 0.3:
                        self.findings.append({
                            'type': 'No Rate Limiting',
                            'location': url,
                            'details': f"Avg response: {avg_time:.2f}s, Status codes: {unique_status}",
                            'severity': 'MEDIUM'
                        })
            except:
                continue
    
    def generate_report(self):
        """Generate comprehensive report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}DEEP ANALYSIS REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        if self.findings:
            high = [f for f in self.findings if f['severity'] == 'HIGH']
            medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
            info = [f for f in self.findings if f['severity'] == 'INFO']
            
            print(f"{Colors.RED}[!] Found {len(self.findings)} finding(s){Colors.RESET}")
            print(f"  HIGH: {len(high)}, MEDIUM: {len(medium)}, INFO: {len(info)}\n")
            
            if high:
                print(f"{Colors.RED}HIGH SEVERITY:{Colors.RESET}")
                for f in high:
                    print(f"  - {f['type']}: {f['location']}")
                    print(f"    {f['details']}\n")
            
            if medium:
                print(f"{Colors.YELLOW}MEDIUM SEVERITY:{Colors.RESET}")
                for f in medium[:10]:  # Limit output
                    print(f"  - {f['type']}: {f['location']}")
                    print(f"    {f['details']}\n")
        else:
            print(f"{Colors.GREEN}[+] No additional findings{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Deep Analysis{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    analyzer = DeepAnalysis()
    
    try:
        analyzer.discover_endpoints_from_html()
        analyzer.test_sensitive_files()
        analyzer.test_ssl_tls()
        analyzer.test_cors_configuration()
        analyzer.test_rate_limiting_detailed()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()
    
    analyzer.generate_report()

if __name__ == "__main__":
    main()

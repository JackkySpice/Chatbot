#!/usr/bin/env python3
"""
MobileSec Red Team Console - Manual Security Audit
Target: media.io
TACTICAL ASSESSMENT: Initial reconnaissance and vulnerability assessment
PROTOCOL: Multi-vector security testing
"""

import requests
import sys
import time
from urllib.parse import urlparse

# ANSI Colors
R = "\x1b[1;31m"
G = "\x1b[1;32m"
Y = "\x1b[1;33m"
B = "\x1b[1;34m"
C = "\x1b[1;36m"
NC = "\x1b[0m"

TARGET = "https://media.io"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def test_headers():
    """Test 1: HTTP Header Security Analysis"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST 1: HTTP Header Security Analysis{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    try:
        r = requests.get(TARGET, headers={'User-Agent': UA}, timeout=10, verify=True)
        print(f"{G}[+] Connection established (Status: {r.status_code}){NC}\n")
        
        # Security headers check
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'Referrer-Policy': 'Referrer policy',
            'Permissions-Policy': 'Permissions policy'
        }
        
        print(f"{C}[*] Security Headers:{NC}")
        vulnerabilities = []
        for header, desc in security_headers.items():
            if header in r.headers:
                print(f"{G}[+] {header}: {r.headers[header]}{NC}")
            else:
                print(f"{R}[-] {header}: MISSING - {desc}{NC}")
                vulnerabilities.append(f"Missing {header}")
        
        # Information disclosure
        print(f"\n{C}[*] Information Disclosure Check:{NC}")
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
        for header in info_headers:
            if header in r.headers:
                print(f"{Y}[!] {header}: {r.headers[header]} (Information disclosure){NC}")
                vulnerabilities.append(f"{header} exposed: {r.headers[header]}")
        
        # All headers
        print(f"\n{C}[*] All Response Headers:{NC}")
        for header, value in sorted(r.headers.items()):
            print(f"  {header}: {value}")
        
        return vulnerabilities, r
        
    except Exception as e:
        print(f"{R}[!] FAILED: {e}{NC}")
        return [], None

def test_directory_discovery():
    """Test 2: Directory and File Discovery"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST 2: Directory/File Discovery{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    wordlist = [
        'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
        'api', 'api/v1', 'api/v2', 'rest', 'graphql',
        'backup', 'config', '.env', '.env.local',
        'robots.txt', 'sitemap.xml', '.git', '.svn',
        'test', 'dev', 'staging', 'debug',
        'swagger.json', 'api-docs', 'openapi.json',
        '.well-known/security.txt', 'crossdomain.xml'
    ]
    
    found = []
    print(f"{C}[*] Testing {len(wordlist)} common paths...{NC}\n")
    
    for path in wordlist:
        try:
            url = f"{TARGET.rstrip('/')}/{path}"
            r = requests.get(url, headers={'User-Agent': UA}, timeout=5, 
                           verify=True, allow_redirects=False)
            
            if r.status_code == 200:
                size = len(r.content)
                print(f"{G}[200] {url} (Size: {size} bytes){NC}")
                found.append((url, 200, size))
            elif r.status_code in [301, 302]:
                location = r.headers.get('Location', 'N/A')
                print(f"{Y}[{r.status_code}] {url} -> {location}{NC}")
                found.append((url, r.status_code, location))
            elif r.status_code == 403:
                print(f"{Y}[403] {url} (Forbidden - but exists){NC}")
                found.append((url, 403, 'Forbidden'))
            elif r.status_code == 401:
                print(f"{C}[401] {url} (Unauthorized){NC}")
                found.append((url, 401, 'Unauthorized'))
            
            time.sleep(0.2)
        except:
            pass
    
    if not found:
        print(f"{C}[*] No accessible resources found with common paths{NC}")
    else:
        print(f"\n{G}[+] Found {len(found)} accessible resources{NC}")
    
    return found

def test_api_endpoints():
    """Test 3: API Endpoint Discovery"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST 3: API Endpoint Discovery{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    endpoints = [
        '/api', '/api/v1', '/api/v2',
        '/rest', '/rest/api', '/graphql',
        '/v1', '/v2',
        '/api/users', '/api/data', '/api/upload',
        '/swagger.json', '/swagger.yaml',
        '/api-docs', '/docs', '/openapi.json'
    ]
    
    methods = ['GET', 'POST', 'OPTIONS']
    discovered = []
    
    for endpoint in endpoints:
        url = f"{TARGET.rstrip('/')}{endpoint}"
        for method in methods:
            try:
                r = requests.request(method, url, headers={'User-Agent': UA}, 
                                    timeout=5, verify=True, allow_redirects=False)
                
                if r.status_code not in [404, 405]:
                    print(f"{G}[{r.status_code}] {method} {url}{NC}")
                    print(f"  Content-Type: {r.headers.get('Content-Type', 'unknown')}")
                    print(f"  Size: {len(r.content)} bytes")
                    if len(r.content) < 500 and r.status_code == 200:
                        print(f"  Preview: {r.text[:100]}...")
                    discovered.append((url, method, r.status_code))
                    break
            except:
                pass
        time.sleep(0.1)
    
    if not discovered:
        print(f"{C}[*] No API endpoints discovered{NC}")
    else:
        print(f"\n{G}[+] Discovered {len(discovered)} API endpoints{NC}")
    
    return discovered

def test_information_disclosure():
    """Test 4: Information Disclosure"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST 4: Information Disclosure Testing{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    test_paths = [
        '/.env',
        '/.git/config',
        '/package.json',
        '/composer.json',
        '/.htaccess',
        '/web.config',
        '/README.md',
        '/CHANGELOG.md',
        '/error',
        '/debug',
        '/phpinfo.php',
        '/info.php'
    ]
    
    found_info = []
    
    for path in test_paths:
        try:
            url = f"{TARGET.rstrip('/')}{path}"
            r = requests.get(url, headers={'User-Agent': UA}, timeout=5, verify=True)
            
            if r.status_code == 200:
                content = r.text.lower()
                # Check for sensitive information
                sensitive_keywords = ['password', 'secret', 'api_key', 'token', 
                                     'database', 'mysql', 'postgres', 'mongodb',
                                     'aws', 's3', 'access_key']
                
                found_keywords = [kw for kw in sensitive_keywords if kw in content]
                if found_keywords:
                    print(f"{R}[!] {url} - Contains sensitive keywords: {', '.join(found_keywords)}{NC}")
                    found_info.append((url, found_keywords))
                else:
                    print(f"{Y}[?] {url} - Accessible (Status: 200){NC}")
                    found_info.append((url, []))
        except:
            pass
    
    if not found_info:
        print(f"{C}[*] No obvious information disclosure found{NC}")
    
    return found_info

def test_error_handling():
    """Test 5: Error Handling and Stack Traces"""
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TEST 5: Error Handling Analysis{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    # Test for error pages that might leak information
    test_urls = [
        f"{TARGET}/nonexistentpage12345",
        f"{TARGET}/../",
        f"{TARGET}/?id=test'",
        f"{TARGET}/?file=../../etc/passwd"
    ]
    
    errors_found = []
    
    for url in test_urls:
        try:
            r = requests.get(url, headers={'User-Agent': UA}, timeout=5, verify=True)
            
            # Check for stack traces or error messages
            error_indicators = [
                'stack trace', 'exception', 'error in', 'fatal error',
                'sql syntax', 'database error', 'mysql', 'postgresql',
                'file not found', 'internal server error', 'traceback'
            ]
            
            content_lower = r.text.lower()
            found_errors = [ind for ind in error_indicators if ind in content_lower]
            
            if found_errors:
                print(f"{R}[!] {url}{NC}")
                print(f"    Contains error indicators: {', '.join(found_errors)}")
                errors_found.append((url, found_errors))
        except:
            pass
    
    if not errors_found:
        print(f"{C}[*] No obvious error disclosure found{NC}")
    
    return errors_found

def main():
    print(f"{B}{'='*70}{NC}")
    print(f"{B}  MOBILESEC RED TEAM CONSOLE - LIVE FIRE AUDIT{NC}")
    print(f"{B}  TARGET: {TARGET}{NC}")
    print(f"{B}{'='*70}{NC}")
    
    all_vulnerabilities = []
    
    # Run all tests
    vulns, response = test_headers()
    all_vulnerabilities.extend(vulns)
    
    found_dirs = test_directory_discovery()
    if found_dirs:
        all_vulnerabilities.append(f"Found {len(found_dirs)} accessible paths")
    
    found_apis = test_api_endpoints()
    if found_apis:
        all_vulnerabilities.append(f"Found {len(found_apis)} API endpoints")
    
    found_info = test_information_disclosure()
    if found_info:
        all_vulnerabilities.append(f"Potential information disclosure: {len(found_info)} paths")
    
    found_errors = test_error_handling()
    if found_errors:
        all_vulnerabilities.append(f"Error disclosure found: {len(found_errors)} instances")
    
    # Final Summary
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] AUDIT SUMMARY{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    if all_vulnerabilities:
        print(f"{R}[!] Found {len(all_vulnerabilities)} potential security issues:{NC}\n")
        for i, vuln in enumerate(all_vulnerabilities, 1):
            print(f"  {i}. {vuln}")
    else:
        print(f"{G}[+] No obvious vulnerabilities detected in initial scan{NC}")
        print(f"{Y}[!] Note: This is a basic scan. Manual testing recommended.{NC}")
    
    print(f"\n{B}[*] Audit completed{NC}")

if __name__ == "__main__":
    main()

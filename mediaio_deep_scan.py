#!/usr/bin/env python3
"""
MobileSec Red Team Console - Deep Scan
Target: www.media.io (following redirects)
TACTICAL ASSESSMENT: All paths redirect to www subdomain - testing actual accessibility
"""

import requests
import sys
import time

# ANSI Colors
R = "\x1b[1;31m"
G = "\x1b[1;32m"
Y = "\x1b[1;33m"
B = "\x1b[1;34m"
C = "\x1b[1;36m"
NC = "\x1b[0m"

TARGET = "https://www.media.io"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

def test_robots_txt():
    """Test robots.txt for information disclosure"""
    print(f"\n{B}[*] Testing robots.txt{NC}\n")
    
    try:
        url = f"{TARGET}/robots.txt"
        r = requests.get(url, headers={'User-Agent': UA}, timeout=10, verify=True)
        
        if r.status_code == 200:
            print(f"{G}[+] robots.txt is accessible{NC}")
            print(f"{C}[*] Content:{NC}")
            print(r.text[:500])
            return True
        else:
            print(f"{C}[*] robots.txt returned status: {r.status_code}{NC}")
            return False
    except Exception as e:
        print(f"{R}[!] Error: {e}{NC}")
        return False

def test_sensitive_paths():
    """Test sensitive paths that redirected"""
    print(f"\n{B}[*] Testing Sensitive Paths on www.media.io{NC}\n")
    
    sensitive_paths = [
        '/admin',
        '/login',
        '/api',
        '/api/v1',
        '/.env',
        '/.git',
        '/config',
        '/backup',
        '/swagger.json',
        '/api-docs'
    ]
    
    accessible = []
    
    for path in sensitive_paths:
        try:
            url = f"{TARGET}{path}"
            r = requests.get(url, headers={'User-Agent': UA}, timeout=5, 
                           verify=True, allow_redirects=False)
            
            if r.status_code == 200:
                size = len(r.content)
                print(f"{G}[200] {url} (Size: {size} bytes){NC}")
                if size < 1000:
                    print(f"    Preview: {r.text[:200]}...")
                accessible.append((url, 200, size))
            elif r.status_code == 403:
                print(f"{Y}[403] {url} (Forbidden - but exists!){NC}")
                accessible.append((url, 403, 'Forbidden'))
            elif r.status_code == 401:
                print(f"{C}[401] {url} (Unauthorized - requires auth){NC}")
                accessible.append((url, 401, 'Unauthorized'))
            elif r.status_code == 301 or r.status_code == 302:
                location = r.headers.get('Location', 'N/A')
                print(f"{C}[{r.status_code}] {url} -> {location}{NC}")
            else:
                print(f"{C}[{r.status_code}] {url}{NC}")
            
            time.sleep(0.3)
        except Exception as e:
            pass
    
    return accessible

def test_api_endpoints():
    """Test API endpoints with different methods"""
    print(f"\n{B}[*] Testing API Endpoints with Different HTTP Methods{NC}\n")
    
    api_paths = ['/api', '/api/v1', '/api/v2', '/rest', '/graphql']
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    
    found = []
    
    for path in api_paths:
        url = f"{TARGET}{path}"
        for method in methods:
            try:
                r = requests.request(method, url, headers={'User-Agent': UA}, 
                                    timeout=5, verify=True, allow_redirects=False)
                
                if r.status_code not in [404, 405]:
                    print(f"{G}[{r.status_code}] {method} {url}{NC}")
                    print(f"    Content-Type: {r.headers.get('Content-Type', 'unknown')}")
                    print(f"    Size: {len(r.content)} bytes")
                    
                    if r.status_code == 200 and len(r.content) < 1000:
                        print(f"    Preview: {r.text[:200]}...")
                    
                    found.append((url, method, r.status_code))
                    break
            except:
                pass
        time.sleep(0.2)
    
    return found

def test_subdomain_enum():
    """Test for subdomains"""
    print(f"\n{B}[*] Testing Common Subdomains{NC}\n")
    
    subdomains = ['api', 'admin', 'dev', 'staging', 'test', 'www', 'mail', 'ftp']
    found = []
    
    for sub in subdomains:
        try:
            url = f"https://{sub}.media.io"
            r = requests.get(url, headers={'User-Agent': UA}, timeout=5, verify=True)
            
            if r.status_code == 200:
                print(f"{G}[+] {url} - Accessible (Status: 200){NC}")
                found.append((url, 200))
            elif r.status_code not in [404, 502, 503]:
                print(f"{Y}[?] {url} - Status: {r.status_code}{NC}")
                found.append((url, r.status_code))
        except requests.exceptions.SSLError:
            print(f"{C}[*] {url} - SSL Error (may not exist){NC}")
        except:
            pass
    
    return found

def test_cors():
    """Test CORS configuration"""
    print(f"\n{B}[*] Testing CORS Configuration{NC}\n")
    
    try:
        # Test with Origin header
        headers = {
            'User-Agent': UA,
            'Origin': 'https://evil.com'
        }
        
        r = requests.get(TARGET, headers=headers, timeout=10, verify=True)
        
        cors_headers = {
            'Access-Control-Allow-Origin': r.headers.get('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Credentials': r.headers.get('Access-Control-Allow-Credentials'),
            'Access-Control-Allow-Methods': r.headers.get('Access-Control-Allow-Methods'),
            'Access-Control-Allow-Headers': r.headers.get('Access-Control-Allow-Headers')
        }
        
        print(f"{C}[*] CORS Headers:{NC}")
        for header, value in cors_headers.items():
            if value:
                if value == '*' or 'evil.com' in value:
                    print(f"{R}[!] {header}: {value} (Potentially vulnerable){NC}")
                else:
                    print(f"{G}[+] {header}: {value}{NC}")
            else:
                print(f"{C}[*] {header}: Not present{NC}")
        
        # Check if wildcard CORS
        if cors_headers['Access-Control-Allow-Origin'] == '*':
            return True  # Vulnerable
        return False
        
    except Exception as e:
        print(f"{R}[!] Error: {e}{NC}")
        return False

def main():
    print(f"{B}{'='*70}{NC}")
    print(f"{B}  MOBILESEC - DEEP SCAN: www.media.io{NC}")
    print(f"{B}{'='*70}{NC}")
    
    vulnerabilities = []
    
    # Test robots.txt
    if test_robots_txt():
        vulnerabilities.append("robots.txt accessible")
    
    # Test sensitive paths
    accessible = test_sensitive_paths()
    if accessible:
        vulnerabilities.append(f"{len(accessible)} sensitive paths accessible")
        for url, status, info in accessible:
            if status == 200:
                vulnerabilities.append(f"CRITICAL: {url} is publicly accessible")
    
    # Test API endpoints
    api_found = test_api_endpoints()
    if api_found:
        vulnerabilities.append(f"{len(api_found)} API endpoints responding")
    
    # Test subdomains
    subdomains = test_subdomain_enum()
    if subdomains:
        vulnerabilities.append(f"{len(subdomains)} subdomains found")
    
    # Test CORS
    cors_vuln = test_cors()
    if cors_vuln:
        vulnerabilities.append("CORS misconfiguration (wildcard or permissive)")
    
    # Summary
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] DEEP SCAN SUMMARY{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    if vulnerabilities:
        print(f"{R}[!] Found {len(vulnerabilities)} security issues:{NC}\n")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"  {i}. {vuln}")
    else:
        print(f"{G}[+] No critical vulnerabilities found in deep scan{NC}")
    
    print(f"\n{B}[*] Deep scan completed{NC}")

if __name__ == "__main__":
    main()

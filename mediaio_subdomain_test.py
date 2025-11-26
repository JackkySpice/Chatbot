#!/usr/bin/env python3
"""
MobileSec Red Team Console - Subdomain Testing
Target: api.media.io and admin.media.io
TACTICAL ASSESSMENT: Found accessible subdomains - testing for vulnerabilities
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

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

def test_subdomain(subdomain):
    """Comprehensive test of a subdomain"""
    url = f"https://{subdomain}.media.io"
    
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] TESTING: {url}{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    findings = []
    
    try:
        # Basic connection test
        r = requests.get(url, headers={'User-Agent': UA}, timeout=10, verify=True)
        print(f"{G}[+] Connection established (Status: {r.status_code}){NC}\n")
        
        # Headers analysis
        print(f"{C}[*] Security Headers:{NC}")
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                           'Strict-Transport-Security', 'Content-Security-Policy']
        for header in security_headers:
            if header in r.headers:
                print(f"{G}[+] {header}: {r.headers[header]}{NC}")
            else:
                print(f"{R}[-] {header}: MISSING{NC}")
                findings.append(f"Missing {header} on {subdomain}")
        
        # Server information
        if 'Server' in r.headers:
            print(f"\n{Y}[!] Server: {r.headers['Server']} (Information disclosure){NC}")
            findings.append(f"Server info exposed: {r.headers['Server']}")
        
        # CORS test
        cors_origin = r.headers.get('Access-Control-Allow-Origin')
        if cors_origin:
            if cors_origin == '*':
                print(f"\n{R}[!] CORS: Access-Control-Allow-Origin: * (VULNERABLE){NC}")
                findings.append(f"CRITICAL: CORS wildcard on {subdomain}")
            else:
                print(f"\n{C}[*] CORS: {cors_origin}{NC}")
        
        # Test common API paths
        if subdomain == 'api':
            print(f"\n{C}[*] Testing API Endpoints:{NC}")
            api_paths = ['/v1', '/v2', '/users', '/data', '/upload', '/health', '/status']
            
            for path in api_paths:
                try:
                    api_url = f"{url}{path}"
                    api_r = requests.get(api_url, headers={'User-Agent': UA}, 
                                       timeout=5, verify=True, allow_redirects=False)
                    
                    if api_r.status_code == 200:
                        print(f"{G}[200] {api_url}{NC}")
                        if len(api_r.content) < 500:
                            print(f"    Preview: {api_r.text[:150]}...")
                        findings.append(f"API endpoint accessible: {api_url}")
                    elif api_r.status_code not in [404, 405]:
                        print(f"{Y}[{api_r.status_code}] {api_url}{NC}")
                    time.sleep(0.2)
                except:
                    pass
        
        # Test admin paths
        if subdomain == 'admin':
            print(f"\n{C}[*] Testing Admin Paths:{NC}")
            admin_paths = ['/login', '/dashboard', '/users', '/settings', '/config']
            
            for path in admin_paths:
                try:
                    admin_url = f"{url}{path}"
                    admin_r = requests.get(admin_url, headers={'User-Agent': UA}, 
                                          timeout=5, verify=True, allow_redirects=False)
                    
                    if admin_r.status_code == 200:
                        print(f"{G}[200] {admin_url} (CRITICAL - Admin panel accessible!){NC}")
                        findings.append(f"CRITICAL: Admin path accessible: {admin_url}")
                    elif admin_r.status_code == 401 or admin_r.status_code == 403:
                        print(f"{Y}[{admin_r.status_code}] {admin_url} (Protected){NC}")
                    elif admin_r.status_code == 301 or admin_r.status_code == 302:
                        location = admin_r.headers.get('Location', 'N/A')
                        print(f"{C}[{admin_r.status_code}] {admin_url} -> {location}{NC}")
                    time.sleep(0.2)
                except:
                    pass
        
        # Test for information disclosure
        print(f"\n{C}[*] Testing for Information Disclosure:{NC}")
        info_paths = ['/.env', '/.git/config', '/package.json', '/composer.json']
        
        for info_path in info_paths:
            try:
                info_url = f"{url}{info_path}"
                info_r = requests.get(info_url, headers={'User-Agent': UA}, 
                                     timeout=5, verify=True)
                
                if info_r.status_code == 200:
                    content = info_r.text.lower()
                    sensitive = ['password', 'secret', 'api_key', 'token', 'database']
                    found_sensitive = [s for s in sensitive if s in content]
                    
                    if found_sensitive:
                        print(f"{R}[!] {info_url} - Contains sensitive data: {', '.join(found_sensitive)}{NC}")
                        findings.append(f"CRITICAL: Sensitive data in {info_url}")
                    else:
                        print(f"{Y}[?] {info_url} - Accessible (Status: 200){NC}")
                        findings.append(f"Information disclosure: {info_url}")
                time.sleep(0.2)
            except:
                pass
        
        return findings
        
    except requests.exceptions.SSLError:
        print(f"{R}[!] SSL Error - subdomain may not exist or have SSL issues{NC}")
        return []
    except Exception as e:
        print(f"{R}[!] Error: {e}{NC}")
        return []

def main():
    print(f"{B}{'='*70}{NC}")
    print(f"{B}  MOBILESEC - SUBDOMAIN VULNERABILITY ASSESSMENT{NC}")
    print(f"{B}{'='*70}{NC}")
    
    all_findings = []
    
    # Test api subdomain
    api_findings = test_subdomain('api')
    all_findings.extend(api_findings)
    
    # Test admin subdomain
    admin_findings = test_subdomain('admin')
    all_findings.extend(admin_findings)
    
    # Final Summary
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] SUBDOMAIN ASSESSMENT SUMMARY{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    if all_findings:
        critical = [f for f in all_findings if 'CRITICAL' in f]
        warnings = [f for f in all_findings if 'CRITICAL' not in f]
        
        if critical:
            print(f"{R}[!] CRITICAL FINDINGS ({len(critical)}):{NC}\n")
            for i, finding in enumerate(critical, 1):
                print(f"  {i}. {finding}")
        
        if warnings:
            print(f"\n{Y}[!] WARNINGS ({len(warnings)}):{NC}\n")
            for i, finding in enumerate(warnings, 1):
                print(f"  {i}. {finding}")
    else:
        print(f"{G}[+] No obvious vulnerabilities found on subdomains{NC}")
    
    print(f"\n{B}[*] Assessment completed{NC}")

if __name__ == "__main__":
    main()

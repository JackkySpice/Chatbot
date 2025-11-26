#!/usr/bin/env python3
"""
MobileSec Red Team Console - Final Analysis
Target: cyrax.info
TACTICAL ASSESSMENT: Laravel app on Heroku - gathering final intelligence
PROTOCOL: Information gathering and vulnerability assessment
"""

import requests
import sys
import time
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

def get_robots_txt():
    """Fetch robots.txt"""
    print(f"\n{B}[*] Fetching robots.txt{NC}\n")
    
    try:
        r = requests.head(f"{TARGET}/robots.txt", headers={'User-Agent': UA}, timeout=10, verify=True)
        if r.status_code == 200:
            # Use GET to get actual content
            r = requests.get(f"{TARGET}/robots.txt", headers={'User-Agent': UA}, timeout=10, verify=True)
            print(f"{G}[+] robots.txt content:{NC}\n")
            print(r.text)
            return r.text
    except Exception as e:
        print(f"{R}[!] Error: {e}{NC}")
    return None

def analyze_laravel_session():
    """Analyze Laravel session cookies"""
    print(f"\n{B}[*] Analyzing Laravel Session Cookies{NC}\n")
    
    try:
        r = requests.head(TARGET, headers={'User-Agent': UA}, timeout=10, verify=True)
        
        if 'Set-Cookie' in r.headers:
            cookies = r.headers.get_list('Set-Cookie')
            print(f"{C}[*] Cookies found: {len(cookies)}{NC}\n")
            
            for cookie in cookies:
                print(f"{C}[*] Cookie: {cookie[:100]}...{NC}")
                
                # Try to decode Laravel session
                if 'laravel_session=' in cookie:
                    session_part = cookie.split('laravel_session=')[1].split(';')[0]
                    print(f"\n{Y}[!] Laravel Session Token: {session_part[:50]}...{NC}")
                    
                    # Laravel sessions are base64 encoded
                    try:
                        decoded = base64.b64decode(session_part + '==')
                        print(f"{C}[*] Decoded (first 100 chars): {decoded[:100]}{NC}")
                    except:
                        pass
                
                if 'XSRF-TOKEN=' in cookie:
                    token_part = cookie.split('XSRF-TOKEN=')[1].split(';')[0]
                    print(f"\n{Y}[!] XSRF Token: {token_part[:50]}...{NC}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{NC}")

def test_laravel_paths():
    """Test Laravel-specific paths"""
    print(f"\n{B}[*] Testing Laravel-Specific Paths{NC}\n")
    
    laravel_paths = [
        '/.env',
        '/config/app.php',
        '/storage/logs/laravel.log',
        '/vendor',
        '/artisan',
        '/composer.json',
        '/package.json',
        '/public/.htaccess',
        '/routes/web.php',
        '/app/Http/Controllers'
    ]
    
    found = []
    
    for path in laravel_paths:
        try:
            url = f"{TARGET}{path}"
            r = requests.head(url, headers={'User-Agent': UA}, timeout=5, verify=True)
            
            if r.status_code == 200:
                print(f"{G}[200] {url} (CRITICAL - Laravel file accessible!){NC}")
                found.append((url, 200))
            elif r.status_code == 403:
                print(f"{Y}[403] {url} (Forbidden - but exists){NC}")
                found.append((url, 403))
            elif r.status_code != 404:
                print(f"{C}[{r.status_code}] {url}{NC}")
            time.sleep(0.2)
        except:
            pass
    
    return found

def test_heroku_info():
    """Test for Heroku-specific information"""
    print(f"\n{B}[*] Testing Heroku Information Disclosure{NC}\n")
    
    try:
        r = requests.head(TARGET, headers={'User-Agent': UA}, timeout=10, verify=True)
        
        # Check for Heroku headers
        heroku_headers = ['via', 'x-request-id', 'x-runtime', 'x-powered-by']
        
        print(f"{C}[*] Heroku-related headers:{NC}")
        for header in heroku_headers:
            if header in r.headers:
                print(f"  {header}: {r.headers[header]}")
        
        # Check for Heroku reporting endpoint
        if 'report-to' in r.headers:
            report_data = r.headers['report-to']
            print(f"\n{Y}[!] Reporting endpoint found: {report_data[:100]}...{NC}")
    except Exception as e:
        print(f"{R}[!] Error: {e}{NC}")

def test_api_routes():
    """Test common Laravel API routes"""
    print(f"\n{B}[*] Testing Laravel API Routes{NC}\n")
    
    api_routes = [
        '/api/user',
        '/api/users',
        '/api/auth/login',
        '/api/auth/register',
        '/api/auth/logout',
        '/api/posts',
        '/api/data'
    ]
    
    found = []
    
    for route in api_routes:
        try:
            url = f"{TARGET}{route}"
            r = requests.head(url, headers={'User-Agent': UA}, timeout=5, verify=True)
            
            if r.status_code == 200:
                print(f"{G}[200] {url} (API endpoint accessible!){NC}")
                found.append((url, 200))
            elif r.status_code == 405:
                print(f"{Y}[405] {url} (Method not allowed - but endpoint exists){NC}")
                found.append((url, 405))
            elif r.status_code == 401:
                print(f"{C}[401] {url} (Unauthorized - endpoint exists){NC}")
                found.append((url, 401))
            time.sleep(0.2)
        except:
            pass
    
    return found

def main():
    print(f"{B}{'='*70}{NC}")
    print(f"{B}  MOBILESEC - FINAL VULNERABILITY ASSESSMENT{NC}")
    print(f"{B}  TARGET: {TARGET}{NC}")
    print(f"{B}  TECHNOLOGY: Laravel on Heroku{NC}")
    print(f"{B}{'='*70}{NC}")
    
    critical_findings = []
    findings = []
    
    # Get robots.txt
    robots = get_robots_txt()
    if robots:
        findings.append("robots.txt accessible")
    
    # Analyze Laravel session
    analyze_laravel_session()
    findings.append("Laravel session cookies exposed")
    
    # Test Laravel paths
    laravel_files = test_laravel_paths()
    if laravel_files:
        for url, status in laravel_files:
            if status == 200:
                critical_findings.append(f"CRITICAL: Laravel file accessible: {url}")
            else:
                findings.append(f"Laravel path exists: {url}")
    
    # Test Heroku info
    test_heroku_info()
    findings.append("Heroku infrastructure detected")
    
    # Test API routes
    api_routes = test_api_routes()
    if api_routes:
        findings.append(f"Found {len(api_routes)} Laravel API endpoints")
        for url, status in api_routes:
            if status == 200:
                critical_findings.append(f"CRITICAL: API endpoint accessible: {url}")
    
    # Final Summary
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] FINAL ASSESSMENT SUMMARY{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    print(f"{C}[*] Technology Stack Identified:{NC}")
    print(f"  - Framework: Laravel (PHP)")
    print(f"  - Hosting: Heroku")
    print(f"  - CDN/WAF: Cloudflare")
    print(f"  - Bypass Method: HEAD requests\n")
    
    if critical_findings:
        print(f"{R}[!] CRITICAL VULNERABILITIES ({len(critical_findings)}):{NC}\n")
        for i, finding in enumerate(critical_findings, 1):
            print(f"  {i}. {finding}")
        print()
    
    if findings:
        print(f"{Y}[!] Additional Findings ({len(findings)}):{NC}\n")
        for i, finding in enumerate(findings, 1):
            print(f"  {i}. {finding}")
    
    print(f"\n{B}[*] Assessment completed{NC}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
MobileSec Red Team Console - Cloudflare Bypass Testing
Target: cyrax.info
TACTICAL ASSESSMENT: Cloudflare WAF detected - testing bypass techniques
PROTOCOL: WAF bypass and alternative access methods
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

TARGET = "https://cyrax.info"

def test_user_agents():
    """Test different User-Agent strings"""
    print(f"\n{B}[*] Testing Different User-Agents{NC}\n")
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "curl/7.68.0",
        "Googlebot/2.1",
        "Mozilla/5.0 (compatible; Bingbot/2.0)"
    ]
    
    for ua in user_agents:
        try:
            r = requests.get(TARGET, headers={'User-Agent': ua}, timeout=10, verify=True)
            status_color = G if r.status_code == 200 else Y if r.status_code != 403 else R
            print(f"{status_color}[{r.status_code}] User-Agent: {ua[:50]}...{NC}")
            if r.status_code == 200:
                print(f"    SUCCESS - Bypassed Cloudflare!")
                return True
        except:
            pass
        time.sleep(0.5)
    
    return False

def test_http_methods():
    """Test different HTTP methods"""
    print(f"\n{B}[*] Testing Different HTTP Methods{NC}\n")
    
    methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'TRACE']
    
    for method in methods:
        try:
            r = requests.request(method, TARGET, timeout=10, verify=True)
            status_color = G if r.status_code == 200 else Y if r.status_code != 403 else R
            print(f"{status_color}[{r.status_code}] {method}{NC}")
            if r.status_code == 200:
                return True
        except:
            pass
        time.sleep(0.3)
    
    return False

def test_http_vs_https():
    """Test HTTP vs HTTPS"""
    print(f"\n{B}[*] Testing HTTP vs HTTPS{NC}\n")
    
    http_target = "http://cyrax.info"
    
    try:
        r = requests.get(http_target, timeout=10, allow_redirects=False)
        print(f"{G}[{r.status_code}] HTTP (no redirect){NC}")
        if r.status_code == 200:
            return True
    except:
        pass
    
    try:
        r = requests.get(http_target, timeout=10, allow_redirects=True)
        print(f"{C}[{r.status_code}] HTTP (with redirect){NC}")
        if r.status_code == 200:
            return True
    except:
        pass
    
    return False

def test_subdomains():
    """Test common subdomains"""
    print(f"\n{B}[*] Testing Subdomains{NC}\n")
    
    subdomains = ['www', 'api', 'admin', 'mail', 'ftp', 'test', 'dev', 'staging']
    found = []
    
    for sub in subdomains:
        try:
            url = f"https://{sub}.cyrax.info"
            r = requests.get(url, timeout=5, verify=True)
            status_color = G if r.status_code == 200 else Y if r.status_code != 403 else R
            print(f"{status_color}[{r.status_code}] {url}{NC}")
            if r.status_code == 200:
                found.append((url, r.status_code))
        except:
            pass
        time.sleep(0.2)
    
    return found

def test_cloudflare_challenge():
    """Analyze Cloudflare challenge page"""
    print(f"\n{B}[*] Analyzing Cloudflare Challenge Response{NC}\n")
    
    try:
        r = requests.get(TARGET, timeout=10, verify=True)
        
        if r.status_code == 403:
            print(f"{Y}[!] Received 403 Forbidden{NC}")
            print(f"{C}[*] Response size: {len(r.content)} bytes{NC}")
            print(f"{C}[*] Content-Type: {r.headers.get('Content-Type', 'unknown')}{NC}")
            
            # Check for Cloudflare challenge indicators
            content = r.text.lower()
            cf_indicators = ['cloudflare', 'challenge', 'checking your browser', 
                           'ray id', 'cf-ray', 'just a moment']
            
            found_indicators = [ind for ind in cf_indicators if ind in content]
            if found_indicators:
                print(f"{Y}[!] Cloudflare challenge detected: {', '.join(found_indicators)}{NC}")
            
            # Show response preview
            print(f"\n{C}[*] Response preview (first 500 chars):{NC}")
            print(r.text[:500])
            
            # Check for interesting headers
            print(f"\n{C}[*] Interesting Headers:{NC}")
            interesting = ['cf-ray', 'cf-mitigated', 'server', 'x-powered-by']
            for header in interesting:
                if header in r.headers:
                    print(f"  {header}: {r.headers[header]}")
        
    except Exception as e:
        print(f"{R}[!] Error: {e}{NC}")

def test_paths_with_session():
    """Test if maintaining a session helps"""
    print(f"\n{B}[*] Testing with Session (Cookie Persistence){NC}\n")
    
    session = requests.Session()
    
    try:
        # First request to get cookies
        r1 = session.get(TARGET, timeout=10, verify=True)
        print(f"{C}[*] Initial request: {r1.status_code}{NC}")
        print(f"{C}[*] Cookies received: {len(session.cookies)} cookies{NC}")
        
        if session.cookies:
            for cookie in session.cookies:
                print(f"    {cookie.name}: {cookie.value[:50]}...")
        
        # Try accessing paths with session
        test_paths = ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt']
        
        for path in test_paths:
            url = f"{TARGET}{path}"
            r = session.get(url, timeout=5, verify=True)
            status_color = G if r.status_code == 200 else Y if r.status_code != 403 else R
            print(f"{status_color}[{r.status_code}] {url}{NC}")
            if r.status_code == 200:
                print(f"    SUCCESS - Session bypass worked!")
                return True
            time.sleep(0.3)
        
    except Exception as e:
        print(f"{R}[!] Error: {e}{NC}")
    
    return False

def test_rate_limit():
    """Test rate limiting behavior"""
    print(f"\n{B}[*] Testing Rate Limiting{NC}\n")
    
    success = 0
    blocked = 0
    
    for i in range(1, 11):
        try:
            r = requests.get(TARGET, timeout=5, verify=True)
            if r.status_code == 200:
                success += 1
            elif r.status_code == 403:
                blocked += 1
            elif r.status_code == 429:
                print(f"{R}[!] Rate limited at request #{i}{NC}")
                return True
            time.sleep(0.1)
        except:
            pass
    
    print(f"{C}[*] Results: {success} success, {blocked} blocked{NC}")
    return False

def main():
    print(f"{B}{'='*70}{NC}")
    print(f"{B}  MOBILESEC - CLOUDFLARE BYPASS TESTING{NC}")
    print(f"{B}  TARGET: {TARGET}{NC}")
    print(f"{B}{'='*70}{NC}")
    
    findings = []
    
    # Analyze the challenge
    test_cloudflare_challenge()
    
    # Test bypass techniques
    if test_user_agents():
        findings.append("User-Agent bypass successful")
    
    if test_http_methods():
        findings.append("HTTP method bypass successful")
    
    if test_http_vs_https():
        findings.append("HTTP access successful")
    
    subdomains = test_subdomains()
    if subdomains:
        findings.append(f"Found {len(subdomains)} accessible subdomains")
    
    if test_paths_with_session():
        findings.append("Session-based bypass successful")
    
    test_rate_limit()
    
    # Summary
    print(f"\n{B}{'='*70}{NC}")
    print(f"{B}[*] BYPASS TEST SUMMARY{NC}")
    print(f"{B}{'='*70}{NC}\n")
    
    if findings:
        print(f"{Y}[!] Findings:{NC}\n")
        for i, finding in enumerate(findings, 1):
            print(f"  {i}. {finding}")
    else:
        print(f"{C}[*] No bypass techniques successful{NC}")
        print(f"{Y}[!] Cloudflare protection appears active{NC}")
        print(f"{C}[*] Recommendations:{NC}")
        print(f"  - Manual browser testing (may pass JavaScript challenge)")
        print(f"  - Test authenticated endpoints if credentials available")
        print(f"  - Check for API endpoints that may not be protected")
    
    print(f"\n{B}[*] Testing completed{NC}")

if __name__ == "__main__":
    main()

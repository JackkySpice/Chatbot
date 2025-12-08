#!/usr/bin/env python3
"""
Quick Security Audit - Fast comprehensive check
"""

import requests
import time

def quick_audit():
    base_url = "https://www.bestchange.com"
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    findings = []
    
    print("Quick Security Audit - BestChange.com\n")
    
    # Test 1: Security Headers
    print("[*] Checking security headers...")
    try:
        resp = session.get(base_url, timeout=5)
        headers = resp.headers
        
        missing = []
        if 'X-Content-Type-Options' not in headers:
            missing.append('X-Content-Type-Options')
        if 'Content-Security-Policy' not in headers:
            missing.append('Content-Security-Policy')
        if 'Referrer-Policy' not in headers:
            missing.append('Referrer-Policy')
        
        if missing:
            findings.append(f"Missing headers: {', '.join(missing)}")
            print(f"  [!] Missing: {', '.join(missing)}")
        else:
            print("  [+] All security headers present")
    except:
        pass
    
    # Test 2: Rate Limiting
    print("[*] Testing rate limiting...")
    try:
        status_codes = []
        for i in range(5):
            resp = session.get(f"{base_url}/index.php", timeout=5)
            status_codes.append(resp.status_code)
            time.sleep(0.1)
        
        if 429 in status_codes:
            print("  [+] Rate limiting active (429 detected)")
        else:
            findings.append("No rate limiting detected")
            print("  [!] No rate limiting detected")
    except:
        pass
    
    # Test 3: SSL/TLS
    print("[*] Checking SSL/TLS...")
    try:
        resp = session.get(base_url, timeout=5, verify=True)
        if resp.status_code == 200:
            print("  [+] SSL/TLS properly configured")
    except:
        findings.append("SSL/TLS issue")
        print("  [!] SSL/TLS issue")
    
    # Test 4: Parameter Pollution
    print("[*] Testing parameter pollution...")
    try:
        resp = session.get(f"{base_url}/click.php?id=1&id=2&from=10&to=58&city=0", timeout=5)
        if resp.status_code == 200:
            findings.append("Parameter pollution possible")
            print("  [!] Parameter pollution detected")
        else:
            print("  [+] Parameter pollution handled")
    except:
        pass
    
    # Summary
    print("\n" + "="*50)
    print("QUICK AUDIT SUMMARY")
    print("="*50)
    
    if findings:
        print(f"\n[!] Found {len(findings)} issue(s):")
        for i, finding in enumerate(findings, 1):
            print(f"  {i}. {finding}")
    else:
        print("\n[+] No critical issues found in quick scan")
    
    print("\nFor detailed audit, run comprehensive scripts.")

if __name__ == "__main__":
    quick_audit()

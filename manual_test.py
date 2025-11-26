#!/usr/bin/env python3
"""
Manual Test - MobileSec Red Team Console
Testing the framework concept with a safe target
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

def test_header_analysis():
    """Test header analysis module"""
    print(f"{B}[*] MOBILESEC RED TEAM CONSOLE - MANUAL TEST{NC}")
    print(f"{B}[*] TACTICAL ASSESSMENT: Testing header analysis module{NC}")
    print(f"{B}[*] PROTOCOL: HTTP Header Security Analysis{NC}\n")
    
    # Using httpbin.org - safe public test service
    TARGET = "https://httpbin.org/headers"
    UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    
    print(f"{B}[*] ENGAGING TARGET: {TARGET}{NC}")
    print(f"{B}[*] PROTOCOL: ACTIVE LIVE FIRE{NC}\n")
    
    try:
        # REAL NETWORK CALL - NO MOCKING
        r = requests.get(TARGET, headers={'User-Agent': UA}, timeout=10)
        print(f"{G}[+] CONNECTION ESTABLISHED (Status: {r.status_code}){NC}\n")
        
        # Analyze security headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP'
        }
        
        print(f"{C}[*] Security Headers Analysis:{NC}")
        for header, desc in security_headers.items():
            if header in r.headers:
                print(f"{G}[+] {header}: {r.headers[header]}{NC}")
            else:
                print(f"{R}[-] {header}: MISSING - {desc}{NC}")
        
        print(f"\n{C}[*] All Response Headers:{NC}")
        for header, value in sorted(r.headers.items()):
            print(f"  {header}: {value}")
        
        print(f"\n{G}[+] Test completed successfully{NC}")
        return True
        
    except requests.exceptions.ConnectionError:
        print(f"{R}[!] EXECUTION FAILED: Connection error{NC}")
        return False
    except Exception as e:
        print(f"{R}[!] EXECUTION FAILED: {e}{NC}")
        return False

def test_rate_limit():
    """Test rate limit detection"""
    print(f"\n{B}[*] Testing Rate Limit Detection{NC}")
    print(f"{B}[*] PROTOCOL: Rate Limit Testing (5 requests){NC}\n")
    
    TARGET = "https://httpbin.org/get"
    UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    
    success = 0
    rate_limited = 0
    
    for i in range(1, 6):
        try:
            r = requests.get(TARGET, headers={'User-Agent': UA}, timeout=5)
            if r.status_code == 200:
                success += 1
                print(f"{G}[+] Request {i}/5: OK (Status: {r.status_code}){NC}")
            elif r.status_code == 429:
                rate_limited += 1
                print(f"{R}[!] Rate limited at request #{i}{NC}")
            time.sleep(0.2)
        except Exception as e:
            print(f"{R}[!] Request {i} failed: {e}{NC}")
    
    print(f"\n{G}[+] Successful: {success}/5{NC}")
    if rate_limited > 0:
        print(f"{Y}[!] Rate limiting detected{NC}")
    else:
        print(f"{C}[*] No rate limiting detected (expected for test service){NC}")
    
    return True

if __name__ == "__main__":
    print(f"{B}{'='*60}{NC}")
    print(f"{B}  MOBILESEC RED TEAM CONSOLE - MANUAL TEST{NC}")
    print(f"{B}{'='*60}{NC}\n")
    
    # Test 1: Header Analysis
    result1 = test_header_analysis()
    
    # Test 2: Rate Limit
    result2 = test_rate_limit()
    
    # Summary
    print(f"\n{B}{'='*60}{NC}")
    print(f"{B}[*] TEST SUMMARY{NC}")
    print(f"{B}{'='*60}{NC}")
    print(f"Header Analysis: {'PASS' if result1 else 'FAIL'}")
    print(f"Rate Limit Test: {'PASS' if result2 else 'FAIL'}")
    print(f"\n{G}[+] Manual test demonstration completed{NC}")

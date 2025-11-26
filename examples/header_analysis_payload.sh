#!/bin/bash
# One-Shot Termux Payload: HTTP Header Security Analysis
# Usage: ./header_analysis_payload.sh

# 1. Setup Environment
echo "[*] Initializing MobileSec..."
pkg update -y > /dev/null 2>&1 && pkg install python -y > /dev/null 2>&1
pip install requests --disable-pip-version-check > /dev/null 2>&1

# 2. Create Payload (Heredoc)
cat << 'EOF' > exploit.py
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

# TACTICAL ASSESSMENT: HTTP Header Security Analysis
# PROTOCOL: Analyze security headers and information disclosure

TARGET = input(f"{B}[?] Enter target URL: {NC}").strip()
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

def run_audit():
    print(f"{B}[*] ENGAGING TARGET: {TARGET}{NC}")
    print(f"{B}[*] PROTOCOL: HTTP Header Security Analysis{NC}\n")
    
    try:
        # REAL NETWORK CALL - NO MOCKING
        r = requests.get(TARGET, headers={'User-Agent': UA}, timeout=10, verify=False)
        print(f"{G}[+] CONNECTION ESTABLISHED (Status: {r.status_code}){NC}\n")
        
        # Security Headers Check
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'X-XSS-Protection': 'XSS protection',
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'Referrer-Policy': 'Referrer policy',
            'Permissions-Policy': 'Permissions policy'
        }
        
        print(f"{C}[*] Security Headers Analysis:{NC}")
        vulnerabilities = []
        
        for header, description in security_headers.items():
            if header in r.headers:
                print(f"{G}[+] {header}: {r.headers[header]}{NC}")
            else:
                print(f"{R}[-] {header}: MISSING - {description}{NC}")
                vulnerabilities.append(f"Missing {header}")
        
        # Information Disclosure Check
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        print(f"\n{C}[*] Information Disclosure Check:{NC}")
        for header in info_headers:
            if header in r.headers:
                print(f"{Y}[!] {header}: {r.headers[header]} (Information disclosure){NC}")
                vulnerabilities.append(f"{header} exposed: {r.headers[header]}")
        
        # Summary
        print(f"\n{B}[*] SUMMARY:{NC}")
        if vulnerabilities:
            print(f"{R}[!] Found {len(vulnerabilities)} potential issues:{NC}")
            for vuln in vulnerabilities:
                print(f"  - {vuln}")
        else:
            print(f"{G}[+] No obvious security header issues detected{NC}")
        
        # All Headers
        print(f"\n{C}[*] All Response Headers:{NC}")
        for header, value in sorted(r.headers.items()):
            print(f"  {header}: {value}")
        
    except requests.exceptions.Timeout:
        print(f"{R}[!] EXECUTION FAILED: Connection timeout{NC}")
    except requests.exceptions.ConnectionError:
        print(f"{R}[!] EXECUTION FAILED: Connection error - Check target URL{NC}")
    except Exception as e:
        print(f"{R}[!] EXECUTION FAILED: {e}{NC}")

if __name__ == "__main__":
    run_audit()
EOF

# 3. Execute
python exploit.py

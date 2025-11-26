#!/bin/bash
# MobileSec Red Team Console - Authorized Security Testing Framework
# ⚠️  WARNING: Use only on systems you own or have explicit written authorization to test.

cat << 'BANNER'
╔══════════════════════════════════════════════════════════════╗
║         MOBILESEC RED TEAM CONSOLE v1.0                      ║
║         Authorized Security Audit Framework                  ║
╚══════════════════════════════════════════════════════════════╝
BANNER

echo -e "\x1b[1;33m[*] Initializing MobileSec Environment...\x1b[0m"

# Setup Environment
pkg update -y > /dev/null 2>&1
pkg install python -y > /dev/null 2>&1
pip install requests --disable-pip-version-check > /dev/null 2>&1

# Authorization Check
echo -e "\x1b[1;31m[!] AUTHORIZATION REQUIRED\x1b[0m"
echo -e "\x1b[1;33m[?] Do you have written authorization to test the target? (yes/no)\x1b[0m"
read -r auth_confirm

if [ "$auth_confirm" != "yes" ]; then
    echo -e "\x1b[1;31m[!] ABORT: Authorization not confirmed. Exiting.\x1b[0m"
    exit 1
fi

echo -e "\x1b[1;33m[?] Enter target URL (e.g., https://example.com):\x1b[0m"
read -r TARGET

echo -e "\x1b[1;33m[?] Select test module:\x1b[0m"
echo "  1) Port Scanner"
echo "  2) HTTP Header Analysis"
echo "  3) Directory/File Discovery"
echo "  4) SQL Injection Tester"
echo "  5) XSS Tester"
echo "  6) API Endpoint Discovery"
echo "  7) Rate Limit Tester"
read -r module_choice

# Generate payload based on selection
case $module_choice in
    1) MODULE="port_scanner" ;;
    2) MODULE="header_analysis" ;;
    3) MODULE="directory_discovery" ;;
    4) MODULE="sqli_tester" ;;
    5) MODULE="xss_tester" ;;
    6) MODULE="api_discovery" ;;
    7) MODULE="rate_limit" ;;
    *) echo -e "\x1b[1;31m[!] Invalid selection\x1b[0m"; exit 1 ;;
esac

cat << EOF > exploit.py
import requests
import sys
import time
import socket
from urllib.parse import urlparse

# ANSI Colors
R = "\x1b[1;31m"
G = "\x1b[1;32m"
Y = "\x1b[1;33m"
B = "\x1b[1;34m"
C = "\x1b[1;36m"
NC = "\x1b[0m"

TARGET = "${TARGET}"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def port_scanner():
    """Port scanning module"""
    print(f"{B}[*] PROTOCOL: Port Scanning{NC}")
    parsed = urlparse(TARGET)
    host = parsed.hostname or parsed.path.split('/')[0]
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"{G}[+] Port {port} is OPEN{NC}")
            sock.close()
        except Exception as e:
            pass
        time.sleep(0.1)

def header_analysis():
    """HTTP header security analysis"""
    print(f"{B}[*] PROTOCOL: HTTP Header Security Analysis{NC}")
    try:
        r = requests.get(TARGET, headers={'User-Agent': UA}, timeout=10, verify=False)
        print(f"{G}[+] Connection established (Status: {r.status_code}){NC}\n")
        
        security_headers = {
            'X-Frame-Options': 'Missing - Clickjacking protection',
            'X-Content-Type-Options': 'Missing - MIME sniffing protection',
            'X-XSS-Protection': 'Missing - XSS protection',
            'Strict-Transport-Security': 'Missing - HSTS',
            'Content-Security-Policy': 'Missing - CSP',
            'Server': 'Information disclosure',
            'X-Powered-By': 'Information disclosure'
        }
        
        print(f"{C}[*] Security Headers Analysis:{NC}")
        for header, issue in security_headers.items():
            if header in r.headers:
                if header in ['Server', 'X-Powered-By']:
                    print(f"{Y}[!] {header}: {r.headers[header]} ({issue}){NC}")
                else:
                    print(f"{G}[+] {header}: {r.headers[header]}{NC}")
            else:
                print(f"{R}[-] {header}: {issue}{NC}")
        
        print(f"\n{C}[*] All Headers:{NC}")
        for header, value in r.headers.items():
            print(f"  {header}: {value}")
            
    except Exception as e:
        print(f"{R}[!] EXECUTION FAILED: {e}{NC}")

def directory_discovery():
    """Directory and file discovery"""
    print(f"{B}[*] PROTOCOL: Directory/File Discovery{NC}")
    
    wordlist = [
        'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
        'backup', 'config', '.env', 'api', 'test', 'dev', 'staging',
        'robots.txt', 'sitemap.xml', '.git', '.svn', 'README.md'
    ]
    
    found = []
    for path in wordlist:
        try:
            url = f"{TARGET.rstrip('/')}/{path}"
            r = requests.get(url, headers={'User-Agent': UA}, timeout=5, verify=False, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403]:
                status_color = G if r.status_code == 200 else Y
                print(f"{status_color}[{r.status_code}] {url}{NC}")
                found.append((url, r.status_code))
            time.sleep(0.2)
        except:
            pass
    
    if not found:
        print(f"{R}[-] No accessible paths found{NC}")

def sqli_tester():
    """SQL Injection vulnerability tester"""
    print(f"{B}[*] PROTOCOL: SQL Injection Testing{NC}")
    print(f"{Y}[!] This is a basic test. Manual verification required.{NC}\n")
    
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--"
    ]
    
    # Test common parameters
    params = ['id', 'user', 'username', 'email', 'search', 'q']
    
    for param in params:
        for payload in payloads:
            try:
                test_url = f"{TARGET}?{param}={payload}"
                r = requests.get(test_url, headers={'User-Agent': UA}, timeout=5, verify=False)
                
                # Basic error detection
                error_indicators = ['sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlite', 'database error']
                if any(indicator in r.text.lower() for indicator in error_indicators):
                    print(f"{R}[!] Potential SQLi in parameter '{param}' with payload: {payload}{NC}")
                    print(f"    URL: {test_url}")
                time.sleep(0.3)
            except:
                pass

def xss_tester():
    """XSS vulnerability tester"""
    print(f"{B}[*] PROTOCOL: XSS Testing{NC}")
    print(f"{Y}[!] This is a basic test. Manual verification required.{NC}\n")
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)"
    ]
    
    params = ['q', 'search', 'name', 'comment', 'message', 'input']
    
    for param in params:
        for payload in payloads:
            try:
                test_url = f"{TARGET}?{param}={payload}"
                r = requests.get(test_url, headers={'User-Agent': UA}, timeout=5, verify=False)
                
                if payload in r.text:
                    print(f"{Y}[?] Potential XSS in parameter '{param}' - Payload reflected in response{NC}")
                    print(f"    URL: {test_url}")
                time.sleep(0.3)
            except:
                pass

def api_discovery():
    """API endpoint discovery"""
    print(f"{B}[*] PROTOCOL: API Endpoint Discovery{NC}")
    
    endpoints = [
        '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
        '/api/users', '/api/data', '/api/admin', '/swagger.json',
        '/api-docs', '/openapi.json', '/.well-known/openapi'
    ]
    
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    
    for endpoint in endpoints:
        try:
            url = f"{TARGET.rstrip('/')}{endpoint}"
            for method in methods:
                r = requests.request(method, url, headers={'User-Agent': UA}, timeout=5, verify=False)
                if r.status_code not in [404, 405]:
                    print(f"{G}[{r.status_code}] {method} {url}{NC}")
                    if r.status_code == 200 and len(r.text) < 500:
                        print(f"    Response preview: {r.text[:100]}...")
                    break
            time.sleep(0.2)
        except:
            pass

def rate_limit():
    """Rate limiting and DoS resistance testing"""
    print(f"{B}[*] PROTOCOL: Rate Limit Testing{NC}")
    print(f"{Y}[!] Testing rate limits (sending 50 requests)...{NC}\n")
    
    success_count = 0
    rate_limited = 0
    
    for i in range(50):
        try:
            r = requests.get(TARGET, headers={'User-Agent': UA}, timeout=5, verify=False)
            if r.status_code == 200:
                success_count += 1
            elif r.status_code in [429, 503]:
                rate_limited += 1
                print(f"{R}[!] Rate limited at request #{i+1} (Status: {r.status_code}){NC}")
                break
            time.sleep(0.1)
        except Exception as e:
            print(f"{R}[!] Request #{i+1} failed: {e}{NC}")
    
    print(f"\n{G}[+] Successful requests: {success_count}/50{NC}")
    if rate_limited > 0:
        print(f"{Y}[!] Rate limiting detected after {50 - rate_limited} requests{NC}")
    else:
        print(f"{R}[!] No rate limiting detected{NC}")

def run_audit():
    print(f"{B}[*] ENGAGING TARGET: {TARGET}{NC}")
    print(f"{B}[*] PROTOCOL: ACTIVE LIVE FIRE{NC}\n")
    
    module = "${MODULE}"
    
    if module == "port_scanner":
        port_scanner()
    elif module == "header_analysis":
        header_analysis()
    elif module == "directory_discovery":
        directory_discovery()
    elif module == "sqli_tester":
        sqli_tester()
    elif module == "xss_tester":
        xss_tester()
    elif module == "api_discovery":
        api_discovery()
    elif module == "rate_limit":
        rate_limit()
    else:
        print(f"{R}[!] Unknown module{NC}")
    
    print(f"\n{B}[*] Audit completed{NC}")

if __name__ == "__main__":
    run_audit()
EOF

echo -e "\x1b[1;32m[+] Payload generated: exploit.py\x1b[0m"
echo -e "\x1b[1;33m[?] Execute now? (yes/no)\x1b[0m"
read -r execute

if [ "$execute" == "yes" ]; then
    python exploit.py
else
    echo -e "\x1b[1;33m[*] Payload saved. Run: python exploit.py\x1b[0m"
fi

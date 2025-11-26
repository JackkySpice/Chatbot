#!/bin/bash
# One-Shot Termux Payload: API Endpoint Discovery
# Usage: ./api_discovery_payload.sh

# 1. Setup Environment
echo "[*] Initializing MobileSec..."
pkg update -y > /dev/null 2>&1 && pkg install python -y > /dev/null 2>&1
pip install requests --disable-pip-version-check > /dev/null 2>&1

# 2. Create Payload (Heredoc)
cat << 'EOF' > exploit.py
import requests
import sys
import time
import json

# ANSI Colors
R = "\x1b[1;31m"
G = "\x1b[1;32m"
Y = "\x1b[1;33m"
B = "\x1b[1;34m"
C = "\x1b[1;36m"
NC = "\x1b[0m"

# TACTICAL ASSESSMENT: API Endpoint Discovery
# PROTOCOL: Discover API endpoints and test HTTP methods

TARGET = input(f"{B}[?] Enter target URL: {NC}").strip()
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# Common API endpoints
ENDPOINTS = [
    '/api', '/api/v1', '/api/v2', '/api/v3',
    '/rest', '/rest/api', '/graphql', '/graphql/v1',
    '/v1', '/v2', '/v3',
    '/api/users', '/api/data', '/api/admin',
    '/swagger.json', '/swagger.yaml',
    '/api-docs', '/api/docs', '/docs',
    '/openapi.json', '/openapi.yaml',
    '/.well-known/openapi', '/.well-known/api',
    '/api/health', '/api/status', '/health', '/status'
]

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

def test_endpoint(url, method='GET'):
    """Test a single endpoint with a specific HTTP method"""
    try:
        r = requests.request(method, url, headers={'User-Agent': UA}, 
                           timeout=5, verify=False, allow_redirects=False)
        return r
    except:
        return None

def analyze_response(response, url, method):
    """Analyze response for interesting information"""
    if not response:
        return None
    
    info = {
        'url': url,
        'method': method,
        'status': response.status_code,
        'headers': dict(response.headers),
        'size': len(response.content),
        'content_type': response.headers.get('Content-Type', 'unknown')
    }
    
    # Try to parse JSON
    if 'application/json' in info['content_type']:
        try:
            info['json'] = response.json()
        except:
            info['json'] = None
    
    return info

def run_audit():
    print(f"{B}[*] ENGAGING TARGET: {TARGET}{NC}")
    print(f"{B}[*] PROTOCOL: API Endpoint Discovery{NC}\n")
    
    discovered = []
    
    try:
        # Test each endpoint
        for endpoint in ENDPOINTS:
            url = f"{TARGET.rstrip('/')}{endpoint}"
            
            # Try OPTIONS first (often reveals allowed methods)
            opt_response = test_endpoint(url, 'OPTIONS')
            if opt_response and opt_response.status_code not in [404, 405]:
                allowed_methods = opt_response.headers.get('Allow', '')
                print(f"{C}[*] Testing: {url}{NC}")
                if allowed_methods:
                    print(f"  {Y}Allowed methods: {allowed_methods}{NC}")
            
            # Test each HTTP method
            for method in HTTP_METHODS:
                response = test_endpoint(url, method)
                
                if response and response.status_code not in [404, 405, 403]:
                    info = analyze_response(response, url, method)
                    if info:
                        discovered.append(info)
                        
                        # Print discovery
                        status_color = G if response.status_code == 200 else Y
                        print(f"{status_color}[{response.status_code}] {method} {url}{NC}")
                        print(f"  Content-Type: {info['content_type']}")
                        print(f"  Size: {info['size']} bytes")
                        
                        # Show JSON preview if available
                        if info.get('json'):
                            json_preview = json.dumps(info['json'], indent=2)[:200]
                            print(f"  JSON Preview: {json_preview}...")
                        
                        # Show interesting headers
                        interesting_headers = ['X-API-Version', 'X-Rate-Limit', 'X-Request-ID']
                        for header in interesting_headers:
                            if header in info['headers']:
                                print(f"  {header}: {info['headers'][header]}")
                        
                        print()
                
                time.sleep(0.1)  # Rate limiting
        
        # Summary
        print(f"\n{B}[*] DISCOVERY SUMMARY:{NC}")
        if discovered:
            print(f"{G}[+] Discovered {len(discovered)} accessible API endpoints:{NC}\n")
            for info in discovered:
                print(f"  {info['method']} {info['url']} ({info['status']})")
        else:
            print(f"{R}[-] No API endpoints discovered with common paths{NC}")
            print(f"{Y}[!] Consider:{NC}")
            print(f"  - Manual enumeration of application-specific endpoints")
            print(f"  - Review JavaScript files for API calls")
            print(f"  - Check for API documentation endpoints")
            print(f"  - Test authenticated endpoints if credentials available")
        
    except Exception as e:
        print(f"{R}[!] EXECUTION FAILED: {e}{NC}")

if __name__ == "__main__":
    run_audit()
EOF

# 3. Execute
python exploit.py

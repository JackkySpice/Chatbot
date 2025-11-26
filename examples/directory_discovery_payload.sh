#!/bin/bash
# One-Shot Termux Payload: Directory/File Discovery
# Usage: ./directory_discovery_payload.sh

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

# TACTICAL ASSESSMENT: Directory and File Discovery
# PROTOCOL: Test common paths for accessible resources

TARGET = input(f"{B}[?] Enter target URL: {NC}").strip()
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# Common wordlist for discovery
WORDLIST = [
    # Admin panels
    'admin', 'administrator', 'admin.php', 'admin.html', 'admin/',
    'wp-admin', 'wp-login.php', 'phpmyadmin', 'pma',
    
    # Authentication
    'login', 'login.php', 'signin', 'auth', 'authentication',
    
    # Configuration files
    'config.php', 'config.ini', 'config.json', '.env', '.env.local',
    'settings.php', 'configuration.php',
    
    # Backup files
    'backup', 'backup.sql', 'backup.tar.gz', 'backup.zip',
    'db_backup.sql', 'database.sql',
    
    # Version control
    '.git', '.git/config', '.svn', '.hg',
    
    # Documentation
    'README.md', 'readme.txt', 'CHANGELOG', 'LICENSE',
    
    # API and endpoints
    'api', 'api/v1', 'api/v2', 'rest', 'graphql',
    'swagger.json', 'api-docs', 'openapi.json',
    
    # Common files
    'robots.txt', 'sitemap.xml', '.well-known/security.txt',
    'crossdomain.xml', 'clientaccesspolicy.xml',
    
    # Development
    'test', 'dev', 'staging', 'debug', 'phpinfo.php',
    
    # Other
    'index.php.bak', 'index.html.bak', '.htaccess', 'web.config'
]

def run_audit():
    print(f"{B}[*] ENGAGING TARGET: {TARGET}{NC}")
    print(f"{B}[*] PROTOCOL: Directory/File Discovery{NC}")
    print(f"{B}[*] Wordlist size: {len(WORDLIST)} entries{NC}\n")
    
    found = []
    tested = 0
    
    try:
        for path in WORDLIST:
            tested += 1
            url = f"{TARGET.rstrip('/')}/{path}"
            
            try:
                # REAL NETWORK CALL - NO MOCKING
                r = requests.get(url, headers={'User-Agent': UA}, timeout=5, 
                               verify=False, allow_redirects=False)
                
                # Check for interesting status codes
                if r.status_code == 200:
                    size = len(r.content)
                    print(f"{G}[200] {url} (Size: {size} bytes){NC}")
                    found.append((url, 200, size))
                elif r.status_code == 301 or r.status_code == 302:
                    location = r.headers.get('Location', 'N/A')
                    print(f"{Y}[{r.status_code}] {url} -> {location}{NC}")
                    found.append((url, r.status_code, location))
                elif r.status_code == 403:
                    print(f"{Y}[403] {url} (Forbidden - but exists){NC}")
                    found.append((url, 403, 'Forbidden'))
                elif r.status_code == 401:
                    print(f"{C}[401] {url} (Unauthorized - requires auth){NC}")
                    found.append((url, 401, 'Unauthorized'))
                
                # Progress indicator
                if tested % 10 == 0:
                    print(f"{C}[*] Progress: {tested}/{len(WORDLIST)} tested...{NC}", end='\r')
                
                time.sleep(0.2)  # Rate limiting
                
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.ConnectionError:
                print(f"{R}[!] Connection error - stopping{NC}")
                break
            except Exception as e:
                pass
        
        print(f"\n\n{B}[*] DISCOVERY SUMMARY:{NC}")
        if found:
            print(f"{G}[+] Found {len(found)} accessible resources:{NC}\n")
            for url, status, info in found:
                if status == 200:
                    print(f"  {G}[{status}]{NC} {url} ({info} bytes)")
                else:
                    print(f"  {Y}[{status}]{NC} {url}")
        else:
            print(f"{R}[-] No accessible resources found with common paths{NC}")
            print(f"{Y}[!] Consider: Custom wordlist, different HTTP methods, or authenticated discovery{NC}")
        
    except Exception as e:
        print(f"{R}[!] EXECUTION FAILED: {e}{NC}")

if __name__ == "__main__":
    run_audit()
EOF

# 3. Execute
python exploit.py

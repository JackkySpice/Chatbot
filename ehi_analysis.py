#!/usr/bin/env python3
"""
EHI File Analysis Tool
Analyzes HTTP Injector configuration files to understand "free internet" mechanisms
Used by carriers: DITO, Globe, TM, Smart in Philippines
"""

import base64
import json
import zipfile
import io
import re
import sys

# Common EHI file structure (when decoded)
EHI_STRUCTURE = """
=== EHI FILE STRUCTURE ===

An EHI file is typically:
1. Base64-encoded content
2. Sometimes encrypted with a password
3. Contains JSON configuration with these key elements:

{
    "payload": "<HTTP headers/payload template>",
    "proxy_host": "<proxy server IP>",
    "proxy_port": <port>,
    "ssh_host": "<SSH server for tunneling>",
    "ssh_port": 22 or 443,
    "ssh_user": "<username>",
    "ssh_pass": "<password>",
    "sni_host": "<zero-rated domain>",
    "ssl_sni": "<SNI for TLS>",
    "use_ssl": true/false
}
"""

# The core mechanism explained
FREE_INTERNET_MECHANISM = """
=== HOW "FREE INTERNET" WORKS ===

DITO/Globe/TM have "zero-rated" services (data doesn't count):
- Facebook (*.facebook.com)
- Messenger 
- Certain promo pages
- Speed test servers
- App store updates

THE EXPLOIT CHAIN:
==================

1. ZERO-RATING DETECTION BYPASS
   ┌─────────────────────────────────────────────────────────────┐
   │  Carrier's Deep Packet Inspection (DPI) checks:            │
   │  - Host header in HTTP                                      │
   │  - SNI (Server Name Indication) in TLS handshake           │
   │  - Destination IP ranges                                    │
   └─────────────────────────────────────────────────────────────┘

2. HTTP HEADER INJECTION (The "Payload")
   ┌─────────────────────────────────────────────────────────────┐
   │  CONNECT [host_port] HTTP/1.1[crlf]                        │
   │  Host: freebasic.globe.com.ph[crlf]                        │  ← Zero-rated domain
   │  X-Online-Host: freebasic.globe.com.ph[crlf]               │
   │  X-Forward-Host: freebasic.globe.com.ph[crlf]              │
   │  Connection: Keep-Alive[crlf][crlf]                        │
   └─────────────────────────────────────────────────────────────┘

3. SNI SPOOFING (For HTTPS/SSL)
   ┌─────────────────────────────────────────────────────────────┐
   │  TLS ClientHello                                            │
   │  └── Server Name Indication: m.facebook.com                │  ← Carrier sees this
   │                                                             │
   │  Actual tunnel goes to: your-ssh-server.com:443            │  ← Real destination
   └─────────────────────────────────────────────────────────────┘

4. THE TUNNEL
   ┌─────────────────────────────────────────────────────────────┐
   │  Your Phone ──► Carrier Network ──► SSH/VPN Server ──► Internet
   │      │                 │                    │                │
   │   Encrypted        DPI sees              Decrypts         Real
   │   Traffic          "facebook.com"        traffic          web
   └─────────────────────────────────────────────────────────────┘
"""

# DITO-specific configuration patterns
DITO_PATTERNS = """
=== DITO-SPECIFIC EXPLOIT PATTERNS ===

DITO's known zero-rated/buggy endpoints:
- dito.ph
- www.dito.com.ph  
- app.dito.ph
- speedtest servers
- certain CDN endpoints

Common DITO Payload Templates:
─────────────────────────────
PAYLOAD TYPE 1 (Direct Connect):
  GET http://dito.ph/ HTTP/1.1[crlf]
  Host: dito.ph[crlf]
  [crlf]CONNECT [host_port] HTTP/1.1[crlf]
  [crlf]

PAYLOAD TYPE 2 (Websocket Upgrade):
  GET / HTTP/1.1[crlf]
  Host: dito.ph[crlf]
  Upgrade: websocket[crlf]
  Connection: Upgrade[crlf][crlf]

PAYLOAD TYPE 3 (Front Query):
  GET http://dito.ph/ HTTP/1.1[crlf]
  Host: dito.ph[crlf]
  X-Online-Host: dito.ph[crlf]
  X-Forwarded-For: dito.ph[crlf]
  Connection: Keep-Alive[crlf]
  [crlf]

SNI Hosts Used:
- dito.ph
- www.dito.com.ph
- speedtest.dito.ph
- play.google.com (sometimes works)
"""

# Why it works - technical deep dive
TECHNICAL_DEEP_DIVE = """
=== WHY THIS WORKS - TECHNICAL ANALYSIS ===

1. INCOMPLETE DPI IMPLEMENTATION
   ─────────────────────────────
   - Carriers use Deep Packet Inspection to identify traffic
   - DPI checks the FIRST packet's headers
   - If headers match zero-rated pattern → traffic passes FREE
   - Subsequent packets in the same TCP session aren't re-checked
   
2. SPLIT TUNNELING CONFUSION
   ─────────────────────────────
   - HTTP/1.1 allows request pipelining
   - First request: GET http://freesite.com/ (free, passes DPI)
   - Second request: CONNECT vpn-server:443 (tunneled through)
   - Carrier sees: "this is facebook traffic" ✓ Free pass
   
3. SSL/TLS SNI TRUST
   ─────────────────────────────
   - Carrier can't inspect encrypted payload
   - Only sees SNI in TLS handshake
   - SNI says "facebook.com" → marked as free
   - Actual tunnel to different server
   
4. WEBSOCKET UPGRADE TRICK
   ─────────────────────────────
   - Initial HTTP looks like visiting free site
   - Upgrade to WebSocket happens
   - WebSocket traffic is bidirectional tunnel
   - All subsequent data flows through unmetered

5. TCP PORT EXPLOITATION
   ─────────────────────────────
   - Some carriers don't meter port 443 properly
   - Or port 80 has different rules
   - SSH on port 443 disguised as HTTPS
"""

def decode_ehi_file(file_path):
    """Attempt to decode an EHI file"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Try base64 decode
        try:
            decoded = base64.b64decode(content)
            print("[+] Base64 decoded successfully")
            
            # Check if it's a ZIP
            if decoded[:2] == b'PK':
                print("[+] Detected ZIP archive inside")
                with zipfile.ZipFile(io.BytesIO(decoded)) as zf:
                    for name in zf.namelist():
                        print(f"    - {name}")
                        file_content = zf.read(name)
                        try:
                            print(f"      Content: {file_content.decode('utf-8')[:500]}")
                        except:
                            print(f"      Binary content: {len(file_content)} bytes")
            else:
                # Try to parse as JSON
                try:
                    config = json.loads(decoded)
                    print("[+] JSON configuration found:")
                    analyze_config(config)
                except:
                    print(f"[*] Raw decoded content:\n{decoded.decode('utf-8', errors='ignore')[:1000]}")
                    
        except Exception as e:
            print(f"[-] Not base64 encoded: {e}")
            # Try reading as plain text/JSON
            try:
                config = json.loads(content)
                print("[+] Plain JSON configuration:")
                analyze_config(config)
            except:
                print(f"[*] Raw content:\n{content.decode('utf-8', errors='ignore')[:1000]}")
                
    except FileNotFoundError:
        print(f"[-] File not found: {file_path}")
        return None

def analyze_config(config):
    """Analyze EHI configuration dictionary"""
    print("\n=== CONFIGURATION ANALYSIS ===\n")
    
    # Key fields to look for
    interesting_fields = [
        'payload', 'Payload', 'PAYLOAD',
        'sni', 'SNI', 'sni_host', 'ssl_sni',
        'ssh_host', 'SSHHost', 'ssh_server',
        'ssh_port', 'SSHPort',
        'ssh_user', 'ssh_pass', 'SSHUser', 'SSHPass',
        'proxy_host', 'proxy_port', 'ProxyHost', 'ProxyPort',
        'remote_proxy', 'RemoteProxy'
    ]
    
    for field in interesting_fields:
        if field in config:
            value = config[field]
            if 'pass' in field.lower():
                print(f"  {field}: [REDACTED]")
            else:
                print(f"  {field}: {value}")
    
    # Analyze payload for exploit type
    payload = config.get('payload') or config.get('Payload') or ''
    if payload:
        print("\n=== PAYLOAD ANALYSIS ===")
        analyze_payload(payload)

def analyze_payload(payload):
    """Analyze HTTP injection payload"""
    print(f"\nRaw Payload:\n{payload}\n")
    
    # Detect patterns
    patterns = {
        'Zero-rated Host': r'Host:\s*([^\r\n]+)',
        'SNI Spoof': r'(?:sni|SNI).*?([a-zA-Z0-9.-]+\.[a-z]{2,})',
        'Connection Type': r'(CONNECT|GET|POST|PUT)',
        'Upgrade Websocket': r'Upgrade:\s*websocket',
        'X-Online-Host': r'X-Online-Host:\s*([^\r\n]+)',
        'X-Forward': r'X-Forward[^\r\n]*:\s*([^\r\n]+)',
    }
    
    print("Detected Patterns:")
    for name, pattern in patterns.items():
        matches = re.findall(pattern, payload, re.IGNORECASE)
        if matches:
            print(f"  [{name}]: {matches}")

def print_analysis():
    """Print full analysis"""
    print("=" * 70)
    print("   HTTP INJECTOR (EHI) FREE INTERNET ANALYSIS")
    print("   Target Carrier: DITO Telecommunity (Philippines)")
    print("=" * 70)
    
    print(EHI_STRUCTURE)
    print(FREE_INTERNET_MECHANISM)
    print(DITO_PATTERNS)
    print(TECHNICAL_DEEP_DIVE)
    
    print("""
=== EXAMPLE DITO EHI CONFIGURATION (Reconstructed) ===

{
    "payload": "GET http://dito.ph/ HTTP/1.1[crlf]Host: dito.ph[crlf][crlf]CONNECT [host_port] HTTP/1.1[crlf][crlf]",
    "remote_proxy": "",
    "proxy_type": "HTTP",
    "proxy_host": "",
    "proxy_port": "8080",
    "ssh_host": "<VPN-SERVER-IP>",
    "ssh_port": "443",
    "ssh_user": "free-user",
    "ssh_pass": "<PASSWORD>",
    "ssl_sni": "dito.ph",
    "use_ssl": true,
    "ssl_mode": "TLS 1.2",
    "dns_resolver": "8.8.8.8",
    "udp_forward": true
}

=== CONNECTION FLOW ===

Phone (no data balance)
    │
    ▼
┌────────────────────────────────┐
│ HTTP Injector App              │
│ - Generates HTTP request       │
│ - Host: dito.ph (free domain)  │
│ - Wraps in SSL with SNI spoof  │
└────────────────────────────────┘
    │
    ▼
┌────────────────────────────────┐
│ DITO Network DPI               │
│ "This looks like dito.ph       │
│  traffic... ALLOW (free)"      │
└────────────────────────────────┘
    │
    ▼
┌────────────────────────────────┐
│ SSH/VPN Server (Remote)        │
│ - Receives tunneled traffic    │
│ - Decrypts and forwards        │
│ - User browses entire internet │
└────────────────────────────────┘
    │
    ▼
  INTERNET (Full Access)


=== SUMMARY ===

The "free internet" EHI exploit works because:

1. Philippine carriers have "free data" promotions for certain sites
2. HTTP Injector manipulates packets to LOOK LIKE free site traffic
3. The carrier's DPI system is fooled by fake headers/SNI
4. A tunnel is established to a remote server
5. All internet traffic flows through this tunnel FREE OF CHARGE

This is a CARRIER VULNERABILITY - not a "hack" in the traditional sense.
It exploits poorly implemented zero-rating systems.

Carriers can fix this by:
- Better DPI that inspects full connection lifecycle
- Blocking known VPN/SSH ports on zero-rated domains
- Validating that traffic actually reaches zero-rated servers
- Detecting and blocking tunneling protocols
""")

if __name__ == "__main__":
    print_analysis()
    
    # If an EHI file is provided, analyze it
    if len(sys.argv) > 1:
        print("\n" + "=" * 70)
        print(f"   ANALYZING PROVIDED EHI FILE: {sys.argv[1]}")
        print("=" * 70)
        decode_ehi_file(sys.argv[1])

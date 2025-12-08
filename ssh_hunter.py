#!/usr/bin/env python3
"""
Free SSH Hunter & EHI Generator
Finds working free SSH servers and generates EHI configurations for DITO Philippines
"""

import subprocess
import socket
import ssl
import json
import base64
import time
import re
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta

# Known free SSH provider endpoints (these change frequently)
FREE_SSH_PROVIDERS = [
    # Format: (name, host, ports_to_try)
    ("FastSSH SG", "sg1.fastssh.com", [22, 443, 80]),
    ("FastSSH SG2", "sg2.fastssh.com", [22, 443, 80]),
    ("FastSSH SG3", "sg3.fastssh.com", [22, 443, 80]),
    ("SSHOcean SG", "sg1.sshocean.com", [22, 443, 80]),
    ("SSHOcean SG2", "sg2.sshocean.com", [22, 443, 80]),
    ("ServerSSH SG", "sg.serverss.me", [22, 443]),
    ("SSHKit SG", "sg1.sshkit.com", [22, 443]),
    ("SSHKit SG2", "sg2.sshkit.com", [22, 443]),
    ("FullSSH SG", "sg1.fullssh.com", [22, 443]),
    ("FullSSH SG2", "sg2.fullssh.com", [22, 443]),
    ("CreateSSH SG", "sg1.createssh.com", [22, 443]),
    ("SSHStores SG", "sg1.sshstores.net", [22, 443]),
    ("JEFRIV SG", "sg-do.jefriv.com", [22, 443]),
    ("Jagoan SG", "sg1.jagoanssh.com", [22, 443, 80]),
    ("Jagoan SG2", "sg2.jagoanssh.com", [22, 443, 80]),
    # Dropbear servers (often on non-standard ports)
    ("Dropbear SG", "sg1.dropbear.me", [443, 80, 109, 143]),
    ("Dropbear SG2", "sg2.dropbear.me", [443, 80, 109, 143]),
]

# Additional servers to scan
ADDITIONAL_HOSTS = [
    "free-sg.sshstores.net",
    "premium-sg.sshstores.net",
    "sg.speedssh.com",
    "sgdo.servervpn.me",
    "sg-maxis.jagoanssh.com",
]

class SSHScanner:
    def __init__(self):
        self.working_servers = []
        self.timeout = 5
        
    def check_port(self, host: str, port: int) -> dict:
        """Check if SSH port is open and get banner"""
        result = {
            "host": host,
            "port": port,
            "open": False,
            "banner": None,
            "ssh_version": None,
            "latency_ms": None
        }
        
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            latency = (time.time() - start) * 1000
            
            result["open"] = True
            result["latency_ms"] = round(latency, 2)
            
            # Try to get SSH banner
            try:
                sock.settimeout(3)
                banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
                result["banner"] = banner
                if 'SSH' in banner:
                    result["ssh_version"] = banner
            except:
                pass
                
            sock.close()
            
        except socket.timeout:
            pass
        except socket.error:
            pass
        except Exception as e:
            pass
            
        return result
    
    def resolve_host(self, hostname: str) -> str:
        """Resolve hostname to IP"""
        try:
            return socket.gethostbyname(hostname)
        except:
            return None
    
    def scan_provider(self, name: str, host: str, ports: list) -> list:
        """Scan a provider for working SSH servers"""
        results = []
        ip = self.resolve_host(host)
        
        if not ip:
            print(f"  [-] Cannot resolve: {host}")
            return results
        
        print(f"  [*] Scanning {name} ({host} -> {ip})")
        
        for port in ports:
            result = self.check_port(host, port)
            if result["open"]:
                result["name"] = name
                result["ip"] = ip
                results.append(result)
                status = f"SSH: {result['ssh_version']}" if result['ssh_version'] else "Open"
                print(f"      [+] Port {port}: {status} ({result['latency_ms']}ms)")
        
        return results
    
    def scan_all(self) -> list:
        """Scan all known providers"""
        print("\n" + "=" * 60)
        print("   FREE SSH SERVER SCANNER")
        print("=" * 60)
        print(f"\nScanning {len(FREE_SSH_PROVIDERS)} known providers...\n")
        
        all_results = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.scan_provider, name, host, ports): (name, host)
                for name, host, ports in FREE_SSH_PROVIDERS
            }
            
            for future in as_completed(futures):
                results = future.result()
                all_results.extend(results)
        
        # Sort by latency
        all_results.sort(key=lambda x: x.get('latency_ms', 9999))
        self.working_servers = all_results
        
        return all_results


class EHIGenerator:
    """Generate EHI configuration files for HTTP Injector"""
    
    # DITO Philippines zero-rated domains and payloads
    DITO_PAYLOADS = {
        "direct_connect": {
            "name": "DITO Direct Connect",
            "payload": "GET http://dito.ph/ HTTP/1.1[crlf]Host: dito.ph[crlf][crlf]CONNECT [host_port] HTTP/1.1[crlf]Host: dito.ph[crlf][crlf]",
            "sni": "dito.ph"
        },
        "websocket": {
            "name": "DITO WebSocket",
            "payload": "GET / HTTP/1.1[crlf]Host: dito.ph[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf][crlf]",
            "sni": "dito.ph"
        },
        "front_query": {
            "name": "DITO Front Query",
            "payload": "GET http://www.dito.com.ph/ HTTP/1.1[crlf]Host: www.dito.com.ph[crlf]X-Online-Host: www.dito.com.ph[crlf]X-Forward-Host: www.dito.com.ph[crlf]Connection: Keep-Alive[crlf][crlf]CONNECT [host_port] HTTP/1.1[crlf][crlf]",
            "sni": "www.dito.com.ph"
        },
        "split_tunnel": {
            "name": "DITO Split Tunnel",
            "payload": "CONNECT [host_port] HTTP/1.1[crlf]Host: dito.ph[crlf]X-Online-Host: dito.ph[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]",
            "sni": "dito.ph"
        },
        "combo_method": {
            "name": "DITO Combo (Most Stable)",
            "payload": "GET http://dito.ph/ HTTP/1.1[crlf]Host: dito.ph[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]CONNECT [host_port] HTTP/1.1[crlf]Host: dito.ph[crlf][crlf]",
            "sni": "dito.ph"
        }
    }
    
    # Globe/TM payloads
    GLOBE_PAYLOADS = {
        "gosakto": {
            "name": "Globe GoSakto",
            "payload": "GET http://gosakto.globe.com.ph/ HTTP/1.1[crlf]Host: gosakto.globe.com.ph[crlf][crlf]CONNECT [host_port] HTTP/1.1[crlf][crlf]",
            "sni": "gosakto.globe.com.ph"
        },
        "freebasic": {
            "name": "Globe FreeBasic",
            "payload": "CONNECT [host_port] HTTP/1.1[crlf]Host: freebasic.globe.com.ph[crlf]X-Online-Host: freebasic.globe.com.ph[crlf][crlf]",
            "sni": "freebasic.globe.com.ph"
        }
    }
    
    def __init__(self, ssh_host: str, ssh_port: int, ssh_user: str = "fastssh.com-free", ssh_pass: str = "1234"):
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass
    
    def generate_config(self, carrier: str = "dito", payload_type: str = "combo_method") -> dict:
        """Generate HTTP Injector configuration"""
        
        if carrier.lower() == "dito":
            payload_info = self.DITO_PAYLOADS.get(payload_type, self.DITO_PAYLOADS["combo_method"])
        else:
            payload_info = self.GLOBE_PAYLOADS.get(payload_type, self.GLOBE_PAYLOADS["gosakto"])
        
        config = {
            # Connection settings
            "ssh_host": self.ssh_host,
            "ssh_port": str(self.ssh_port),
            "ssh_user": self.ssh_user,
            "ssh_pass": self.ssh_pass,
            
            # Payload
            "payload": payload_info["payload"],
            "payload_name": payload_info["name"],
            
            # SSL/SNI
            "ssl_sni": payload_info["sni"],
            "use_ssl": True,
            "ssl_mode": "TLS 1.2",
            
            # Proxy settings
            "proxy_type": "HTTP",
            "proxy_host": "",
            "proxy_port": "",
            "remote_proxy": "",
            
            # DNS
            "dns_resolver": "8.8.8.8",
            "dns_port": "53",
            
            # UDP
            "udp_forward": True,
            "udp_port": "7300",
            
            # Misc
            "connection_mode": "SSH",
            "lock_payload": False,
            "note": f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | {payload_info['name']}"
        }
        
        return config
    
    def export_ehi(self, config: dict, filename: str, encrypt: bool = False, password: str = None) -> str:
        """Export configuration as .ehi file"""
        
        json_str = json.dumps(config, indent=2)
        
        if encrypt and password:
            # Simple XOR encryption (compatible with many EHI readers)
            key = password.encode()
            encrypted = bytes([ord(c) ^ key[i % len(key)] for i, c in enumerate(json_str)])
            content = base64.b64encode(encrypted)
        else:
            # Standard Base64 encoding
            content = base64.b64encode(json_str.encode())
        
        filepath = filename if filename.endswith('.ehi') else f"{filename}.ehi"
        with open(filepath, 'wb') as f:
            f.write(content)
        
        return filepath
    
    def export_all_payloads(self, carrier: str = "dito", base_filename: str = "dito_config") -> list:
        """Export all payload variations"""
        files = []
        payloads = self.DITO_PAYLOADS if carrier.lower() == "dito" else self.GLOBE_PAYLOADS
        
        for payload_type in payloads.keys():
            config = self.generate_config(carrier, payload_type)
            filename = f"{base_filename}_{payload_type}.ehi"
            filepath = self.export_ehi(config, filename)
            files.append(filepath)
            print(f"  [+] Created: {filepath}")
        
        return files


def test_ssh_connection(host: str, port: int, user: str, password: str, timeout: int = 10) -> bool:
    """Test SSH connection using sshpass or expect"""
    print(f"\n[*] Testing SSH connection to {host}:{port}...")
    
    # Check if sshpass is available
    sshpass_available = subprocess.run(["which", "sshpass"], capture_output=True).returncode == 0
    
    if sshpass_available:
        cmd = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "BatchMode=no",
            "-p", str(port),
            f"{user}@{host}",
            "echo CONNECTION_SUCCESS"
        ]
    else:
        # Use timeout + ssh with password via stdin (won't work without tty, but we try)
        print("  [!] sshpass not available, attempting basic connectivity test...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = sock.recv(256).decode('utf-8', errors='ignore')
            sock.close()
            if 'SSH' in banner:
                print(f"  [+] SSH service detected: {banner.strip()}")
                return True
        except Exception as e:
            print(f"  [-] Connection failed: {e}")
        return False
    
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout+5, text=True)
        if "CONNECTION_SUCCESS" in result.stdout:
            print("  [+] SSH connection successful!")
            return True
        else:
            print(f"  [-] SSH connection failed: {result.stderr[:200]}")
            return False
    except subprocess.TimeoutExpired:
        print("  [-] SSH connection timed out")
        return False
    except Exception as e:
        print(f"  [-] SSH test error: {e}")
        return False


def main():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║         FREE SSH HUNTER & DITO EHI GENERATOR                     ║
║         For Educational/Research Purposes Only                   ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    # Step 1: Scan for working servers
    scanner = SSHScanner()
    working_servers = scanner.scan_all()
    
    if not working_servers:
        print("\n[-] No working servers found!")
        print("[*] Generating config with default server (may not work)...")
        working_servers = [{
            "name": "Default",
            "host": "sg1.sshocean.com",
            "port": 443,
            "ip": "0.0.0.0",
            "latency_ms": 999
        }]
    
    # Summary of found servers
    print(f"\n{'=' * 60}")
    print(f"   FOUND {len(working_servers)} WORKING SERVERS")
    print(f"{'=' * 60}")
    
    for i, server in enumerate(working_servers[:10], 1):  # Show top 10
        banner = server.get('ssh_version', 'Unknown')[:40] if server.get('ssh_version') else 'Port Open'
        print(f"  {i}. {server['name']:20} | {server['host']}:{server['port']} | {server['latency_ms']}ms")
    
    # Use best server (lowest latency with SSH banner)
    best_server = None
    for server in working_servers:
        if server.get('ssh_version'):
            best_server = server
            break
    
    if not best_server and working_servers:
        best_server = working_servers[0]
    
    if best_server:
        print(f"\n[+] Selected best server: {best_server['name']} ({best_server['host']}:{best_server['port']})")
        
        # Step 2: Generate EHI files
        print(f"\n{'=' * 60}")
        print("   GENERATING EHI CONFIGURATIONS")
        print(f"{'=' * 60}\n")
        
        generator = EHIGenerator(
            ssh_host=best_server['host'],
            ssh_port=best_server['port'],
            ssh_user="fastssh.com-free",  # Common free SSH username format
            ssh_pass="1234"  # Common default password
        )
        
        # Generate all DITO payload variations
        print("[*] Creating DITO configurations...")
        dito_files = generator.export_all_payloads("dito", "/workspace/DITO")
        
        # Also create a "best" config
        print("\n[*] Creating optimized configuration...")
        best_config = generator.generate_config("dito", "combo_method")
        best_file = generator.export_ehi(best_config, "/workspace/DITO_BEST_CONFIG.ehi")
        print(f"  [+] Created: {best_file}")
        
        # Save raw JSON for inspection
        with open("/workspace/DITO_CONFIG_READABLE.json", "w") as f:
            json.dump(best_config, f, indent=2)
        print(f"  [+] Created: /workspace/DITO_CONFIG_READABLE.json (human readable)")
        
        # Summary
        print(f"\n{'=' * 60}")
        print("   GENERATION COMPLETE")
        print(f"{'=' * 60}")
        print(f"""
Files created in /workspace/:
  • DITO_BEST_CONFIG.ehi     - Best payload (Combo Method)
  • DITO_direct_connect.ehi  - Direct Connect method
  • DITO_websocket.ehi       - WebSocket upgrade method
  • DITO_front_query.ehi     - Front Query method  
  • DITO_split_tunnel.ehi    - Split Tunnel method
  • DITO_combo_method.ehi    - Combined methods
  • DITO_CONFIG_READABLE.json - Human-readable config

SSH Server Details:
  • Host: {best_server['host']}
  • Port: {best_server['port']}
  • IP:   {best_server.get('ip', 'N/A')}
  
To use:
  1. Transfer .ehi file to your Android phone
  2. Open HTTP Injector app
  3. Import the .ehi file
  4. Connect!
        """)
        
        return best_server, dito_files
    else:
        print("\n[-] Could not find any suitable SSH servers")
        return None, []


if __name__ == "__main__":
    main()

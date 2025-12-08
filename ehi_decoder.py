#!/usr/bin/env python3
"""
EHI File Decoder & Analyzer
Decodes HTTP Injector configuration files (.ehi)

Usage: python3 ehi_decoder.py <file.ehi> [password]
"""

import base64
import json
import zipfile
import io
import sys
import re
import hashlib
from typing import Optional, Dict, Any

class EHIDecoder:
    """Decoder for HTTP Injector .ehi configuration files"""
    
    def __init__(self, file_path: str, password: Optional[str] = None):
        self.file_path = file_path
        self.password = password
        self.raw_content = None
        self.decoded_content = None
        self.config = None
        
    def load(self) -> bool:
        """Load the EHI file"""
        try:
            with open(self.file_path, 'rb') as f:
                self.raw_content = f.read()
            print(f"[+] Loaded {len(self.raw_content)} bytes from {self.file_path}")
            return True
        except FileNotFoundError:
            print(f"[-] File not found: {self.file_path}")
            return False
        except Exception as e:
            print(f"[-] Error loading file: {e}")
            return False
    
    def decode(self) -> bool:
        """Attempt to decode the EHI file"""
        if not self.raw_content:
            return False
            
        # Method 1: Try direct JSON parse
        try:
            self.config = json.loads(self.raw_content)
            print("[+] Direct JSON decode successful")
            return True
        except:
            pass
        
        # Method 2: Try Base64 decode
        try:
            # Clean the content (remove whitespace/newlines)
            cleaned = self.raw_content.strip()
            decoded = base64.b64decode(cleaned)
            print(f"[+] Base64 decoded: {len(decoded)} bytes")
            
            # Check if it's a ZIP
            if decoded[:2] == b'PK':
                return self._handle_zip(decoded)
            
            # Try JSON parse
            try:
                self.config = json.loads(decoded)
                print("[+] JSON parse after Base64 successful")
                return True
            except:
                # Store as decoded content
                self.decoded_content = decoded
                print("[*] Decoded but not JSON - checking for other formats")
                return self._try_alternative_formats()
                
        except Exception as e:
            print(f"[-] Base64 decode failed: {e}")
        
        # Method 3: Try URL-safe Base64
        try:
            decoded = base64.urlsafe_b64decode(self.raw_content.strip())
            self.config = json.loads(decoded)
            print("[+] URL-safe Base64 + JSON successful")
            return True
        except:
            pass
        
        # Method 4: Check if encrypted
        print("[*] Attempting to detect encryption...")
        return self._try_decrypt()
    
    def _handle_zip(self, data: bytes) -> bool:
        """Handle ZIP archive"""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                print(f"[+] ZIP archive detected with {len(zf.namelist())} files:")
                for name in zf.namelist():
                    print(f"    - {name}")
                
                # Look for config file
                config_names = ['config.json', 'settings.json', 'payload.txt', 'config']
                for config_name in config_names:
                    if config_name in zf.namelist():
                        content = zf.read(config_name)
                        try:
                            self.config = json.loads(content)
                            print(f"[+] Loaded config from {config_name}")
                            return True
                        except:
                            self.decoded_content = content
                
                # If no config found, read first file
                if zf.namelist():
                    first_file = zf.namelist()[0]
                    content = zf.read(first_file)
                    try:
                        self.config = json.loads(content)
                        return True
                    except:
                        self.decoded_content = content
                        return True
                        
        except zipfile.BadZipFile as e:
            print(f"[-] Bad ZIP file: {e}")
        except Exception as e:
            print(f"[-] ZIP handling error: {e}")
        return False
    
    def _try_alternative_formats(self) -> bool:
        """Try to parse alternative EHI formats"""
        if not self.decoded_content:
            return False
            
        content = self.decoded_content
        
        # Try to find JSON embedded in content
        try:
            # Look for JSON object pattern
            match = re.search(rb'\{.*\}', content, re.DOTALL)
            if match:
                self.config = json.loads(match.group())
                print("[+] Extracted embedded JSON")
                return True
        except:
            pass
        
        # Try line-by-line key=value parsing
        try:
            config = {}
            for line in content.decode('utf-8', errors='ignore').split('\n'):
                if '=' in line:
                    key, _, value = line.partition('=')
                    config[key.strip()] = value.strip()
            if config:
                self.config = config
                print("[+] Parsed key=value format")
                return True
        except:
            pass
            
        return False
    
    def _try_decrypt(self) -> bool:
        """Attempt to decrypt encrypted EHI files"""
        if not self.password:
            print("[!] File may be encrypted - try providing a password")
            print("[!] Usage: python3 ehi_decoder.py <file.ehi> <password>")
            return False
        
        # Common encryption schemes used in EHI files
        print(f"[*] Attempting decryption with password...")
        
        # Try XOR with password
        try:
            key = self.password.encode()
            decrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(self.raw_content)])
            # Try base64 decode result
            decoded = base64.b64decode(decrypted)
            self.config = json.loads(decoded)
            print("[+] XOR decryption successful")
            return True
        except:
            pass
        
        # Try AES (common in newer EHI files)
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad
            
            key = hashlib.md5(self.password.encode()).digest()
            iv = self.raw_content[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(self.raw_content[16:]), AES.block_size)
            self.config = json.loads(decrypted)
            print("[+] AES decryption successful")
            return True
        except ImportError:
            print("[!] PyCryptodome not installed - skipping AES decryption")
        except:
            pass
            
        print("[-] Decryption failed")
        return False
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze the decoded configuration"""
        if not self.config and not self.decoded_content:
            return {"error": "No configuration loaded"}
        
        analysis = {
            "file": self.file_path,
            "format": "unknown",
            "payload_analysis": {},
            "connection_info": {},
            "security_findings": [],
            "exploit_type": []
        }
        
        if self.config:
            analysis["format"] = "json"
            analysis["raw_config"] = self.config
            
            # Extract key configuration
            payload = self._get_field(['payload', 'Payload', 'PAYLOAD'])
            if payload:
                analysis["payload_analysis"] = self._analyze_payload(payload)
            
            # SSH/VPN Configuration
            analysis["connection_info"] = {
                "ssh_host": self._get_field(['ssh_host', 'SSHHost', 'ssh_server', 'server']),
                "ssh_port": self._get_field(['ssh_port', 'SSHPort', 'port']),
                "ssh_user": self._get_field(['ssh_user', 'SSHUser', 'username', 'user']),
                "proxy_host": self._get_field(['proxy_host', 'ProxyHost', 'proxy']),
                "proxy_port": self._get_field(['proxy_port', 'ProxyPort']),
                "sni_host": self._get_field(['ssl_sni', 'sni', 'SNI', 'sni_host', 'SNIHost']),
                "use_ssl": self._get_field(['use_ssl', 'UseSSL', 'ssl', 'SSL']),
            }
            
            # Identify exploit type
            if payload:
                analysis["exploit_type"] = self._identify_exploit_type(payload)
            
            # Security findings
            analysis["security_findings"] = self._security_scan()
            
        elif self.decoded_content:
            analysis["format"] = "raw"
            analysis["content_preview"] = self.decoded_content[:500].decode('utf-8', errors='ignore')
            
        return analysis
    
    def _get_field(self, names: list) -> Any:
        """Get field value by trying multiple possible names"""
        if not self.config:
            return None
        for name in names:
            if name in self.config:
                return self.config[name]
        return None
    
    def _analyze_payload(self, payload: str) -> Dict[str, Any]:
        """Deep analysis of the HTTP injection payload"""
        analysis = {
            "raw": payload,
            "method": None,
            "target_hosts": [],
            "headers": {},
            "injection_points": [],
            "variables": []
        }
        
        # Detect HTTP method
        method_match = re.search(r'^(GET|POST|CONNECT|PUT|DELETE|HEAD|OPTIONS)', payload, re.MULTILINE)
        if method_match:
            analysis["method"] = method_match.group(1)
        
        # Extract Host headers
        host_matches = re.findall(r'Host:\s*([^\r\n\[]+)', payload, re.IGNORECASE)
        analysis["target_hosts"] = [h.strip() for h in host_matches]
        
        # Extract other headers
        header_pattern = r'([A-Za-z-]+):\s*([^\r\n\[]+)'
        for match in re.finditer(header_pattern, payload):
            header, value = match.groups()
            if header.lower() != 'host':
                analysis["headers"][header] = value.strip()
        
        # Find variables/placeholders
        var_matches = re.findall(r'\[([^\]]+)\]', payload)
        analysis["variables"] = list(set(var_matches))
        
        # Identify injection points
        if 'CONNECT' in payload:
            analysis["injection_points"].append("CONNECT tunnel")
        if 'Upgrade: websocket' in payload.lower():
            analysis["injection_points"].append("WebSocket upgrade")
        if '[crlf]' in payload.lower():
            analysis["injection_points"].append("CRLF injection")
        if 'X-Online-Host' in payload or 'X-Forward' in payload:
            analysis["injection_points"].append("Header spoofing")
            
        return analysis
    
    def _identify_exploit_type(self, payload: str) -> list:
        """Identify the type of carrier exploit"""
        exploits = []
        
        payload_lower = payload.lower()
        
        if 'connect' in payload_lower:
            exploits.append("CONNECT Tunnel")
        
        if 'websocket' in payload_lower or 'upgrade' in payload_lower:
            exploits.append("WebSocket Tunnel")
        
        if any(h in payload_lower for h in ['x-online-host', 'x-forward', 'x-real-ip']):
            exploits.append("Header Injection")
        
        if 'front' in payload_lower or re.search(r'GET.*GET|GET.*CONNECT', payload_lower):
            exploits.append("Request Splitting")
        
        # Check for specific carrier exploits
        carrier_domains = {
            'dito': ['dito.ph', 'dito.com.ph'],
            'globe': ['globe.com.ph', 'freebasic.globe', 'gosakto'],
            'smart': ['smart.com.ph', 'tnt', 'liveit'],
            'tm': ['tm.com.ph']
        }
        
        for carrier, domains in carrier_domains.items():
            if any(d in payload_lower for d in domains):
                exploits.append(f"{carrier.upper()} Zero-Rating Bypass")
        
        return exploits or ["Generic HTTP Injection"]
    
    def _security_scan(self) -> list:
        """Scan for security issues in the configuration"""
        findings = []
        
        if not self.config:
            return findings
        
        # Check for exposed credentials
        if self._get_field(['ssh_pass', 'SSHPass', 'password']):
            findings.append("⚠️ SSH password exposed in config")
        
        # Check for weak ports
        port = self._get_field(['ssh_port', 'SSHPort', 'port'])
        if port and int(port) in [22, 80, 8080]:
            findings.append(f"⚠️ Using common port {port} - may be blocked")
        
        # Check SSL/TLS
        if not self._get_field(['use_ssl', 'UseSSL', 'ssl']):
            findings.append("⚠️ SSL disabled - traffic not encrypted")
        
        # Check for hardcoded IPs
        ssh_host = self._get_field(['ssh_host', 'SSHHost', 'server'])
        if ssh_host and re.match(r'^\d+\.\d+\.\d+\.\d+$', str(ssh_host)):
            findings.append(f"ℹ️ Hardcoded IP: {ssh_host}")
        
        return findings
    
    def print_report(self):
        """Print a formatted analysis report"""
        analysis = self.analyze()
        
        print("\n" + "=" * 70)
        print("   EHI FILE ANALYSIS REPORT")
        print("=" * 70)
        
        print(f"\nFile: {analysis['file']}")
        print(f"Format: {analysis['format']}")
        
        if analysis.get('exploit_type'):
            print(f"\n[EXPLOIT TYPE]")
            for exp in analysis['exploit_type']:
                print(f"  • {exp}")
        
        if analysis.get('payload_analysis'):
            pa = analysis['payload_analysis']
            print(f"\n[PAYLOAD ANALYSIS]")
            print(f"  Method: {pa.get('method', 'Unknown')}")
            print(f"  Target Hosts: {', '.join(pa.get('target_hosts', [])) or 'None'}")
            print(f"  Injection Points: {', '.join(pa.get('injection_points', [])) or 'None'}")
            print(f"  Variables: {', '.join(pa.get('variables', [])) or 'None'}")
            if pa.get('headers'):
                print(f"  Headers:")
                for h, v in pa['headers'].items():
                    print(f"    {h}: {v}")
            print(f"\n  Raw Payload:")
            print("  " + "-" * 50)
            for line in pa.get('raw', '').split('[crlf]'):
                print(f"  {line}")
            print("  " + "-" * 50)
        
        if analysis.get('connection_info'):
            ci = analysis['connection_info']
            print(f"\n[CONNECTION INFO]")
            for key, value in ci.items():
                if value:
                    display_value = '[REDACTED]' if 'pass' in key.lower() else value
                    print(f"  {key}: {display_value}")
        
        if analysis.get('security_findings'):
            print(f"\n[SECURITY FINDINGS]")
            for finding in analysis['security_findings']:
                print(f"  {finding}")
        
        if analysis.get('raw_config'):
            print(f"\n[FULL CONFIGURATION]")
            safe_config = {k: ('[REDACTED]' if 'pass' in k.lower() else v) 
                          for k, v in analysis['raw_config'].items()}
            print(json.dumps(safe_config, indent=2))
        
        print("\n" + "=" * 70)


def main():
    if len(sys.argv) < 2:
        print("EHI File Decoder & Analyzer")
        print("-" * 40)
        print(f"Usage: {sys.argv[0]} <file.ehi> [password]")
        print("\nExample:")
        print(f"  {sys.argv[0]} dito_config.ehi")
        print(f"  {sys.argv[0]} encrypted.ehi mypassword")
        sys.exit(1)
    
    file_path = sys.argv[1]
    password = sys.argv[2] if len(sys.argv) > 2 else None
    
    decoder = EHIDecoder(file_path, password)
    
    if decoder.load() and decoder.decode():
        decoder.print_report()
    else:
        print("\n[-] Failed to decode EHI file")
        print("[*] The file may be encrypted or in an unknown format")
        print("[*] Try providing the password if you know it")


if __name__ == "__main__":
    main()

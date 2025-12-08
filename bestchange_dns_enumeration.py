#!/usr/bin/env python3
"""
BestChange.com DNS and Subdomain Enumeration
Comprehensive DNS and subdomain discovery
"""

import requests
import socket
import time
import random

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

class DNSEnumerator:
    def __init__(self, domain="bestchange.com"):
        self.domain = domain
        self.findings = []
        self.discovered_subdomains = []
    
    def log_finding(self, finding_type, details, severity="INFO"):
        self.findings.append({
            'type': finding_type,
            'details': details,
            'severity': severity
        })
        color = Colors.CYAN if severity == "INFO" else Colors.YELLOW
        print(f"{color}[+] {finding_type}: {details}{Colors.RESET}")
    
    def enumerate_subdomains(self):
        """Enumerate common subdomains"""
        print(f"{Colors.BLUE}[*] Enumerating subdomains...{Colors.RESET}")
        
        common_subdomains = [
            'www', 'api', 'admin', 'test', 'dev', 'staging', 'mail', 'ftp',
            'blog', 'shop', 'store', 'cdn', 'static', 'assets', 'img', 'images',
            'secure', 'vpn', 'portal', 'dashboard', 'panel', 'control', 'manage',
            'app', 'mobile', 'm', 'web', 'www2', 'beta', 'alpha',
            'support', 'help', 'docs', 'documentation', 'wiki',
            'old', 'new', 'backup', 'backups', 'archive',
        ]
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{self.domain}"
                
                # Try DNS lookup
                try:
                    ip = socket.gethostbyname(full_domain)
                    self.discovered_subdomains.append(full_domain)
                    self.log_finding("Subdomain Found", f"{full_domain} -> {ip}", "INFO")
                except socket.gaierror:
                    pass
                
                # Try HTTPS
                try:
                    response = requests.get(f"https://{full_domain}", timeout=5, verify=False)
                    if response.status_code in [200, 301, 302, 403]:
                        if full_domain not in self.discovered_subdomains:
                            self.discovered_subdomains.append(full_domain)
                            self.log_finding("Subdomain Found (HTTPS)", f"{full_domain} (Status: {response.status_code})", "INFO")
                except:
                    pass
                
                time.sleep(0.1)
            except:
                continue
    
    def test_dns_security(self):
        """Test DNS security configurations"""
        print(f"{Colors.BLUE}[*] Testing DNS security...{Colors.RESET}")
        
        try:
            # Test for SPF records
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, 'TXT')
                for rdata in answers:
                    if 'v=spf1' in str(rdata):
                        self.log_finding("SPF Record", "SPF record found", "INFO")
            except:
                pass
        except ImportError:
            print(f"{Colors.YELLOW}[!] dnspython not available for DNS testing{Colors.RESET}")
        except:
            pass
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}DNS ENUMERATION REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}Discovered {len(self.discovered_subdomains)} subdomain(s){Colors.RESET}\n")
        
        if self.discovered_subdomains:
            print(f"{Colors.BLUE}Subdomains:{Colors.RESET}")
            for subdomain in self.discovered_subdomains:
                print(f"  - {subdomain}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com DNS Enumeration{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    enumerator = DNSEnumerator()
    
    try:
        enumerator.enumerate_subdomains()
        enumerator.test_dns_security()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    enumerator.generate_report()

if __name__ == "__main__":
    main()

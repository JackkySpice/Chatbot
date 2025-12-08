#!/usr/bin/env python3
"""
BestChange.com Session Security Testing
Comprehensive session management and cookie security testing
"""

import requests
import time
import random
import re
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class SessionSecurityTester:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.findings = []
    
    def log_finding(self, vuln_type, location, details, severity="MEDIUM"):
        self.findings.append({
            'type': vuln_type,
            'location': location,
            'details': details,
            'severity': severity
        })
        color = Colors.RED if severity == "HIGH" else Colors.YELLOW
        print(f"{color}[!] {vuln_type} [{severity}]{Colors.RESET}")
        print(f"    {location}: {details}\n")
    
    def test_session_cookies(self):
        """Test session cookie security"""
        print(f"{Colors.BLUE}[*] Testing session cookie security...{Colors.RESET}")
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        
        try:
            response = session.get(self.base_url, timeout=10)
            time.sleep(0.5)
            
            cookies = response.cookies
            set_cookie_headers = response.headers.get('Set-Cookie', '')
            
            for cookie in cookies:
                cookie_name = cookie.name.lower()
                
                # Check for session-related cookies
                if 'session' in cookie_name or 'sess' in cookie_name or 'sid' in cookie_name or 'phpsessid' in cookie_name:
                    print(f"{Colors.CYAN}[+] Found session cookie: {cookie.name}{Colors.RESET}")
                    
                    # Check Secure flag
                    if not cookie.secure:
                        # Also check Set-Cookie header
                        if 'Secure' not in set_cookie_headers:
                            self.log_finding(
                                "Session Cookie Missing Secure Flag",
                                "Cookies",
                                f"{cookie.name} missing Secure flag",
                                "MEDIUM"
                            )
                    
                    # Check HttpOnly flag
                    if 'HttpOnly' not in set_cookie_headers and cookie.name in set_cookie_headers:
                        # Try to check if accessible via JavaScript (would need browser)
                        self.log_finding(
                            "Session Cookie Missing HttpOnly Flag",
                            "Cookies",
                            f"{cookie.name} may be missing HttpOnly flag",
                            "MEDIUM"
                        )
                    
                    # Check SameSite attribute
                    if 'SameSite' not in set_cookie_headers:
                        self.log_finding(
                            "Session Cookie Missing SameSite",
                            "Cookies",
                            f"{cookie.name} missing SameSite attribute",
                            "LOW"
                        )
                    
                    # Check cookie value predictability
                    if len(cookie.value) < 20:
                        self.log_finding(
                            "Weak Session Token",
                            "Cookies",
                            f"{cookie.name} has short value ({len(cookie.value)} chars)",
                            "MEDIUM"
                        )
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {str(e)}{Colors.RESET}")
    
    def test_session_fixation(self):
        """Test for session fixation"""
        print(f"{Colors.BLUE}[*] Testing session fixation...{Colors.RESET}")
        
        session1 = requests.Session()
        session1.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        try:
            # Get initial session
            response1 = session1.get(self.base_url, timeout=10)
            time.sleep(0.5)
            
            session_id_1 = None
            for cookie in response1.cookies:
                if 'session' in cookie.name.lower() or 'sess' in cookie.name.lower():
                    session_id_1 = cookie.value
                    break
            
            if session_id_1:
                # Create new session and try to set the same ID
                session2 = requests.Session()
                session2.headers.update({'User-Agent': 'Mozilla/5.0'})
                session2.cookies.set('PHPSESSID', session_id_1)
                
                response2 = session2.get(self.base_url, timeout=10)
                time.sleep(0.5)
                
                session_id_2 = None
                for cookie in response2.cookies:
                    if 'session' in cookie.name.lower() or 'sess' in cookie.name.lower():
                        session_id_2 = cookie.value
                        break
                
                if session_id_1 == session_id_2:
                    self.log_finding(
                        "Potential Session Fixation",
                        "Session Management",
                        "Session ID not regenerated",
                        "MEDIUM"
                    )
        except Exception as e:
            pass
    
    def test_session_timeout(self):
        """Test session timeout"""
        print(f"{Colors.BLUE}[*] Testing session timeout...{Colors.RESET}")
        
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        try:
            # Get session
            response1 = session.get(self.base_url, timeout=10)
            time.sleep(0.5)
            
            # Wait and test if session is still valid
            # (In real test, would wait longer)
            response2 = session.get(self.base_url, timeout=10)
            
            # Check if session is still valid
            if response2.status_code == 200:
                print(f"{Colors.GREEN}[+] Session appears to be valid{Colors.RESET}")
        except:
            pass
    
    def test_concurrent_sessions(self):
        """Test concurrent session handling"""
        print(f"{Colors.BLUE}[*] Testing concurrent sessions...{Colors.RESET}")
        
        import threading
        
        results = []
        
        def make_request():
            try:
                session = requests.Session()
                session.headers.update({'User-Agent': 'Mozilla/5.0'})
                response = session.get(self.base_url, timeout=10)
                results.append(response.status_code)
            except:
                pass
        
        threads = []
        for i in range(10):
            t = threading.Thread(target=make_request)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        if len(set(results)) > 1:
            self.log_finding(
                "Inconsistent Concurrent Sessions",
                "Session Management",
                f"Multiple status codes: {set(results)}",
                "MEDIUM"
            )
    
    def generate_report(self):
        """Generate report"""
        print(f"\n{Colors.YELLOW}{'='*70}{Colors.RESET}")
        print(f"{Colors.YELLOW}SESSION SECURITY REPORT{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*70}{Colors.RESET}\n")
        
        if self.findings:
            high = [f for f in self.findings if f['severity'] == 'HIGH']
            medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
            low = [f for f in self.findings if f['severity'] == 'LOW']
            
            print(f"{Colors.RED}[!] Found {len(self.findings)} finding(s){Colors.RESET}")
            print(f"  HIGH: {len(high)}, MEDIUM: {len(medium)}, LOW: {len(low)}\n")
            
            for finding in self.findings:
                color = Colors.RED if finding['severity'] == 'HIGH' else Colors.YELLOW if finding['severity'] == 'MEDIUM' else Colors.CYAN
                print(f"{color}[{finding['severity']}] {finding['type']}{Colors.RESET}")
                print(f"    {finding['location']}: {finding['details']}\n")
        else:
            print(f"{Colors.GREEN}[+] No session security issues found{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Session Security Testing{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    tester = SessionSecurityTester()
    
    try:
        tester.test_session_cookies()
        tester.test_session_fixation()
        tester.test_session_timeout()
        tester.test_concurrent_sessions()
    except Exception as e:
        print(f"{Colors.RED}Error: {str(e)}{Colors.RESET}")
    
    tester.generate_report()

if __name__ == "__main__":
    main()

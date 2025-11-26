#!/usr/bin/env python3
"""
MobileSec Red Team Console - Strategic Adaptation Layer
Implements failure detection and pivot logic for security testing
"""

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

class TacticalAssessment:
    """Meta-analysis and failure detection"""
    
    def __init__(self, target):
        self.target = target
        self.failed_vectors = []
        self.successful_vectors = []
        self.observations = []
    
    def log_failure(self, vector, reason, status_code=None):
        """Log a failed attack vector"""
        failure = {
            'vector': vector,
            'reason': reason,
            'status_code': status_code,
            'timestamp': time.time()
        }
        self.failed_vectors.append(failure)
        print(f"{R}[!] FAILURE: {vector} - {reason}{NC}")
        if status_code:
            print(f"    Status Code: {status_code}")
    
    def log_success(self, vector, details):
        """Log a successful finding"""
        success = {
            'vector': vector,
            'details': details,
            'timestamp': time.time()
        }
        self.successful_vectors.append(success)
        print(f"{G}[+] SUCCESS: {vector} - {details}{NC}")
    
    def log_observation(self, observation):
        """Log an observation about the target"""
        self.observations.append(observation)
        print(f"{C}[*] OBSERVATION: {observation}{NC}")
    
    def should_pivot(self, vector):
        """Check if we should pivot from a vector"""
        # If same vector failed multiple times, pivot
        failures = [f for f in self.failed_vectors if f['vector'] == vector]
        if len(failures) >= 2:
            return True
        return False
    
    def suggest_pivot(self):
        """Suggest alternative attack vectors based on failures"""
        print(f"\n{B}[*] STRATEGIC PIVOT ANALYSIS:{NC}")
        
        if not self.failed_vectors:
            print(f"{G}[+] No failures detected - continue current approach{NC}")
            return
        
        # Analyze failure patterns
        sql_failures = [f for f in self.failed_vectors if 'SQL' in f['vector'] or 'sqli' in f['vector'].lower()]
        xss_failures = [f for f in self.failed_vectors if 'XSS' in f['vector'] or 'xss' in f['vector'].lower()]
        waf_blocks = [f for f in self.failed_vectors if f['status_code'] in [403, 406, 413]]
        rate_limits = [f for f in self.failed_vectors if f['status_code'] == 429]
        
        suggestions = []
        
        if sql_failures:
            print(f"{Y}[!] SQL Injection attempts failed{NC}")
            suggestions.extend([
                "→ PIVOT: Test for IDOR (Insecure Direct Object Reference)",
                "→ PIVOT: Test for Information Disclosure (error messages, stack traces)",
                "→ PIVOT: Test for NoSQL Injection (if MongoDB detected)",
                "→ PIVOT: Test for Command Injection instead"
            ])
        
        if xss_failures:
            print(f"{Y}[!] XSS attempts failed{NC}")
            suggestions.extend([
                "→ PIVOT: Test for CSRF vulnerabilities",
                "→ PIVOT: Test for Open Redirect vulnerabilities",
                "→ PIVOT: Test for Template Injection (SSTI)",
                "→ PIVOT: Test for DOM-based XSS (client-side)"
            ])
        
        if waf_blocks:
            print(f"{Y}[!] WAF detected - requests blocked (403/406/413){NC}")
            suggestions.extend([
                "→ PIVOT: Test rate limits and DoS resistance",
                "→ PIVOT: Test for Information Disclosure (headers, error pages)",
                "→ PIVOT: Test for Authentication bypass",
                "→ PIVOT: Test for Business Logic flaws (not signature-based)"
            ])
        
        if rate_limits:
            print(f"{Y}[!] Rate limiting detected{NC}")
            suggestions.extend([
                "→ PIVOT: Test with slower request rate",
                "→ PIVOT: Test for race conditions",
                "→ PIVOT: Focus on authenticated endpoints (may have higher limits)"
            ])
        
        if suggestions:
            print(f"\n{C}[*] SUGGESTED PIVOTS:{NC}")
            for suggestion in set(suggestions):  # Remove duplicates
                print(f"  {suggestion}")
        else:
            print(f"{Y}[!] Generic pivot suggestions:{NC}")
            print(f"  → Perform reconnaissance: Directory discovery, API enumeration")
            print(f"  → Test authentication mechanisms")
            print(f"  → Test for information disclosure")
            print(f"  → Test for business logic vulnerabilities")
    
    def generate_report(self):
        """Generate tactical assessment report"""
        print(f"\n{B}{'='*60}{NC}")
        print(f"{B}[*] TACTICAL ASSESSMENT REPORT{NC}")
        print(f"{B}{'='*60}{NC}\n")
        
        print(f"{C}[*] Target: {self.target}{NC}")
        print(f"{C}[*] Successful Vectors: {len(self.successful_vectors)}{NC}")
        print(f"{C}[*] Failed Vectors: {len(self.failed_vectors)}{NC}")
        print(f"{C}[*] Observations: {len(self.observations)}{NC}\n")
        
        if self.successful_vectors:
            print(f"{G}[+] SUCCESSFUL FINDINGS:{NC}")
            for success in self.successful_vectors:
                print(f"  - {success['vector']}: {success['details']}")
        
        if self.failed_vectors:
            print(f"\n{R}[-] FAILED ATTEMPTS:{NC}")
            for failure in self.failed_vectors:
                print(f"  - {failure['vector']}: {failure['reason']}")
        
        if self.observations:
            print(f"\n{C}[*] OBSERVATIONS:{NC}")
            for obs in self.observations:
                print(f"  - {obs}")
        
        self.suggest_pivot()

def test_vector(assessment, vector_name, test_func):
    """Test a vector with failure detection"""
    print(f"\n{B}[*] Testing: {vector_name}{NC}")
    
    try:
        result = test_func()
        if result:
            assessment.log_success(vector_name, result)
            return True
        else:
            assessment.log_failure(vector_name, "No vulnerability detected")
            return False
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if hasattr(e, 'response') else None
        assessment.log_failure(vector_name, f"HTTP Error: {e}", status_code)
        return False
    except Exception as e:
        assessment.log_failure(vector_name, f"Exception: {e}")
        return False

# Example usage
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{R}[!] Usage: {sys.argv[0]} <target_url>{NC}")
        sys.exit(1)
    
    target = sys.argv[1]
    assessment = TacticalAssessment(target)
    
    print(f"{B}[*] MOBILESEC STRATEGIC ADAPTATION LAYER{NC}")
    print(f"{B}[*] Target: {target}{NC}\n")
    
    # Example: Test SQL injection
    def test_sqli():
        """Example SQL injection test"""
        payload = "' OR '1'='1"
        r = requests.get(f"{target}?id={payload}", timeout=5, verify=False)
        
        if r.status_code == 403:
            raise requests.exceptions.HTTPError("WAF Blocked")
        
        error_indicators = ['sql syntax', 'mysql', 'database error']
        if any(ind in r.text.lower() for ind in error_indicators):
            return "Potential SQL injection detected"
        return None
    
    # Run test
    test_vector(assessment, "SQL Injection", test_sqli)
    
    # Generate report
    assessment.generate_report()

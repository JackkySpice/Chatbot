#!/bin/bash
# One-Shot Termux Payload: Rate Limit & DoS Resistance Tester
# TACTICAL ASSESSMENT: Previous WAF bypass failed. Switching to rate-limit testing.
# PROTOCOL: Test rate limiting and DoS resistance

# 1. Setup Environment
echo "[*] Initializing MobileSec..."
pkg update -y > /dev/null 2>&1 && pkg install python -y > /dev/null 2>&1
pip install requests --disable-pip-version-check > /dev/null 2>&1

# 2. Create Payload (Heredoc)
cat << 'EOF' > exploit.py
import requests
import sys
import time
from datetime import datetime

# ANSI Colors
R = "\x1b[1;31m"
G = "\x1b[1;32m"
Y = "\x1b[1;33m"
B = "\x1b[1;34m"
C = "\x1b[1;36m"
NC = "\x1b[0m"

TARGET = input(f"{B}[?] Enter target URL: {NC}").strip()
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

def run_audit():
    print(f"{B}[*] ENGAGING TARGET: {TARGET}{NC}")
    print(f"{B}[*] PROTOCOL: ACTIVE LIVE FIRE - Rate Limit Testing{NC}\n")
    
    # Test parameters
    request_count = 50
    delay_between_requests = 0.1  # seconds
    
    print(f"{C}[*] Configuration:{NC}")
    print(f"  Requests: {request_count}")
    print(f"  Delay: {delay_between_requests}s between requests")
    print(f"  Total duration: ~{request_count * delay_between_requests:.1f}s\n")
    
    results = {
        'success': 0,
        'rate_limited': 0,
        'server_errors': 0,
        'timeouts': 0,
        'other_errors': 0,
        'status_codes': {},
        'response_times': []
    }
    
    rate_limit_detected_at = None
    start_time = time.time()
    
    try:
        for i in range(1, request_count + 1):
            request_start = time.time()
            
            try:
                # REAL NETWORK CALL - NO MOCKING
                r = requests.get(TARGET, headers={'User-Agent': UA}, 
                               timeout=5, verify=False, allow_redirects=False)
                
                response_time = time.time() - request_start
                results['response_times'].append(response_time)
                
                status = r.status_code
                results['status_codes'][status] = results['status_codes'].get(status, 0) + 1
                
                # Analyze response
                if status == 200:
                    results['success'] += 1
                    if i % 10 == 0:
                        print(f"{G}[+] Request {i}/{request_count}: OK (Status: {status}, Time: {response_time:.2f}s){NC}")
                elif status == 429:
                    results['rate_limited'] += 1
                    if not rate_limit_detected_at:
                        rate_limit_detected_at = i
                        print(f"{R}[!] RATE LIMIT DETECTED at request #{i}{NC}")
                        print(f"    Status: {status}")
                        print(f"    Response: {r.text[:200]}...")
                        
                        # Check for rate limit headers
                        if 'Retry-After' in r.headers:
                            print(f"    Retry-After: {r.headers['Retry-After']} seconds")
                        if 'X-RateLimit-Limit' in r.headers:
                            print(f"    Rate Limit: {r.headers.get('X-RateLimit-Limit')} requests")
                        if 'X-RateLimit-Remaining' in r.headers:
                            print(f"    Remaining: {r.headers.get('X-RateLimit-Remaining')} requests")
                elif status >= 500:
                    results['server_errors'] += 1
                    if i <= 5:  # Only show first few
                        print(f"{Y}[!] Request {i}: Server Error (Status: {status}){NC}")
                elif status == 403:
                    results['other_errors'] += 1
                    if i <= 5:
                        print(f"{Y}[!] Request {i}: Forbidden (Status: {status}){NC}")
                else:
                    if i <= 5:
                        print(f"{C}[*] Request {i}: Status {status}{NC}")
                
            except requests.exceptions.Timeout:
                results['timeouts'] += 1
                if i <= 5:
                    print(f"{R}[!] Request {i}: Timeout{NC}")
            except requests.exceptions.ConnectionError:
                results['other_errors'] += 1
                print(f"{R}[!] Request {i}: Connection Error - Stopping test{NC}")
                break
            except Exception as e:
                results['other_errors'] += 1
                if i <= 5:
                    print(f"{R}[!] Request {i}: Error - {e}{NC}")
            
            # Rate limiting delay
            time.sleep(delay_between_requests)
        
        total_time = time.time() - start_time
        
        # Calculate statistics
        avg_response_time = sum(results['response_times']) / len(results['response_times']) if results['response_times'] else 0
        min_response_time = min(results['response_times']) if results['response_times'] else 0
        max_response_time = max(results['response_times']) if results['response_times'] else 0
        
        # Print summary
        print(f"\n{B}{'='*60}{NC}")
        print(f"{B}[*] RATE LIMIT TEST SUMMARY{NC}")
        print(f"{B}{'='*60}{NC}\n")
        
        print(f"{C}[*] Test Statistics:{NC}")
        print(f"  Total Requests: {request_count}")
        print(f"  Total Time: {total_time:.2f}s")
        print(f"  Requests/sec: {request_count/total_time:.2f}\n")
        
        print(f"{C}[*] Response Statistics:{NC}")
        print(f"  {G}Successful (200): {results['success']}{NC}")
        print(f"  {R}Rate Limited (429): {results['rate_limited']}{NC}")
        print(f"  {Y}Server Errors (5xx): {results['server_errors']}{NC}")
        print(f"  {R}Timeouts: {results['timeouts']}{NC}")
        print(f"  {Y}Other Errors: {results['other_errors']}{NC}\n")
        
        if results['response_times']:
            print(f"{C}[*] Response Time Statistics:{NC}")
            print(f"  Average: {avg_response_time:.3f}s")
            print(f"  Minimum: {min_response_time:.3f}s")
            print(f"  Maximum: {max_response_time:.3f}s\n")
        
        print(f"{C}[*] Status Code Distribution:{NC}")
        for status, count in sorted(results['status_codes'].items()):
            color = G if status == 200 else Y if status == 429 else R
            print(f"  {color}{status}: {count}{NC}")
        
        # Security assessment
        print(f"\n{B}[*] SECURITY ASSESSMENT:{NC}")
        if rate_limit_detected_at:
            print(f"{Y}[!] Rate limiting is ACTIVE{NC}")
            print(f"    First detected at request #{rate_limit_detected_at}")
            print(f"    Recommendation: Implement slower request rate or use distributed testing")
        else:
            print(f"{R}[!] NO RATE LIMITING DETECTED{NC}")
            print(f"    Recommendation: Implement rate limiting to prevent DoS attacks")
        
        if results['success'] == request_count:
            print(f"{R}[!] All requests succeeded - potential DoS vulnerability{NC}")
        
        if avg_response_time > 2.0:
            print(f"{Y}[!] High average response time ({avg_response_time:.2f}s) - may indicate resource exhaustion{NC}")
        
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Test interrupted by user{NC}")
    except Exception as e:
        print(f"{R}[!] EXECUTION FAILED: {e}{NC}")

if __name__ == "__main__":
    run_audit()
EOF

# 3. Execute
python exploit.py

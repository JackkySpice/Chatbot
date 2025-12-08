#!/usr/bin/env python3
"""
BestChange.com Continuous Monitoring
Long-running monitoring and testing
"""

import requests
import time
import random
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class ContinuousMonitor:
    def __init__(self, base_url="https://www.bestchange.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        self.start_time = time.time()
        self.setup_session()
    
    def setup_session(self):
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.session.timeout = 10
    
    def monitor_continuously(self, duration_minutes=10):
        """Monitor continuously for specified duration"""
        print(f"{Colors.BLUE}[*] Starting continuous monitoring for {duration_minutes} minutes...{Colors.RESET}")
        
        end_time = time.time() + (duration_minutes * 60)
        request_count = 0
        
        while time.time() < end_time:
            try:
                # Test various endpoints
                endpoints = [
                    f'{self.base_url}/',
                    f'{self.base_url}/index.php',
                    f'{self.base_url}/click.php?id=1&from=10&to=58&city=0',
                ]
                
                for endpoint in endpoints:
                    try:
                        response = self.session.get(endpoint, timeout=5)
                        request_count += 1
                        
                        # Check for changes
                        if response.status_code not in [200, 301, 302, 429]:
                            self.findings.append({
                                'time': datetime.now().isoformat(),
                                'endpoint': endpoint,
                                'status': response.status_code,
                            })
                            print(f"{Colors.YELLOW}[!] Unusual status {response.status_code} on {endpoint}{Colors.RESET}")
                        
                        time.sleep(0.5)
                    except:
                        continue
                
                # Status update every minute
                elapsed = time.time() - self.start_time
                if int(elapsed) % 60 == 0:
                    print(f"{Colors.CYAN}[*] Monitoring... {int(elapsed/60)} minutes, {request_count} requests{Colors.RESET}")
                
            except KeyboardInterrupt:
                break
            except:
                continue
        
        print(f"{Colors.GREEN}[+] Monitoring completed: {request_count} requests{Colors.RESET}")

def main():
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}")
    print(f"{Colors.BLUE}BestChange.com Continuous Monitoring{Colors.RESET}")
    print(f"{Colors.BLUE}{'='*70}{Colors.RESET}\n")
    
    monitor = ContinuousMonitor()
    monitor.monitor_continuously(duration_minutes=5)

if __name__ == "__main__":
    main()

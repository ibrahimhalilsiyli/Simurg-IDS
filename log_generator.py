#!/usr/bin/env python3
"""
Simurg IDS — Attack Simulator / Log Generator
Generates realistic attack logs for testing detection rules.
"""

import time
import random
import os

LOG_FILE = "access.log"

ATTACK_TEMPLATES = [
    # SQL Injection
    '192.168.1.{ip} - - [{ts}] "GET /api/user?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 452',
    '192.168.1.{ip} - - [{ts}] "GET /products.php?category=electronics%27%20OR%201=1-- HTTP/1.1" 200 2130',
    
    # XSS
    '192.168.1.{ip} - - [{ts}] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 843',
    
    # Directory Traversal
    '192.168.1.{ip} - - [{ts}] "GET /../../../../etc/passwd HTTP/1.1" 403 150',
    '192.168.1.{ip} - - [{ts}] "GET /static/../../windows/win.ini HTTP/1.1" 403 150',
    
    # Sensitive Files
    '192.168.1.{ip} - - [{ts}] "GET /.env HTTP/1.1" 404 210',
    '192.168.1.{ip} - - [{ts}] "GET /.git/config HTTP/1.1" 404 210',
    
    # Scanners
    '192.168.1.{ip} - - [{ts}] "GET /phpmyadmin/index.php HTTP/1.1" 404 180',
    
    # Normal Traffic
    '192.168.1.{ip} - - [{ts}] "GET /index.html HTTP/1.1" 200 4500',
    '192.168.1.{ip} - - [{ts}] "GET /styles.css HTTP/1.1" 200 1200',
    '192.168.1.{ip} - - [{ts}] "GET /logo.png HTTP/1.1" 200 35000',
]

def generate_timestamp():
    return time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())

def main():
    print(f"\n[*] Starting Attack Simulator (generating to {LOG_FILE})...")
    print("[*] Press Ctrl+C to stop.\n")
    
    try:
        while True:
            ip = random.randint(100, 200)
            ts = generate_timestamp()
            template = random.choice(ATTACK_TEMPLATES)
            log_line = template.format(ip=ip, ts=ts)
            
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
            
            print(f"[+] Logged: {log_line}")
            time.sleep(random.uniform(0.5, 2.0))
            
    except KeyboardInterrupt:
        print("\n[*] Simulator stopped.")

if __name__ == "__main__":
    main()

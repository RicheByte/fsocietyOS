#!/usr/bin/env python3
"""
ICMP Ping Sweeper
A tool to quickly identify live hosts on a network by sending ICMP echo requests.
"""

import subprocess
import sys
import threading
import platform
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def run():
    print("\033[92m" + "="*70)
    print("           ICMP PING SWEEPER - Live Host Discovery")
    print("="*70 + "\033[0m\n")
    
    print("\033[97m[*] Scan Options:\033[0m")
    print("  [1] Single host")
    print("  [2] IP range (e.g., 192.168.1.1-254)")
    print("  [3] CIDR notation (e.g., 192.168.1.0/24)")
    print("  [4] Custom list of IPs")
    
    choice = input("\n\033[95m[?] Select option: \033[0m").strip()
    
    hosts_to_scan = []
    
    if choice == '1':
        host = input("\033[97m[?] Enter IP address or hostname: \033[0m").strip()
        if host:
            hosts_to_scan = [host]
    
    elif choice == '2':
        network = input("\033[97m[?] Enter IP range (e.g., 192.168.1.1-254): \033[0m").strip()
        try:
            if '-' in network:
                base_ip, range_part = network.rsplit('.', 1)
                if '-' in range_part:
                    start, end = range_part.split('-')
                    for i in range(int(start), int(end) + 1):
                        hosts_to_scan.append(f"{base_ip}.{i}")
                else:
                    print("\033[91m[!] Invalid range format.\033[0m")
                    return
        except Exception as e:
            print(f"\033[91m[!] Error parsing range: {str(e)}\033[0m")
            return
    
    elif choice == '3':
        network = input("\033[97m[?] Enter CIDR (e.g., 192.168.1.0/24): \033[0m").strip()
        try:
            import ipaddress
            net = ipaddress.ip_network(network, strict=False)
            hosts_to_scan = [str(ip) for ip in net.hosts()]
            
            if len(hosts_to_scan) > 1000:
                confirm = input(f"\033[93m[!] This will scan {len(hosts_to_scan)} hosts. Continue? (y/n): \033[0m").strip().lower()
                if confirm != 'y':
                    return
        except Exception as e:
            print(f"\033[91m[!] Invalid CIDR format: {str(e)}\033[0m")
            return
    
    elif choice == '4':
        print("\033[97m[*] Enter IP addresses (one per line, empty line to finish):\033[0m")
        while True:
            ip = input("  ").strip()
            if not ip:
                break
            hosts_to_scan.append(ip)
    
    else:
        print("\033[91m[!] Invalid choice.\033[0m")
        return
    
    if not hosts_to_scan:
        print("\033[91m[!] No hosts to scan.\033[0m")
        return
    
    threads_num = input(f"\033[97m[?] Number of threads (1-200, default 100): \033[0m").strip()
    threads_num = int(threads_num) if threads_num.isdigit() and 1 <= int(threads_num) <= 200 else 100
    
    alive_hosts = []
    scanned_count = [0]
    lock = threading.Lock()
    
    def ping_host(ip):
        """Ping a single host using system ping command"""
        try:
            # Different ping command for Windows vs Unix
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            
            with lock:
                scanned_count[0] += 1
                progress = (scanned_count[0] / len(hosts_to_scan)) * 100
                print(f"\r\033[97m[*] Progress: {scanned_count[0]}/{len(hosts_to_scan)} ({progress:.1f}%)\033[0m", end='', flush=True)
            
            if result.returncode == 0:
                # Try to get hostname
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = ""
                
                with lock:
                    alive_hosts.append((ip, hostname))
                    print(f"\n\033[92m[+] {ip:<15} is alive {('(' + hostname + ')') if hostname else ''}\033[0m", end='')
                
                return True
            return False
        
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    print(f"\n\033[92m[*] Scanning {len(hosts_to_scan)} hosts with {threads_num} threads...\033[0m")
    print("\033[93m[*] This may take a while...\033[0m\n")
    
    # Scan hosts using thread pool
    with ThreadPoolExecutor(max_workers=threads_num) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts_to_scan}
        for future in as_completed(futures):
            future.result()
    
    print("\n")
    
    # Summary
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m[*] Ping Sweep Summary\033[0m")
    print(f"\033[92m{'='*70}\033[0m\n")
    
    print(f"\033[97m[*] Total hosts scanned: {len(hosts_to_scan)}\033[0m")
    print(f"\033[92m[*] Alive hosts found: {len(alive_hosts)}\033[0m")
    print(f"\033[91m[*] Dead hosts: {len(hosts_to_scan) - len(alive_hosts)}\033[0m\n")
    
    if alive_hosts:
        print(f"\033[92m[+] Live Hosts:\033[0m\n")
        for ip, hostname in sorted(alive_hosts):
            if hostname:
                print(f"    \033[97m{ip:<15} -> {hostname}\033[0m")
            else:
                print(f"    \033[97m{ip}\033[0m")
        
        # Offer to save results
        save = input(f"\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[97m[?] Enter filename (default: alive_hosts.txt): \033[0m").strip() or "alive_hosts.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"Ping Sweep Results\n")
                    f.write(f"{'='*70}\n")
                    f.write(f"Scanned: {len(hosts_to_scan)} hosts\n")
                    f.write(f"Alive: {len(alive_hosts)} hosts\n\n")
                    for ip, hostname in sorted(alive_hosts):
                        if hostname:
                            f.write(f"{ip:<15} -> {hostname}\n")
                        else:
                            f.write(f"{ip}\n")
                print(f"\033[92m[*] Results saved to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Error saving file: {str(e)}\033[0m")
    else:
        print("\033[93m[!] No alive hosts found.\033[0m")
    
    print(f"\n\033[92m[*] Scan completed!\033[0m")

if __name__ == "__main__":
    run()

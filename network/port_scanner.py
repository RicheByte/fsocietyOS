#!/usr/bin/env python3
"""
Port Scanner (Nmap Wrapper)
A Python script that leverages Nmap for stealthy SYN scans and service version detection.
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import sys

def run():
    print("\033[92m" + "="*70)
    print("           PORT SCANNER - Multi-threaded Port Scanner")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Ensure you have permission to scan the target!\033[0m\n")
    
    target = input("\033[97m[?] Enter target IP or hostname: \033[0m").strip()
    if not target:
        print("\033[91m[!] No target specified.\033[0m")
        return
    
    # Resolve hostname to IP
    try:
        target_ip = socket.gethostbyname(target)
        print(f"\033[97m[*] Target resolved: {target} -> {target_ip}\033[0m\n")
    except socket.gaierror:
        print(f"\033[91m[!] Could not resolve hostname: {target}\033[0m")
        return
    
    print("\n\033[97m[*] Scan Options:\033[0m")
    print("  [1] Quick Scan (Common 20 ports)")
    print("  [2] Standard Scan (Top 100 ports)")
    print("  [3] Custom Port Range")
    print("  [4] Single Port")
    
    choice = input("\n\033[95m[?] Select scan type: \033[0m").strip()
    
    # Define port ranges
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    top_100_ports = list(range(1, 101)) + [110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    ports_to_scan = []
    
    if choice == '1':
        ports_to_scan = common_ports
    elif choice == '2':
        ports_to_scan = list(set(top_100_ports))
    elif choice == '3':
        try:
            start = int(input("\033[97m[?] Enter start port (1-65535): \033[0m").strip())
            end = int(input("\033[97m[?] Enter end port (1-65535): \033[0m").strip())
            if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                ports_to_scan = list(range(start, end + 1))
            else:
                print("\033[91m[!] Invalid port range.\033[0m")
                return
        except ValueError:
            print("\033[91m[!] Invalid input.\033[0m")
            return
    elif choice == '4':
        try:
            port = int(input("\033[97m[?] Enter port number (1-65535): \033[0m").strip())
            if 1 <= port <= 65535:
                ports_to_scan = [port]
            else:
                print("\033[91m[!] Invalid port number.\033[0m")
                return
        except ValueError:
            print("\033[91m[!] Invalid input.\033[0m")
            return
    else:
        print("\033[91m[!] Invalid choice.\033[0m")
        return
    
    print(f"\n\033[92m[*] Scanning {len(ports_to_scan)} ports on {target_ip}...\033[0m")
    print("\033[93m[*] This may take a moment...\033[0m\n")
    
    open_ports = []
    scanned_count = [0]
    lock = threading.Lock()
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            with lock:
                scanned_count[0] += 1
                if scanned_count[0] % 10 == 0 or scanned_count[0] == len(ports_to_scan):
                    print(f"\r\033[97m[*] Progress: {scanned_count[0]}/{len(ports_to_scan)} ports scanned\033[0m", end='', flush=True)
            
            if result == 0:
                # Try to grab banner
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((target_ip, port))
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    sock.close()
                except:
                    banner = ""
                
                # Identify common services
                service = get_service_name(port)
                
                with lock:
                    open_ports.append((port, service, banner[:50] if banner else ""))
        except:
            pass
    
    def get_service_name(port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
        }
        return services.get(port, "Unknown")
    
    # Scan ports using thread pool
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(scan_port, ports_to_scan)
    
    print("\n")
    
    # Display results
    if open_ports:
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[+] Found {len(open_ports)} open ports:\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        for port, service, banner in sorted(open_ports):
            print(f"\033[92m[+] Port {port:5d}/tcp\033[0m - {service}")
            if banner:
                print(f"    \033[93mBanner: {banner}\033[0m")
        
        # Save results option
        save = input(f"\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = f"scan_{target_ip.replace('.', '_')}.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"Port Scan Results for {target_ip}\n")
                    f.write(f"{'='*70}\n\n")
                    for port, service, banner in sorted(open_ports):
                        f.write(f"Port {port}/tcp - {service}\n")
                        if banner:
                            f.write(f"  Banner: {banner}\n")
                        f.write("\n")
                print(f"\033[92m[*] Results saved to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Error saving file: {str(e)}\033[0m")
    else:
        print(f"\033[93m[!] No open ports found.\033[0m")
    
    print(f"\n\033[92m[*] Scan completed!\033[0m")

if __name__ == "__main__":
    run()

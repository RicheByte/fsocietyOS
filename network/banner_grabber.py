#!/usr/bin/env python3
"""
Banner Grabbing Tool
A script that connects to network services on open ports to retrieve version information.
"""

import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

def run():
    print("\033[92m" + "="*70)
    print("           BANNER GRABBING TOOL - Service Fingerprinting")
    print("="*70 + "\033[0m\n")
    
    target = input("\033[97m[?] Enter target IP/hostname: \033[0m").strip()
    if not target:
        print("\033[91m[!] No target specified.\033[0m")
        return
    
    # Resolve hostname
    try:
        target_ip = socket.gethostbyname(target)
        print(f"\033[97m[*] Target resolved: {target} -> {target_ip}\033[0m\n")
    except socket.gaierror:
        print(f"\033[91m[!] Could not resolve hostname: {target}\033[0m")
        return
    
    print("\n\033[97m[*] Options:\033[0m")
    print("  [1] Single port")
    print("  [2] Multiple ports")
    print("  [3] Common service ports")
    print("  [4] All ports (1-1024)")
    
    choice = input("\n\033[95m[?] Select option: \033[0m").strip()
    
    ports = []
    
    if choice == '1':
        port = input("\033[97m[?] Enter port number: \033[0m").strip()
        if port.isdigit():
            ports = [int(port)]
        else:
            print("\033[91m[!] Invalid port number.\033[0m")
            return
    
    elif choice == '2':
        port_input = input("\033[97m[?] Enter ports (comma-separated, e.g., 80,443,8080): \033[0m").strip()
        try:
            ports = [int(p.strip()) for p in port_input.split(',') if p.strip().isdigit()]
        except:
            print("\033[91m[!] Invalid port format.\033[0m")
            return
    
    elif choice == '3':
        # Common service ports with descriptions
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443]
        print(f"\033[97m[*] Scanning {len(ports)} common ports\033[0m")
    
    elif choice == '4':
        ports = list(range(1, 1025))
        print(f"\033[97m[*] Scanning ports 1-1024\033[0m")
    
    else:
        print("\033[91m[!] Invalid choice.\033[0m")
        return
    
    if not ports:
        print("\033[91m[!] No valid ports specified.\033[0m")
        return
    
    timeout = 3
    results = []
    scanned = [0]
    lock = threading.Lock()
    
    # Service name database
    service_names = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS-SSN",
        143: "IMAP", 443: "HTTPS", 445: "Microsoft-DS", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }
    
    def grab_banner(ip, port):
        try:
            # Check if port is open first
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            
            with lock:
                scanned[0] += 1
                if len(ports) > 10 and scanned[0] % 10 == 0:
                    print(f"\r\033[97m[*] Scanning... {scanned[0]}/{len(ports)}\033[0m", end='', flush=True)
            
            if result != 0:
                sock.close()
                return None
            
            sock.close()
            
            # Port is open, try to grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            banner = ""
            service = service_names.get(port, "Unknown")
            
            # Send appropriate probe based on port
            try:
                if port in [80, 8080, 8000, 8443]:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif port == 21:  # FTP
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif port == 22:  # SSH
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif port == 25:  # SMTP
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif port == 110:  # POP3
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                elif port == 143:  # IMAP
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                else:
                    # Generic probe
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if not banner:
                        sock.send(b'\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                banner = "[No response to probe]"
            
            sock.close()
            
            return (port, service, banner if banner else "[Port open, no banner]")
        
        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            return None
    
    print(f"\n\033[92m[*] Grabbing banners from {target_ip}...\033[0m\n")
    
    # Use thread pool for faster scanning
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_results = list(executor.map(lambda p: grab_banner(target_ip, p), ports))
    
    # Filter out None results
    results = [r for r in future_results if r is not None]
    
    if len(ports) > 10:
        print("\n")
    
    # Display results
    if results:
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[+] Found {len(results)} open ports with banners:\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        for port, service, banner in sorted(results):
            print(f"\033[92m[+] Port {port:5d}/tcp\033[0m - {service}")
            
            # Pretty print banner
            if banner:
                lines = banner.split('\n')
                first_line = lines[0][:100]
                print(f"    \033[93m{first_line}\033[0m")
                
                # Show additional lines if available
                if len(lines) > 1:
                    for line in lines[1:3]:  # Show up to 2 more lines
                        if line.strip():
                            print(f"    \033[90m{line[:100]}\033[0m")
            print()
        
        # Save results option
        save = input(f"\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = f"banners_{target_ip.replace('.', '_')}.txt"
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Banner Grabbing Results for {target_ip}\n")
                    f.write(f"{'='*70}\n\n")
                    for port, service, banner in sorted(results):
                        f.write(f"Port {port}/tcp - {service}\n")
                        f.write(f"Banner:\n{banner}\n")
                        f.write(f"{'-'*70}\n\n")
                print(f"\033[92m[*] Results saved to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Error saving file: {str(e)}\033[0m")
    else:
        print("\033[93m[!] No open ports found or no banners received.\033[0m")
    
    print(f"\n\033[92m[*] Banner grabbing completed!\033[0m")

if __name__ == "__main__":
    run()

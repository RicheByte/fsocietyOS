#!/usr/bin/env python3
"""
NetBIOS Name Resolver
A tool for enumerating Windows hosts, shares, and users on a local network.
"""

import sys
import subprocess
import platform
import socket

def run():
    print("\033[92m" + "="*70)
    print("           NetBIOS NAME RESOLVER - Windows Network Enumeration")
    print("="*70 + "\033[0m\n")
    
    print("\033[97m[*] This tool enumerates Windows hosts using NetBIOS\033[0m\n")
    
    print("\033[97m[*] Options:\033[0m")
    print("  [1] Enumerate single host")
    print("  [2] Enumerate network range")
    print("  [3] List local NetBIOS names")
    print("  [4] SMB Share enumeration")
    
    choice = input("\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        target = input("\033[97m[?] Enter target IP/hostname: \033[0m").strip()
        if not target:
            print("\033[91m[!] No target specified.\033[0m")
            return
        
        print(f"\n\033[92m[*] Enumerating {target}...\033[0m\n")
        
        # Using nmblookup (Linux/Mac) or nbtstat (Windows)
        if platform.system() == "Windows":
            cmd = f"nbtstat -A {target}"
            print(f"\033[97m[*] Running: {cmd}\033[0m\n")
        else:
            cmd = f"nmblookup -A {target}"
            print(f"\033[97m[*] Running: {cmd}\033[0m\n")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.stdout:
                print(result.stdout)
                
                # Parse and format output
                if "No reply" in result.stdout or "failed" in result.stdout.lower():
                    print("\033[93m[!] No NetBIOS response from target\033[0m")
            if result.stderr:
                print(f"\033[93m{result.stderr}\033[0m")
        except subprocess.TimeoutExpired:
            print("\033[91m[!] Command timeout.\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    elif choice == '2':
        network = input("\033[97m[?] Enter network range (e.g., 192.168.1.1-20): \033[0m").strip()
        if not network:
            print("\033[91m[!] No network specified.\033[0m")
            return
        
        print(f"\n\033[92m[*] Scanning network {network}...\033[0m\n")
        
        hosts_to_scan = []
        try:
            if '-' in network:
                base_ip, range_part = network.rsplit('.', 1)
                start, end = range_part.split('-')
                hosts_to_scan = [f"{base_ip}.{i}" for i in range(int(start), int(end) + 1)]
            else:
                print("\033[91m[!] Invalid format. Use format like: 192.168.1.1-254\033[0m")
                return
        except:
            print("\033[91m[!] Invalid network range format.\033[0m")
            return
        
        found_hosts = []
        
        print(f"\033[97m[*] Scanning {len(hosts_to_scan)} hosts for NetBIOS...\033[0m\n")
        
        for i, ip in enumerate(hosts_to_scan, 1):
            try:
                print(f"\r\033[97m[*] Scanning {i}/{len(hosts_to_scan)}...\033[0m", end='', flush=True)
                
                if platform.system() == "Windows":
                    cmd = f"nbtstat -A {ip}"
                else:
                    cmd = f"nmblookup -A {ip}"
                
                result = subprocess.run(cmd, shell=True, capture_output=True, 
                                      text=True, timeout=2)
                
                if result.returncode == 0 and result.stdout:
                    # Check if we got a valid response
                    if "No reply" not in result.stdout and len(result.stdout) > 50:
                        found_hosts.append(ip)
                        print(f"\n\033[92m[+] Found NetBIOS host: {ip}\033[0m")
                        
                        # Try to get hostname
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                            print(f"    \033[97mHostname: {hostname}\033[0m")
                        except:
                            pass
                        
                        # Show NetBIOS names
                        lines = result.stdout.split('\n')[:5]
                        for line in lines:
                            if line.strip():
                                print(f"    \033[90m{line}\033[0m")
            
            except subprocess.TimeoutExpired:
                continue
            except:
                continue
        
        print("\n")
        
        if found_hosts:
            print(f"\n\033[92m[*] Found {len(found_hosts)} NetBIOS hosts\033[0m")
            for host in found_hosts:
                print(f"    \033[97m{host}\033[0m")
        else:
            print("\n\033[93m[!] No NetBIOS hosts found\033[0m")
    
    elif choice == '3':
        print(f"\n\033[92m[*] Listing local NetBIOS names...\033[0m\n")
        
        if platform.system() == "Windows":
            cmd = "nbtstat -n"
            print(f"\033[97m[*] Running: {cmd}\033[0m\n")
        else:
            print("\033[93m[!] This option is primarily for Windows systems\033[0m")
            cmd = "nmblookup -S '*'"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(f"\033[93m{result.stderr}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    elif choice == '4':
        target = input("\033[97m[?] Enter target IP/hostname: \033[0m").strip()
        if not target:
            print("\033[91m[!] No target specified.\033[0m")
            return
        
        print(f"\n\033[92m[*] Enumerating SMB shares on {target}...\033[0m\n")
        
        # Try using net view on Windows, smbclient on Linux
        if platform.system() == "Windows":
            cmd = f"net view \\\\{target}"
            print(f"\033[97m[*] Running: {cmd}\033[0m\n")
        else:
            cmd = f"smbclient -L //{target} -N"
            print(f"\033[97m[*] Running: {cmd}\033[0m\n")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.stdout:
                print(result.stdout)
            if result.stderr and "error" not in result.stderr.lower():
                print(result.stderr)
            
            if result.returncode != 0:
                print("\033[93m[!] Could not enumerate shares. Target may require authentication.\033[0m")
        except subprocess.TimeoutExpired:
            print("\033[91m[!] Command timeout.\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    else:
        print("\033[91m[!] Invalid choice.\033[0m")

if __name__ == "__main__":
    run()

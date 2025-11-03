#!/usr/bin/env python3
"""
Vulnerability Scanner Integrator
A script that automates network vulnerability scanning by integrating with tools like OpenVAS.
"""

import subprocess
import sys

def run():
    print("\033[92m" + "="*70)
    print("           VULNERABILITY SCANNER INTEGRATOR")
    print("="*70 + "\033[0m\n")
    
    print("\033[97m[*] This tool integrates with external vulnerability scanners\033[0m\n")
    
    print("\033[97m[*] Scanner Options:\033[0m")
    print("  [1] OpenVAS/GVM Scanner")
    print("  [2] Nmap Vulnerability Scripts (NSE)")
    print("  [3] Nikto Web Server Scanner")
    print("  [4] Custom Script Scanner")
    
    choice = input("\n\033[95m[?] Select scanner: \033[0m").strip()
    
    target = input("\033[97m[?] Enter target IP/hostname: \033[0m").strip()
    if not target:
        print("\033[91m[!] No target specified.\033[0m")
        return
    
    if choice == '1':
        print(f"\n\033[92m[*] OpenVAS/GVM Scanner\033[0m")
        print("\033[93m[!] Note: This requires OpenVAS/GVM to be installed and configured\033[0m")
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            print("\033[97m[*] Connecting to GVM...\033[0m")
            # This is a placeholder - actual implementation requires proper GVM setup
            print("\033[93m[!] Please configure GVM connection settings in the script\033[0m")
            
        except ImportError:
            print("\033[91m[!] python-gvm library not found.\033[0m")
            print("\033[97m[*] Install it with: pip install python-gvm\033[0m")
    
    elif choice == '2':
        print(f"\n\033[92m[*] Running Nmap Vulnerability Scripts against {target}...\033[0m\n")
        
        cmd = f"nmap -sV --script vuln {target}"
        print(f"\033[97m[*] Command: {cmd}\033[0m\n")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(f"\033[91m{result.stderr}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    elif choice == '3':
        print(f"\n\033[92m[*] Running Nikto against {target}...\033[0m\n")
        
        port = input("\033[97m[?] Enter port (default 80): \033[0m").strip() or "80"
        cmd = f"nikto -h {target} -p {port}"
        print(f"\033[97m[*] Command: {cmd}\033[0m\n")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(f"\033[91m{result.stderr}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    elif choice == '4':
        print(f"\n\033[92m[*] Custom Script Scanner\033[0m")
        script_path = input("\033[97m[?] Enter path to custom scanner script: \033[0m").strip()
        
        if script_path:
            try:
                cmd = f"python {script_path} {target}"
                print(f"\033[97m[*] Running: {cmd}\033[0m\n")
                subprocess.run(cmd, shell=True)
            except Exception as e:
                print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    else:
        print("\033[91m[!] Invalid choice.\033[0m")

if __name__ == "__main__":
    run()

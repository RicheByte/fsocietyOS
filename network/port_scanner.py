#!/usr/bin/env python3
"""
Port Scanner (Real Nmap Wrapper)
A Python script that uses nmap for SYN scans, service version detection, and OS fingerprinting.
"""

import sys
import os
import socket
import nmap
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import (
    setup_logger, get_validated_input, validate_ip, validate_port,
    ScanResult, Finding, StealthController, get_session
)

# Actual Nmap Top 100 Ports (based on real-world frequency data)
NMAP_TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009,
    8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# Service name mapping
SERVICE_NAMES = {
    7: "echo", 9: "discard", 13: "daytime", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 26: "rsftp",
    37: "time", 53: "dns", 79: "finger", 80: "http", 81: "http-proxy", 88: "kerberos", 106: "poppassd",
    110: "pop3", 111: "rpc", 113: "auth", 119: "nntp", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 513: "rlogin", 514: "syslog", 515: "lprng", 543: "klogin",
    544: "kshell", 548: "afp", 554: "rtsp", 587: "smtp", 631: "ipp", 646: "ldp", 873: "rsync",
    990: "ftp-ssl", 993: "imaps", 995: "pop3s", 1025: "nfs", 1433: "mssql", 1720: "h323", 1723: "pptp",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5666: "nrpe", 5900: "vnc", 8080: "http-proxy",
    8443: "https-alt"
}


def run():
    logger = setup_logger("port_scanner")
    logger.info("Port Scanner started")
    
    print("\033[92m" + "="*70)
    print("           PORT SCANNER - Real Nmap Wrapper")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Ensure you have permission to scan the target!\033[0m\n")
    
    try:
        # Get target
        target = input("\033[97m[?] Enter target IP or hostname: \033[0m").strip()
        if not target:
            print("\033[91m[!] No target specified.\033[0m")
            return
        
        # Resolve hostname to IP
        try:
            target_ip = str(validate_ip(target))
            logger.info(f"Target IP: {target_ip}")
        except ValueError:
            # Try to resolve hostname
            try:
                target_ip = socket.gethostbyname(target)
                logger.info(f"Target resolved: {target} -> {target_ip}")
                print(f"\033[97m[*] Target resolved: {target} -> {target_ip}\033[0m\n")
            except socket.gaierror as e:
                logger.error(f"Could not resolve hostname: {target}")
                print(f"\033[91m[!] Could not resolve hostname: {target}\033[0m")
                return
        
        print("\n\033[97m[*] Scan Options:\033[0m")
        print("  [1] Quick Scan (Common 20 ports)")
        print("  [2] Standard Scan (Top 100 ports)")
        print("  [3] Full Scan (All ports)")
        print("  [4] Custom Port Range")
        print("  [5] Single Port")
        
        choice = input("\n\033[95m[?] Select scan type: \033[0m").strip()
        
        # Select ports
        ports_to_scan = ""
        if choice == '1':
            ports_to_scan = ",".join(map(str, COMMON_PORTS))
            logger.info(f"Quick scan: {len(COMMON_PORTS)} common ports")
        elif choice == '2':
            ports_to_scan = ",".join(map(str, NMAP_TOP_100_PORTS))
            logger.info(f"Standard scan: {len(NMAP_TOP_100_PORTS)} top ports")
        elif choice == '3':
            ports_to_scan = "1-65535"
            logger.warning("Full port scan selected - this will be very slow")
        elif choice == '4':
            start = get_validated_input("\033[97m[?] Enter start port: \033[0m", int, (1, 65535))
            end = get_validated_input("\033[97m[?] Enter end port: \033[0m", int, (start, 65535))
            ports_to_scan = f"{start}-{end}"
            logger.info(f"Custom range scan: {start}-{end}")
        elif choice == '5':
            port = get_validated_input("\033[97m[?] Enter port number: \033[0m", int, (1, 65535))
            ports_to_scan = str(port)
            logger.info(f"Single port scan: {port}")
        else:
            print("\033[91m[!] Invalid choice.\033[0m")
            logger.error("Invalid scan type choice")
            return
        
        # Ask for advanced options
        use_version_detection = input("\033[95m[?] Enable service version detection? (y/n): \033[0m").strip().lower() == 'y'
        use_os_detection = input("\033[95m[?] Enable OS detection? (y/n): \033[0m").strip().lower() == 'y'
        use_scripts = input("\033[95m[?] Enable NSE scripts? (y/n): \033[0m").strip().lower() == 'y'
        
        # Build nmap arguments
        nmap_args = "-sS"  # SYN scan (stealth)
        
        if use_version_detection:
            nmap_args += " -sV"
        if use_os_detection:
            nmap_args += " -O"
        if use_scripts:
            nmap_args += " --script=default"
        
        print(f"\n\033[92m[*] Scanning {target_ip} (ports: {ports_to_scan})...\033[0m")
        print("\033[93m[*] This may take a moment...\033[0m\n")
        
        # Perform scan
        start_time = time.time()
        
        try:
            nm = nmap.PortScanner()
            nm.scan(target_ip, ports=ports_to_scan, arguments=nmap_args)
            
        except nmap.PortScannerError as e:
            logger.error(f"Nmap error: {str(e)}")
            print(f"\033[91m[!] Nmap error: {str(e)}\033[0m")
            print("\033[91m[!] Make sure nmap is installed and you have proper permissions.\033[0m")
            return
        
        except Exception as e:
            logger.error(f"Unexpected error during scan: {str(e)}")
            print(f"\033[91m[!] Unexpected error: {str(e)}\033[0m")
            return
        
        scan_time = time.time() - start_time
        
        # Create result object
        result = ScanResult(
            tool="port_scanner",
            target=target_ip,
            execution_time=scan_time
        )
        
        # Process results
        open_ports = []
        
        if target_ip in nm.all_hosts():
            host = nm[target_ip]
            
            for protocol in host.all_protocols():
                for port in host[protocol].keys():
                    port_info = host[protocol][port]
                    state = port_info['state']
                    
                    if state == 'open':
                        service_name = SERVICE_NAMES.get(port, port_info.get('name', 'unknown'))
                        version = port_info.get('version', '')
                        
                        open_ports.append({
                            'port': port,
                            'service': service_name,
                            'version': version,
                            'state': state
                        })
                        
                        # Add to findings
                        result.add_finding_dict(
                            title=f"Open Port {port}/{protocol}",
                            description=f"Port {port} is open ({service_name})",
                            severity="INFO",
                            finding_type="open_port",
                            details={
                                'port': port,
                                'protocol': protocol,
                                'service': service_name,
                                'version': version,
                                'state': state
                            }
                        )
        
        # Display results
        if open_ports:
            print(f"\n\033[92m{'='*70}\033[0m")
            print(f"\033[92m[+] Found {len(open_ports)} open ports:\033[0m")
            print(f"\033[92m{'='*70}\033[0m\n")
            
            for port_info in sorted(open_ports, key=lambda x: x['port']):
                port = port_info['port']
                service = port_info['service']
                version = port_info['version']
                
                print(f"\033[92m[+] Port {port:5d}/tcp\033[0m - {service}")
                if version:
                    print(f"    \033[93mVersion: {version}\033[0m")
            
            logger.info(f"Found {len(open_ports)} open ports")
            
            # Save results option
            save = input(f"\n\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
            if save == 'y':
                filename = f"scan_{target_ip.replace('.', '_')}_{int(time.time())}.json"
                try:
                    result.save_to_file(filename)
                    print(f"\033[92m[*] Results saved to {filename}\033[0m")
                    logger.info(f"Results saved to {filename}")
                except Exception as e:
                    logger.error(f"Error saving results: {str(e)}")
                    print(f"\033[91m[!] Error saving file: {str(e)}\033[0m")
        else:
            print(f"\033[93m[!] No open ports found.\033[0m")
            result.status = "completed"
            logger.info("No open ports found")
        
        print(f"\n\033[92m[*] Scan completed in {scan_time:.2f} seconds!\033[0m")
        logger.info(f"Scan completed in {scan_time:.2f} seconds")
        
        return result

    except KeyboardInterrupt:
        print("\n\033[91m[!] Scan interrupted by user.\033[0m")
        logger.warning("Scan interrupted by user")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        print(f"\033[91m[!] Unexpected error: {str(e)}\033[0m")
        return None


if __name__ == "__main__":
    run()

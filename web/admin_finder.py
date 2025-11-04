#!/usr/bin/env python3
"""
Admin Interface Discovery Tool
Automated tool to find hidden administrative panels
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run():
    print("\033[92m" + "="*70)
    print("           ADMIN INTERFACE DISCOVERY TOOL")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only scan sites you own or have permission to test!\033[0m\n")
    
    # Comprehensive admin panel paths
    ADMIN_PATHS = [
        # Generic Admin Panels
        'admin', 'administrator', 'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
        'admin/', 'administrator/', 'admin1', 'admin2', 'admin3', 'admin4', 'admin5',
        'admins', 'admins/', 'administrat', 'adminarea', 'admin-area', 'admin_area',
        'admincontrol', 'admin-control', 'admin_control', 'admincp', 'admin-cp',
        'adminpanel', 'admin-panel', 'admin_panel', 'adm', 'adm/', 'adminhome',
        
        # Login Pages
        'login', 'login.php', 'login.html', 'login.asp', 'login.aspx', 'login/',
        'signin', 'sign-in', 'signin.php', 'user/login', 'users/login', 'auth',
        'authentication', 'authenticate', 'sso', 'session/new', 'accounts/login',
        
        # Dashboard & Control Panels
        'dashboard', 'dashboard.php', 'dashboard/', 'panel', 'panel.php', 'panel/',
        'controlpanel', 'control-panel', 'control_panel', 'cp', 'cpanel', 'cPanel',
        'webadmin', 'web-admin', 'web_admin', 'webmaster', 'master', 'console',
        
        # CMS Specific
        'wp-admin', 'wp-admin/', 'wp-login.php', 'wordpress/wp-admin', 'blog/wp-admin',
        'phpmyadmin', 'phpMyAdmin', 'pma', 'myadmin', 'mysql', 'dbadmin', 'database',
        'joomla/administrator', 'administrator/index.php', 'drupal/admin', 'typo3',
        
        # User Management
        'user', 'users', 'user.php', 'users.php', 'user/', 'users/', 'useradmin',
        'account', 'accounts', 'account.php', 'accounts.php', 'myaccount', 'profile',
        'member', 'members', 'membership', 'moderator', 'manage', 'management',
        
        # Backend & System
        'backend', 'back-end', 'backend.php', 'backend/', 'sys', 'system', 'system/',
        'sysadmin', 'sys-admin', 'systemadmin', 'admin/system', 'administration',
        'admin/admin', 'root', 'root.php', 'root/', 'superuser', 'supervisor',
        
        # Application Specific
        'app/admin', 'application/admin', 'admin/app', 'api/admin', 'v1/admin',
        'admin/login', 'admin/signin', 'admin/dashboard', 'admin/home', 'admin/index',
        'admin/index.php', 'admin/index.html', 'admin/main', 'admin/default',
        
        # Hidden/Secret
        'hidden', 'secret', 'private', 'restricted', 'secure', 'security',
        '_admin', '__admin', 'admin_', 'admin__', '.admin', 'admin.',
        'adminlogin', 'admin-login', 'admin_login', 'cadmin', 'cmsadmin',
        
        # Configuration & Settings
        'config', 'configuration', 'settings', 'preferences', 'setup', 'install',
        'admin/config', 'admin/configuration', 'admin/settings', 'admin/setup',
        
        # Mobile & Responsive
        'mobile/admin', 'm/admin', 'admin/mobile', 'admin-mobile', 'responsive/admin',
        
        # Development & Testing
        'dev', 'development', 'test', 'testing', 'stage', 'staging', 'demo',
        'admin/dev', 'admin/test', 'dev/admin', 'test/admin',
        
        # Localized
        'admin/en', 'admin/us', 'en/admin', 'us/admin', 'admin/cms', 'cms/admin',
        
        # Framework Specific
        'rails/admin', 'django/admin', 'laravel/admin', 'symfony/admin', 'admin/rails',
        'yii/admin', 'codeigniter/admin', 'zend/admin', 'cake/admin', 'spring/admin'
    ]
    
    target_url = input("\033[97m[?] Enter target URL (e.g., http://example.com): \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    target_url = target_url.rstrip('/')
    
    threads = input("\033[97m[?] Number of threads (default 30): \033[0m").strip()
    threads = int(threads) if threads.isdigit() else 30
    
    print(f"\n\033[92m[*] Scanning for admin panels...\033[0m")
    print(f"\033[97m[*] Target: {target_url}\033[0m")
    print(f"\033[97m[*] Paths to test: {len(ADMIN_PATHS)}\033[0m")
    print(f"\033[97m[*] Threads: {threads}\033[0m\n")
    
    found_panels = []
    tested = [0]
    lock = threading.Lock()
    
    def test_admin_path(path):
        """Test if admin path exists"""
        try:
            url = urljoin(target_url, path)
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            
            with lock:
                tested[0] += 1
                if tested[0] % 20 == 0:
                    print(f"\r\033[97m[*] Tested: {tested[0]}/{len(ADMIN_PATHS)}\033[0m", end='', flush=True)
            
            # Check for successful responses
            if response.status_code == 200:
                # Look for admin panel indicators
                indicators = [
                    'login', 'username', 'password', 'admin', 'dashboard', 'sign in',
                    'authentication', 'control panel', 'administrator', 'management',
                    'cms', 'backend', 'user', 'session', 'auth', 'credential'
                ]
                
                content_lower = response.text.lower()
                found_indicators = [ind for ind in indicators if ind in content_lower]
                
                if found_indicators:
                    with lock:
                        found_panels.append({
                            'url': url,
                            'status': response.status_code,
                            'indicators': found_indicators,
                            'title': get_title(response.text),
                            'size': len(response.content)
                        })
                    
                    print(f"\n\033[92m[+] FOUND: {url}\033[0m")
                    print(f"    \033[93mIndicators: {', '.join(found_indicators[:5])}\033[0m")
                    return True
            
            # Check for redirects to login
            elif response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if any(word in location.lower() for word in ['login', 'signin', 'auth']):
                    with lock:
                        found_panels.append({
                            'url': url,
                            'status': response.status_code,
                            'redirect': location,
                            'type': 'redirect'
                        })
                    print(f"\n\033[93m[~] REDIRECT: {url} -> {location}\033[0m")
                    return True
            
            # 401/403 might indicate protected resource
            elif response.status_code in [401, 403]:
                with lock:
                    found_panels.append({
                        'url': url,
                        'status': response.status_code,
                        'type': 'protected'
                    })
                print(f"\n\033[93m[!] PROTECTED: {url} [{response.status_code}]\033[0m")
                return True
            
            return False
            
        except Exception as e:
            return False
    
    def get_title(html):
        """Extract page title from HTML"""
        import re
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1) if match else "No title"
    
    # Execute scan
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(test_admin_path, ADMIN_PATHS)
    
    elapsed = time.time() - start_time
    
    print("\n")
    
    # Results
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m[*] Admin Panel Discovery Complete\033[0m")
    print(f"\033[92m{'='*70}\033[0m\n")
    
    if found_panels:
        print(f"\033[92m[+] Found {len(found_panels)} potential admin panels!\033[0m\n")
        
        for i, panel in enumerate(found_panels, 1):
            print(f"\033[93m[{i}] {panel['url']}\033[0m")
            print(f"    Status: {panel['status']}")
            
            if 'indicators' in panel:
                print(f"    Indicators: {', '.join(panel['indicators'][:5])}")
                if 'title' in panel:
                    print(f"    Title: {panel['title'][:60]}")
            elif 'redirect' in panel:
                print(f"    Redirects to: {panel['redirect']}")
            elif panel.get('type') == 'protected':
                print(f"    Type: Protected Resource")
            print()
        
        # Save results
        save = input("\033[95m[?] Save results? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = "admin_panels.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"Admin Panel Discovery Results\n{'='*70}\n")
                    f.write(f"Target: {target_url}\n")
                    f.write(f"Found: {len(found_panels)} panels\n\n")
                    
                    for panel in found_panels:
                        f.write(f"{panel['url']}\n")
                        f.write(f"  Status: {panel['status']}\n")
                        if 'indicators' in panel:
                            f.write(f"  Indicators: {', '.join(panel['indicators'])}\n")
                        f.write("\n")
                
                print(f"\033[92m[*] Saved to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Error: {str(e)}\033[0m")
    else:
        print(f"\033[93m[!] No admin panels found.\033[0m")
    
    print(f"\n\033[97m[*] Tested: {tested[0]} paths\033[0m")
    print(f"\033[97m[*] Time: {elapsed:.2f}s\033[0m\n")

if __name__ == "__main__":
    run()

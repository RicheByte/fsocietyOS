#!/usr/bin/env python3
"""
Web Directory & File Brute-Forcer
Advanced directory and file discovery tool similar to Gobuster
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from urllib.parse import urljoin
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run():
    print("\033[92m" + "="*70)
    print("           WEB DIRECTORY & FILE BRUTE-FORCER")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only scan websites you own or have permission to test!\033[0m\n")
    
    # Common directories and files wordlist
    COMMON_DIRS = [
        'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 'dashboard',
        'panel', 'cpanel', 'user', 'upload', 'uploads', 'files', 'file', 'downloads',
        'download', 'backup', 'backups', 'old', 'new', 'test', 'testing', 'dev',
        'development', 'prod', 'production', 'stage', 'staging', 'api', 'v1', 'v2',
        'mobile', 'app', 'application', 'public', 'private', 'restricted', 'secret',
        'hidden', 'config', 'configuration', 'settings', 'setup', 'install', 'installation',
        'temp', 'tmp', 'cache', 'log', 'logs', 'data', 'database', 'db', 'sql',
        'includes', 'include', 'assets', 'static', 'media', 'images', 'img', 'css',
        'js', 'javascript', 'scripts', 'src', 'lib', 'libraries', 'vendor', 'plugins',
        'modules', 'components', 'themes', 'templates', 'views', 'controllers', 'models',
        'admin-panel', 'control-panel', 'cms', 'content', 'portal', 'dashboard',
        'system', 'server', 'site', 'www', 'web', 'old-site', 'backup-site', 'secure',
        'bin', 'cgi-bin', 'documentation', 'docs', 'help', 'support', 'faq',
        'about', 'contact', 'company', 'profile', 'account', 'accounts', 'users'
    ]
    
    COMMON_FILES = [
        'index.html', 'index.php', 'index.asp', 'index.aspx', 'index.jsp',
        'admin.php', 'login.php', 'dashboard.php', 'config.php', 'configuration.php',
        'settings.php', 'setup.php', 'install.php', 'database.php', 'db.php',
        'readme.txt', 'README.md', 'readme.html', 'license.txt', 'changelog.txt',
        'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', '.env', '.git/config',
        'composer.json', 'package.json', 'config.json', 'settings.json',
        'backup.sql', 'dump.sql', 'database.sql', 'backup.zip', 'backup.tar.gz',
        'phpinfo.php', 'info.php', 'test.php', 'upload.php', 'shell.php',
        '.gitignore', '.env.example', '.env.local', '.env.production',
        'wp-config.php', 'configuration.php', 'config.inc.php', 'settings.php',
        'admin.html', 'login.html', 'console.html', 'debug.log', 'error.log',
        'access.log', 'error_log', 'access_log', 'app.log', 'application.log'
    ]
    
    EXTENSIONS = ['php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'txt', 'bak', 'old', 'zip', 'tar.gz', 'sql', 'log']
    
    target_url = input("\033[97m[?] Enter target URL (e.g., http://example.com): \033[0m").strip()
    if not target_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    # Ensure URL ends without trailing slash
    target_url = target_url.rstrip('/')
    
    print("\n\033[97m[*] Scan Options:\033[0m")
    print("  [1] Quick Scan (Common directories)")
    print("  [2] Standard Scan (Directories + Common files)")
    print("  [3] Advanced Scan (All wordlists)")
    print("  [4] Custom Wordlist")
    print("  [5] File Extension Fuzzing")
    
    choice = input("\n\033[95m[?] Select scan type: \033[0m").strip()
    
    threads = input("\033[97m[?] Number of threads (1-50, default 20): \033[0m").strip()
    threads = int(threads) if threads.isdigit() and 1 <= int(threads) <= 50 else 20
    
    # Build wordlist
    wordlist = []
    
    if choice == '1':
        wordlist = COMMON_DIRS
    elif choice == '2':
        wordlist = COMMON_DIRS + COMMON_FILES
    elif choice == '3':
        wordlist = COMMON_DIRS + COMMON_FILES
        # Add files with different extensions
        for dir_name in COMMON_DIRS[:20]:
            for ext in ['php', 'html', 'asp', 'aspx']:
                wordlist.append(f"{dir_name}.{ext}")
    elif choice == '4':
        wordlist_file = input("\033[97m[?] Enter wordlist file path: \033[0m").strip()
        try:
            with open(wordlist_file, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"\033[92m[*] Loaded {len(wordlist)} entries from wordlist\033[0m")
        except Exception as e:
            print(f"\033[91m[!] Error loading wordlist: {str(e)}\033[0m")
            return
    elif choice == '5':
        base_name = input("\033[97m[?] Enter base filename (e.g., index): \033[0m").strip()
        wordlist = [f"{base_name}.{ext}" for ext in EXTENSIONS]
    else:
        print("\033[91m[!] Invalid choice.\033[0m")
        return
    
    print(f"\n\033[92m[*] Starting directory/file brute-force...\033[0m")
    print(f"\033[97m[*] Target: {target_url}\033[0m")
    print(f"\033[97m[*] Wordlist size: {len(wordlist)}\033[0m")
    print(f"\033[97m[*] Threads: {threads}\033[0m\n")
    
    found_items = []
    tested = [0]
    lock = threading.Lock()
    
    def test_path(path):
        """Test a single path"""
        try:
            url = urljoin(target_url, path)
            
            # Try as directory first
            dir_url = url if url.endswith('/') else f"{url}/"
            response = requests.get(dir_url, timeout=5, verify=False, allow_redirects=False)
            
            with lock:
                tested[0] += 1
                if tested[0] % 10 == 0:
                    print(f"\r\033[97m[*] Tested: {tested[0]}/{len(wordlist)}\033[0m", end='', flush=True)
            
            if response.status_code in [200, 201, 204, 301, 302, 307, 401, 403]:
                size = len(response.content)
                
                with lock:
                    found_items.append({
                        'url': dir_url,
                        'status': response.status_code,
                        'size': size,
                        'type': 'directory'
                    })
                
                status_color = "\033[92m" if response.status_code == 200 else "\033[93m"
                print(f"\n{status_color}[{response.status_code}]\033[0m {dir_url:<50} Size: {size}")
                return True
            
            # Try as file
            response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
            
            if response.status_code in [200, 201, 204, 301, 302, 307, 401, 403]:
                size = len(response.content)
                
                with lock:
                    found_items.append({
                        'url': url,
                        'status': response.status_code,
                        'size': size,
                        'type': 'file'
                    })
                
                status_color = "\033[92m" if response.status_code == 200 else "\033[93m"
                print(f"\n{status_color}[{response.status_code}]\033[0m {url:<50} Size: {size}")
                return True
            
            return False
            
        except requests.Timeout:
            return False
        except Exception as e:
            return False
    
    # Execute scan with thread pool
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(test_path, path): path for path in wordlist}
        for future in as_completed(futures):
            future.result()
    
    elapsed_time = time.time() - start_time
    
    print("\n")
    
    # Results Summary
    print(f"\n\033[92m{'='*70}\033[0m")
    print(f"\033[92m[*] Directory Brute-Force Complete\033[0m")
    print(f"\033[92m{'='*70}\033[0m\n")
    
    if found_items:
        print(f"\033[92m[+] Found {len(found_items)} accessible paths:\033[0m\n")
        
        # Group by status code
        by_status = {}
        for item in found_items:
            status = item['status']
            if status not in by_status:
                by_status[status] = []
            by_status[status].append(item)
        
        for status, items in sorted(by_status.items()):
            print(f"\033[93m[Status {status}] - {len(items)} items\033[0m")
            for item in items[:10]:  # Show first 10
                print(f"  {item['url']}")
            if len(items) > 10:
                print(f"  ... and {len(items) - 10} more")
            print()
        
        # Save results
        save = input("\033[95m[?] Save results to file? (y/n): \033[0m").strip().lower()
        if save == 'y':
            filename = input("\033[97m[?] Filename (default: dir_scan.txt): \033[0m").strip() or "dir_scan.txt"
            try:
                with open(filename, 'w') as f:
                    f.write(f"Directory Brute-Force Results\n{'='*70}\n")
                    f.write(f"Target: {target_url}\n")
                    f.write(f"Found: {len(found_items)} paths\n")
                    f.write(f"Time: {elapsed_time:.2f}s\n\n")
                    
                    for item in sorted(found_items, key=lambda x: x['status']):
                        f.write(f"[{item['status']}] {item['url']} ({item['size']} bytes)\n")
                
                print(f"\033[92m[*] Results saved to {filename}\033[0m")
            except Exception as e:
                print(f"\033[91m[!] Error: {str(e)}\033[0m")
    else:
        print(f"\033[93m[!] No accessible directories or files found.\033[0m")
    
    print(f"\n\033[97m[*] Total paths tested: {tested[0]}\033[0m")
    print(f"\033[97m[*] Time elapsed: {elapsed_time:.2f}s\033[0m")
    print(f"\033[97m[*] Requests/second: {tested[0]/elapsed_time:.2f}\033[0m\n")

if __name__ == "__main__":
    run()

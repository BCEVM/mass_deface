import requests
import base64
import time
import os

# === CONFIG ===
FOFA_EMAIL = "c00efd442cf902a42ca0ca3c5124115d"
FOFA_KEY = "t5KngXz4AviymMiZgjycAa866dA8v4in"
SHODAN_KEY = "t5KngXz4AviymMiZgjycAa866dA8v4in"

MAX_RESULTS = 100
TARGET_FILE = "targets.txt"

DEFAULT_FOFA_QUERY = 'title="index of /uploads" || body="file manager" || app="WordPress"'
DEFAULT_SHODAN_QUERY = 'http.title:"upload" port:80'

def fetch_from_fofa(query=None):
    query = query or DEFAULT_FOFA_QUERY
    print(f"[*] Fetching from FOFA: {query}")
    b64_query = base64.b64encode(query.encode()).decode()
    url = f"https://fofa.info/api/v1/search/all?email={FOFA_EMAIL}&key={FOFA_KEY}&qbase64={b64_query}&size={MAX_RESULTS}&fields=host,ip,port"

    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        result = r.json()
        links = [f"http://{x[0]}:{x[2]}" for x in result.get("results", [])]
        print(f"[+] FOFA found {len(links)} targets")
        return links
    except Exception as e:
        print(f"[!] FOFA error: {e}")
        return []

def fetch_from_shodan(query=None):
    query = query or DEFAULT_SHODAN_QUERY
    print(f"[*] Fetching from Shodan: {query}")
    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_KEY}&query={query}&limit={MAX_RESULTS}"

    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        result = r.json()
        links = []
        for match in result.get("matches", []):
            ip = match.get("ip_str")
            port = match.get("port", 80)
            links.append(f"http://{ip}:{port}")
        print(f"[+] Shodan found {len(links)} targets")
        return links
    except Exception as e:
        print(f"[!] Shodan error: {e}")
        return []

def save_targets(targets):
    targets = list(set(targets))
    with open(TARGET_FILE, "a") as f:
        for url in targets:
            f.write(f"{url}\n")
    print(f"[+] Saved {len(targets)} new targets to {TARGET_FILE}")

def main():
    print("== FOFA & SHODAN TARGET LOADER ==")
    use_custom = input("[?] Mau input keyword sendiri? (y/N): ").strip().lower() == 'y'

    if use_custom:
        fofa_q = input("[>] FOFA query: ").strip()
        shodan_q = input("[>] Shodan query: ").strip()
    else:
        fofa_q = None
        shodan_q = None

    fofa_targets = fetch_from_fofa(fofa_q)
    time.sleep(2)
    shodan_targets = fetch_from_shodan(shodan_q)

    all_targets = fofa_targets + shodan_targets
    save_targets(all_targets)
    print("[*] Done fetching targets.")

if __name__ == "__main__":
    main()

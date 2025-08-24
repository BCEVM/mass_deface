# fofa_shodan_loader.py
import requests
import base64
import os

FOFA_EMAIL = "c00efd442cf902a42ca0ca3c5124115d"
FOFA_KEY = "t5KngXz4AviymMiZgjycAa866dA8v4in"
SHODAN_KEY = "t5KngXz4AviymMiZgjycAa866dA8v4in"

def load_from_file(filename="targets.txt"):
    if not os.path.exists(filename):
        print(f"[!] {filename} not found, please create it with your targets.")
        return []
    with open(filename, "r") as f:
        targets = [line.strip() for line in f if line.strip()]
    print(f"[+] Loaded {len(targets)} targets from {filename}")
    return targets

def fetch_fofa(query, size=100):
    try:
        qbase64 = base64.b64encode(query.encode()).decode()
        url = f"https://fofa.info/api/v1/search/all?email={FOFA_EMAIL}&key={FOFA_KEY}&qbase64={qbase64}&size={size}&fields=host,ip,port"
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        if "results" in data:
            return [res[0] for res in data["results"]]
    except Exception as e:
        print(f"[!] FOFA error: {e}")
    return []

def fetch_shodan(query, limit=100):
    try:
        url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_KEY}&query={query}&limit={limit}"
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        if "matches" in data:
            return [match.get("ip_str", "") for match in data["matches"] if match.get("ip_str")]
    except Exception as e:
        print(f"[!] Shodan error: {e}")
    return []

def save_targets(targets, filename="targets.txt"):
    existing = set()
    if os.path.exists(filename):
        with open(filename, "r") as f:
            existing = set(line.strip() for line in f)
    new_targets = [t for t in targets if t not in existing]
    if not new_targets:
        print("[*] No new targets found.")
        return
    with open(filename, "a") as f:
        for target in new_targets:
            f.write(target + "\n")
    print(f"[+] Saved {len(new_targets)} new targets to {filename}")

def main():
    print("== TARGET LOADER ==")
    print("[1] Manual upload (targets.txt)")
    print("[2] FOFA (API)")
    print("[3] Shodan (API)")
    choice = input("[?] Pilih sumber target: ")

    targets = []

    if choice == "1":
        targets = load_from_file()
    elif choice == "2":
        query = 'title="index of /uploads" || body="file manager" || app="WordPress"'
        print(f"[*] Fetching from FOFA: {query}")
        targets = fetch_fofa(query)
    elif choice == "3":
        query = 'http.title:"upload" port:80'
        print(f"[*] Fetching from Shodan: {query}")
        targets = fetch_shodan(query)
    else:
        print("[!] Invalid choice")

    if targets:
        save_targets(targets)

if __name__ == "__main__":
    main()

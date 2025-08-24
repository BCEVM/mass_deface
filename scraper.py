import sys
import requests
from bs4 import BeautifulSoup

def scrape_duckduckgo(query, limit=10, output="targets.txt"):
    print(f"[*] Mencari: {query}")
    url = f"https://duckduckgo.com/html/?q={query}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code != 200:
            print(f"[!] Request gagal ({r.status_code})")
            return

        soup = BeautifulSoup(r.text, "html.parser")
        links = []

        for a in soup.select("a.result__a"):
            href = a.get("href")
            if href and href.startswith("http"):
                links.append(href)

        if not links:
            print("[!] Tidak ada hasil scraping.")
            return

        links = links[:limit]
        with open(output, "w") as f:
            for link in links:
                f.write(link + "\n")

        print(f"[+] {len(links)} target tersimpan di {output}")
        for link in links:
            print("   ->", link)

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
    else:
        query = 'inurl:"upload.php"'   # default dork

    scrape_duckduckgo(query)

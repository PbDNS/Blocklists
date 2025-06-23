import requests
import tldextract
from pathlib import Path

SOURCE_URL = "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt"
LIGHT_PATH = Path("light.txt")

VALID_TLDS = {
    "com", "net", "org", "fr", "de", "uk", "us", "ca", "eu", "ch", "es", "it", "nl",
    "be", "pl", "se", "no", "fi", "cz", "at", "dk", "au", "nz", "ru", "in",
    "co", "io", "tv", "app", "dev", "info", "me", "name", "biz", "shop", "store",
    "edu", "gov", "mil", "int", "xyz", "top", "icu", "online", "site", "club", "buzz", "live", "click", "link",
    "fit", "review", "work", "win", "bid", "gq", "cf", "ml", "tk", "ga", "cam", "rest",
    "men", "mom", "stream", "cyou", "space", "today", "monster", "lol", "pics",
    "loan", "surf", "fun", "bar", "party", "press", "hosting", "trade", "website",
    "beauty", "accountant", "faith", "science", "date", "racing", "pro"
}

def is_valid_tld(domain: str) -> bool:
    ext = tldextract.extract(domain)
    return ext.suffix.lower() in VALID_TLDS

def load_previous_blocklist() -> set:
    if not LIGHT_PATH.exists():
        return set()
    with open(LIGHT_PATH, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def main():
    response = requests.get(SOURCE_URL)
    if response.status_code != 200:
        raise Exception(f"Erreur de téléchargement : {response.status_code}")

    lines = response.text.splitlines()
    filtered_rules = set()

    for line in lines:
        line = line.strip()
        if not line.startswith("||") or not line.endswith("^"):
            continue
        domain = line[2:-1]
        if is_valid_tld(domain):
            filtered_rules.add(line)

    # Charger les anciennes règles
    old_rules = load_previous_blocklist()

    # Détecter uniquement les nouvelles
    new_rules = sorted(filtered_rules - old_rules)

    # Écraser le fichier avec uniquement les nouvelles règles
    with open(LIGHT_PATH, "w", encoding="utf-8") as f:
        for rule in new_rules:
            f.write(rule + "\n")

    print(f"{len(new_rules)} nouvelles règles écrites dans light.txt.")

if __name__ == "__main__":
    main()

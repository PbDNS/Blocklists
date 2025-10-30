import urllib.request
import concurrent.futures
from datetime import datetime
import locale
import re
import ipaddress
import os

locale.setlocale(locale.LC_TIME, "fr_FR.UTF-8")

########### blocklists incluses ###########
blocklist_urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/popupads.txt",
    # ✅ Fichier TLDs à ajouter
    "https://dl.red.flag.domains/red.flag.domains_fr.txt"
]

# --- validation de domaine + TLD ---
def is_valid_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    if re.match(r"^\.[a-zA-Z]{2,63}$", domain):  # .agency
        return True
    return re.match(r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$", domain) is not None


# --- extraction de règles depuis une liste ---
def download_and_extract(url):
    rules = set()
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")

            # ✅ Cas spécial fichier TLD
            if "red.flag.domains_fr.txt" in url:
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("||*.") and "^" in line:
                        m = re.search(r"\|\|\*\.(.*?)\^", line)
                        if m:
                            tld = "." + m.group(1).lower()
                            rules.add(tld)
                return rules

            # ✅ Autres blocklists classiques
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("!") or line.startswith("#"):
                    continue

                if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                    parts = re.split(r"\s+", line)
                    if len(parts) >= 2:
                        target = parts[1].strip()
                        if "*" not in target and is_valid_domain(target):
                            rules.add(target)
                elif line.startswith("||") and line.endswith("^"):
                    target = line[2:-1]
                    if "*" not in target and is_valid_domain(target):
                        rules.add(target)
                elif re.match(r"^[a-zA-Z0-9.-]+$", line):
                    if "*" not in line and is_valid_domain(line):
                        rules.add(line)
    except Exception as e:
        print(f"⚠️ Erreur pour {url}: {e}")
    return rules


# --- Téléchargement en parallèle ---
all_entries = set()
tld_entries = set()

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(download_and_extract, blocklist_urls))
    for url, entry_set in zip(blocklist_urls, results):
        if "red.flag.domains_fr.txt" in url:
            tld_entries.update(entry_set)
        else:
            all_entries.update(entry_set)

# ✅ Ajoute les TLDs au set global
all_entries.update(tld_entries)


# --- suppression des redondances : trie simplifié ---
class DomainTrieNode:
    def __init__(self):
        self.children = {}
        self.is_terminal = False

    def insert(self, parts):
        node = self
        for part in parts:
            if node.is_terminal:
                return False  # déjà couvert par un domaine plus général
            node = node.children.setdefault(part, DomainTrieNode())
        node.is_terminal = True
        return True


def domain_to_parts(domain):
    clean = domain.lstrip(".")
    return clean.split(".")[::-1]


# ✅ Trie TLD d’abord, puis domaines plus spécifiques
trie_root = DomainTrieNode()
final_entries = set()

# 1. TLDs (racines)
for tld in sorted(tld_entries):
    trie_root.insert(domain_to_parts(tld))
    final_entries.add(tld)

# 2. Autres domaines : ajout uniquement s’ils ne tombent pas sous un TLD bloqué
for entry in sorted(all_entries - tld_entries, key=lambda e: e.count(".")):
    parts = domain_to_parts(entry)
    node = trie_root
    redundant = False
    for part in parts:
        if node.is_terminal:  # déjà couvert par un TLD
            redundant = True
            break
        node = node.children.get(part)
        if not node:
            break
    if not redundant and is_valid_domain(entry):
        trie_root.insert(parts)
        final_entries.add(entry)

# --- Écriture du fichier final ---
total_unique_before = len(all_entries)
total_unique_after = len(final_entries)
timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {total_unique_after:06} entrées\n\n")
    for entry in sorted(final_entries):
        if entry.startswith("."):
            f.write(f"||{entry}^\n")
        else:
            f.write(f"||{entry.lower()}^\n")

print(f"✅ Fichier blocklist.txt généré : {total_unique_after} entrées (TLDs inclus et redondances supprimées)")

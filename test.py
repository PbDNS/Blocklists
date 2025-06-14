import urllib.request
import concurrent.futures
from datetime import datetime
import re
import ipaddress
import locale
import os

# Liste des TLD en deux parties (à adapter selon tes besoins)
tlds_double_parts = [
    '.ac.uk', '.co.uk', '.org.uk', '.net.uk', '.gov.uk', '.edu.au', '.com.au',
    '.net.au', '.org.au', '.co.in', '.gov.in', '.com.sg', '.net.sg', '.org.sg',
    '.edu.sg', '.co.nz', '.org.nz', '.com.br', '.net.br', '.gov.br', '.org.br',
    '.com.co', '.net.co', '.org.co', '.com.mx', '.net.mx', '.org.mx', '.co.jp',
    '.com.tw', '.net.tw', '.org.tw', '.co.za', '.org.za', '.com.ar', '.net.ar',
    '.org.ar', '.co.ve', '.com.ve', '.net.ve', '.org.ve', '.com.cl', '.net.cl',
    '.org.cl', '.co.il', '.com.il', '.net.il', '.org.il', '.co.ke', '.com.ke',
    '.org.ke', '.com.ph', '.net.ph', '.org.ph', '.co.kr', '.com.hk', '.net.hk',
    '.org.hk', '.co.id', '.co.th', '.co.my'
]

def is_valid_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass

    return re.match(
        r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$",
        domain
    ) is not None

def download_and_extract(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
            rules = set()
            for line in content.splitlines():
                line = line.strip()

                if not line or line.startswith("!") or line.startswith("#"):
                    continue

                if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                    parts = re.split(r"\s+", line)
                    if len(parts) >= 2:
                        target = parts[1].strip()
                        if "*" in target:
                            continue
                        if is_valid_domain(target):
                            rules.add(target)

                elif line.startswith("||") and line.endswith("^"):
                    target = line[2:-1]
                    if "*" in target:
                        continue
                    if is_valid_domain(target):
                        rules.add(target)

                elif re.match(r"^[a-zA-Z0-9.-]+$", line):
                    if "*" in line:
                        continue
                    if is_valid_domain(line):
                        rules.add(line)

            return rules

    except Exception as e:
        print(f"Erreur lors du téléchargement de {url} : {e}")
        return set()

# Télécharger et extraire les règles en parallèle
all_entries = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, blocklist_urls)
    for entry_set in results:
        all_entries.update(entry_set)

# Suppression des sous-domaines redondants (en utilisant un Trie)
class DomainTrieNode:
    def __init__(self):
        self.children = {}
        self.is_terminal = False

    def insert(self, parts):
        node = self
        for part in parts:
            if node.is_terminal:
                return False
            node = node.children.setdefault(part, DomainTrieNode())
        node.is_terminal = True
        return True

def domain_to_parts(domain):
    return domain.strip().split(".")[::-1]

trie_root = DomainTrieNode()
final_entries = set()

# Trier les domaines par nom de domaine principal, puis sous-domaine
for entry in sorted(all_entries, key=lambda e: e.count(".")):
    if is_valid_domain(entry):
        if trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)

# Format de la date locale française
timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

# Écriture du fichier de sortie avec les règles de domaine
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {len(final_entries):06} entrées\n\n")

    # Trier les entrées en fonction des domaines et TLD
    sorted_entries = sorted(final_entries, key=lambda domain: domain.lower())

    for entry in sorted_entries:
        # Vérification si le domaine a un TLD composé et ajustement du tri
        for tld in tlds_double_parts:
            if entry.endswith(tld):
                f.write(f"||{entry.lower()}^\n")
                break
        else:
            f.write(f"||{entry.lower()}^\n")

print(f"✅ Fichier blocklist.txt généré avec {len(final_entries)} entrées.")

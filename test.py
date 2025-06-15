import urllib.request
import concurrent.futures
from datetime import datetime
import re
import ipaddress
import locale
import os

# Définir local France
try:
    locale.setlocale(locale.LC_TIME, 'fr_FR.UTF-8')
except locale.Error as e:
    print(f"⚠️ Impossible de définir local fr_FR.UTF-8 : {e}")
    pass 

# Liste des TLDs à traiter
tlds_to_add = ['cn', 'ru', 'jp', 'in']  # Ajoutez ici les TLDs souhaités

# Fonction pour vérifier si un domaine est valide
def is_valid_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass  # Ce n’est pas une IP, on continue

    return re.match(
        r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$",
        domain
    ) is not None

# Fonction pour télécharger et extraire les règles
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

# Téléchargement parallèle des règles
blocklist_urls = [
    "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/add.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt",
    # Ajoutez ici toutes les autres URLs de blocklists
]

all_entries = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, blocklist_urls)
    for entry_set in results:
        all_entries.update(entry_set)

# Suppression des sous-domaines redondants
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

for entry in sorted(all_entries, key=lambda e: e.count(".")):
    if is_valid_domain(entry):
        if trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)

# Suppression des règles contenant un TLD spécifique
tlds_to_process = {tld: False for tld in tlds_to_add}  # Dictionnaire pour gérer les TLDs ajoutés

# Règles finales après traitement
final_filtered_entries = set()

for entry in final_entries:
    domain_parts = entry.split(".")
    tld = domain_parts[-1]  # Récupérer le dernier élément (TLD)
    
    if tld in tlds_to_process:
        if not tlds_to_process[tld]:  # Si ce TLD n'a pas encore été ajouté, ajoutez-le
            final_filtered_entries.add(f"||{tld}^")
            tlds_to_process[tld] = True
    else:
        final_filtered_entries.add(f"||{entry.lower()}^")

# Format de la date locale française
timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

# Écriture du fichier de sortie
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {len(final_filtered_entries):06} entrées\n\n")
    for entry in sorted(final_filtered_entries):
        f.write(f"{entry}\n")

print(f"✅ Fichier blocklist.txt généré avec {len(final_filtered_entries)} entrées.")

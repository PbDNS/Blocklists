import urllib.request
import concurrent.futures
from datetime import datetime, timezone, timedelta
import re
import ipaddress
import os

############################################################
################### Blocklistes incluses ###################
############################################################
# Liste des URLs de blocklistes
blocklist_urls = [
    "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/add.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/popupads.txt",
    # ... (ajouter d'autres URLs)
]

# Validation des domaines
def is_valid_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    return re.match(r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$", domain) is not None

# Télécharger et extraire les règles des blocklistes
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

# Téléchargement parallèle
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

# Calcul des statistiques
total_unique_before = len(all_entries)
total_unique_after = len(final_entries)

# Utiliser l'heure GMT+2 pour la France (heure d'été)
france_timezone = timezone(timedelta(hours=2))  # UTC+2 pour l'heure d'été
timestamp = datetime.now(france_timezone).strftime("%A %d %B %Y, %H:%M")

# Écriture du fichier de sortie
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {total_unique_after:06} entrées\n\n")
    for entry in sorted(final_entries):
        f.write(f"||{entry.lower()}^\n")

print(f"✅ Fichier blocklist.txt généré: {total_unique_after} entrées")

# Mise à jour du README.md
def update_readme(stats):
    readme_path = 'README.md'

    # Lire le contenu du README.md
    with open(readme_path, 'r') as file:
        content = file.read()

    # Créer le nouveau contenu pour le tableau des statistiques
    new_table_content = f"""
| **filtres uniques avant traitement** | **redondances supprimées** |
|--------------------------------------|----------------------------|
| {stats['before']}                    | {stats['after']}           |
"""

    # Rechercher la balise <!-- STATISTICS_TABLE -->
    table_position = content.find("<!-- STATISTICS_TABLE -->")

    if table_position != -1:
        # Remplacer le tableau existant avec le nouveau contenu
        start_pos = content.find('|', table_position)
        end_pos = content.find('|', start_pos + 1)
        content = content[:start_pos] + new_table_content + content[end_pos + 1:]
    else:
        # Si la balise n'est pas trouvée, ajouter le tableau à la fin du fichier
        content += "\n<!-- STATISTICS_TABLE -->\n" + new_table_content

    # Réécrire le contenu modifié dans le fichier README.md
    with open(readme_path, 'w') as file:
        file.write(content)

# Mise à jour des statistiques
stats = {
    'before': total_unique_before,
    'after': total_unique_after
}

# Mise à jour du README avec les statistiques
update_readme(stats)

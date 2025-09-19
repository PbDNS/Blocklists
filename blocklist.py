import urllib.request
import concurrent.futures
from datetime import datetime
import locale
import re
import ipaddress
import os

locale.setlocale(locale.LC_TIME, "fr_FR.UTF-8")

blocklist_urls = [
    "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/add.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/popupads.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.amazon.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.tiktok.extended.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/doh-vpn-proxy-bypass.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.winoffice.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    "https://small.oisd.nl/",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_53.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.apple.txt",
    "https://raw.githubusercontent.com/d3ward/toolz/master/src/d3host.adblock",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/refs/heads/master/FrenchFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/refs/heads/master/FrenchFilter/sections/adservers_firstparty.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    "https://raw.githubusercontent.com/easylist/listefr/refs/heads/master/hosts.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    "https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/abuse-tlds/domains.adblock"  # Ajout de la blocklist des TLDs
]

def is_valid_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    return re.match(r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$", domain) is not None

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

def extract_tlds(url):
    """ Extraire les TLDs de la blocklist des TLDs (format Adblock Plus) """
    tlds = set()
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("||") and line.endswith("^"):
                    tld = line[2:-1]  # Extraire le domaine avant le ^
                    if is_valid_domain(tld):
                        tlds.add(tld)
    except Exception as e:
        print(f"Erreur lors de l'extraction des TLDs depuis {url} : {e}")
    return tlds

# Télécharger et extraire les blocklists
all_entries = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, blocklist_urls)
    for entry_set in results:
        all_entries.update(entry_set)

# Extraire les TLDs depuis la blocklist
tlds_url = "https://raw.githubusercontent.com/cbuijs/hagezi/refs/heads/main/lists/abuse-tlds/domains.adblock"
tlds_entries = extract_tlds(tlds_url)
all_entries.update(tlds_entries)

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

# Trie pour gérer les domaines et supprimer les redondances
trie_root = DomainTrieNode()
final_entries = set()

for entry in sorted(all_entries, key=lambda e: e.count(".")):
    if is_valid_domain(entry):
        if trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)

# Sauvegarde de la blocklist finale dans un fichier
total_unique_before = len(all_entries)
total_unique_after = len(final_entries)

timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {total_unique_after:06} entrées\n\n")
    for entry in sorted(final_entries):
        f.write(f"||{entry.lower()}^\n")

print(f"✅ fichier blocklist.txt généré: {total_unique_after} entrées")

# Mise à jour du fichier README
def update_readme(stats):
    readme_path = 'README.md'
    with open(readme_path, 'r') as file:
        content = file.read()

    new_table_content = f"""
| **filtres uniques avant traitement** | **filtres uniques sans redondance** |
|:------------------------------------:|:------------------------------------:|
| {stats['before']}                    | **{stats['after']}**                 |
"""

    start_tag = "<!-- STATISTICS_TABLE_START -->"
    end_tag = "<!-- STATISTICS_TABLE_END -->"

    start_position = content.find(start_tag)
    end_position = content.find(end_tag)

    if start_position != -1 and end_position != -1:
        content = content[:start_position + len(start_tag)] + "\n" + new_table_content + "\n" + content[end_position:]
    else:
        if start_position == -1:
            content += f"\n{start_tag}\n"
        if end_position == -1:
            content += f"\n{end_tag}\n"
        content = content.replace(end_tag, f"\n{new_table_content}\n{end_tag}")

    with open(readme_path, 'w') as file:
        file.write(content)

stats = {
    'before': total_unique_before,
    'after': total_unique_after
}

update_readme(stats)

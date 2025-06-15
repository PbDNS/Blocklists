import urllib.request
import concurrent.futures
from datetime import datetime, timezone, timedelta
import re
import ipaddress
import os

############################################################
################### Blocklistes incluses ###################
############################################################
# HaGeZi's Normal DNS Blocklist
# HaGeZi's Pop-Up Ads DNS Blocklist
# HaGeZi's Amazon Tracker DNS Blocklist
# HaGeZi's TikTok Extended Fingerprinting DNS Blocklist
# HaGeZi's Badware Hoster Blocklist
# HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass DNS Blocklist
# HaGeZi's DynDNS Blocklist
# HaGeZi's Windows/Office Tracker DNS Blocklist
# ShadowWhisperer's Malware List
# OISD Small
# Dandelion Sprout's Anti Malware List
# Dandelion Sprout's Anti Push Notifications
# HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass
# AWAvenue Ads Rule
# HaGeZi's Apple Tracker DNS Blocklist
# d3Host
# AdGuard DNS filter
# Phishing Army
# Phishing URL Blocklist (PhishTank and OpenPhish)
# Malicious URL Blocklist (URLHaus)
# Scam Blocklist by DurableNapkin
# AdGuard French adservers
# AdGuard French adservers first party
# Steven Black's List
# Peter Lowe's Blocklist
# Dan Pollock's List
# Easylist FR
# The Big List of Hacked Malware Web Sites
# Stalkerware Indicators List

blocklist_urls = [
    "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/add.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/popupads.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.amazon.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.tiktok.extended.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_39.txt",
    "https://raw.githubusercontent.com/ngfblog/dns-blocklists/refs/heads/main/adblock/doh-vpn-proxy-bypass.txt",
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
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt"
]

def is_valid_domain(domain):
    # Exclusion des IPs
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
total_unique_before = len(all_entries)  # Nombre d'entrées avant suppression des sous-domaines redondants
total_unique_after = len(final_entries)  # Nombre d'entrées après suppression des sous-domaines redondants

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

# Mise à jour du README.md avec les statistiques
def update_readme(stats):
    readme_path = 'README.md'

    with open(readme_path, 'r') as file:
        content = file.read()

    # Tableau des statistiques à insérer au début
    table = f"""
## Statistiques de l'Agrégation des Blocklistes

| Statistique                                      | Valeur     |
|--------------------------------------------------|------------|
| **Filtres uniques avant agrégation**            | {stats['before']} |
| **Filtres uniques après suppression des sous-domaines** | {stats['after']} |
| **Mis à jour le**                                | {timestamp} |
    """

    # Insérer le tableau après le lien vers blocklist.txt
    content = content.replace('🔗 [blocklist.txt](https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt)', 
                              f'🔗 [blocklist.txt](https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt)\n\n{table}')

    with open(readme_path, 'w') as file:
        file.write(content)

# Préparer les statistiques
stats = {
    'before': total_unique_before,
    'after': total_unique_after
}

# Mise à jour du README avec les statistiques
update_readme(stats)

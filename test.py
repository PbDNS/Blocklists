import urllib.request
import concurrent.futures
from datetime import datetime
import re
import ipaddress
import locale
import os

# Liste mise à jour des TLD à deux parties
two_part_tlds = {
    "co.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "ac.uk", "gov.uk", "org.uk", "edu.uk",
    "sch.uk", "us.com", "eu.com", "nom.co", "ca", "mx", "tv", "int", "coop", "aero", "museum", "asia", "cat",
    "com.br", "org.br", "gov.br", "net.br", "edu.br", "mil.br", "eng.br", "co.za", "org.za", "gov.za", "net.za",
    "edu.za", "ac.za", "co.nz", "org.nz", "govt.nz", "edu.nz", "net.nz", "ac.nz", "co.in", "org.in", "net.in",
    "edu.in", "gov.in", "mil.in", "co.il", "org.il", "gov.il", "edu.il", "ac.il", "co.jp", "ne.jp", "or.jp",
    "ac.jp", "edu.jp", "go.jp", "gov.jp", "co.kr", "or.kr", "edu.kr", "ac.kr", "gov.kr", "net.kr", "co.id", 
    "ac.id", "or.id", "co.th", "ac.th", "go.th", "in.th", "edu.th", "com.cn", "org.cn", "net.cn", "gov.cn", 
    "edu.cn", "mil.cn", "co.sg", "org.sg", "gov.sg", "edu.sg", "net.sg", "com.hk", "edu.hk", "gov.hk", "org.hk",
    "co.my", "com.my", "gov.my", "edu.my", "org.my", "ac.my", "co.ph", "com.ph", "gov.ph", "edu.ph", "org.ph",
    "co.kr", "com.kr", "edu.kr", "gov.kr", "net.kr", "com.tw", "org.tw", "edu.tw", "gov.tw", "ac.tw", "net.tw",
    "com.mx", "net.mx", "gov.mx", "org.mx", "edu.mx", "co.ug", "org.ug", "ac.ug", "gov.ug", "co.ke", "or.ke", 
    "gov.ke", "edu.ke", "net.ke", "co.ng", "org.ng", "edu.ng", "gov.ng", "com.ng", "net.ng", "ac.ng", "co.za",
    "org.za", "edu.za", "gov.za", "net.za", "mil.za"
}

# Liste des URLs des blocklists à télécharger
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
    """Vérifie si le domaine est valide."""
    try:
        ipaddress.ip_address(domain)  # Si c'est une IP, retourner False
        return False
    except ValueError:
        pass  # Ce n'est pas une IP, continuer

    # Vérification des noms de domaine valides
    return re.match(
        r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$",
        domain
    ) is not None

def download_and_extract(url):
    """Télécharge et extrait les règles de la blocklist à partir de l'URL."""
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

def domain_to_parts(domain):
    """Convertit un domaine en une liste de parties, inversée."""
    return domain.strip().split(".")[::-1]

class DomainTrieNode:
    """Trie (arbre) pour la gestion des domaines."""
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

# Téléchargement parallèle des blocklists
all_entries = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, blocklist_urls)
    for entry_set in results:
        all_entries.update(entry_set)

# Suppression des sous-domaines redondants
trie_root = DomainTrieNode()
final_entries = set()

# On trie les domaines par nombre de segments, puis on insère dans le trie
for entry in sorted(all_entries, key=lambda e: e.count(".")):
    if is_valid_domain(entry):
        if trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)

# Format de la date locale française
timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

# Écriture du fichier de sortie
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {len(final_entries):06} entrées\n\n")
    for entry in sorted(final_entries):
        f.write(f"||{entry.lower()}^\n")

print(f"✅ Fichier blocklist.txt généré avec {len(final_entries)} entrées.")

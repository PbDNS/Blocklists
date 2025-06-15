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

tlds_to_add = [
    'af',  # Afghanistan
    'am',  # Arménie
    'az',  # Azerbaïdjan
    'bd',  # Bangladesh
    'bt',  # Bhoutan
    'by',  # Biélorussie
    'cn',  # Chine
    'cv',  # Cap-Vert
    'ge',  # Géorgie
    'gz',  # Gaza (Palestine)
    'id',  # Indonésie
    'in',  # Inde
    'ir',  # Iran
    'jp',  # Japon
    'kh',  # Cambodge
    'kg',  # Kirghizistan
    'ke',  # Kenya
    'la',  # Laos
    'mn',  # Mongolie
    'my',  # Malaisie
    'np',  # Népal
    'pk',  # Pakistan
    'tj',  # Tadjikistan
    'tz',  # Tanzanie
    'uz',  # Ouzbékistan
    'vn',  # Vietnam
    'zm',  # Zambie
    'sy',  # Syrie
    'ye',  # Yémen
    'iq',  # Irak
    'sd',  # Soudan
    'ss',  # Soudan du Sud
    'ly',  # Libye
    'om',  # Oman
    'sa',  # Arabie Saoudite
    'kw',  # Koweït
    'ae',  # Émirats Arabes Unis
    'qa',  # Qatar
    'ps',  # Palestine
    'mv',  # Maldives
]

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

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
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt",
    # ✅ nouvelle source : TLD list
    "https://dl.red.flag.domains/red.flag.domains_fr.txt"
]


def is_valid_domain(domain):
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    # ✅ On autorise aussi les TLD simples (ex: ".agency")
    if re.match(r"^\.[a-zA-Z]{2,63}$", domain):
        return True
    return re.match(r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$", domain) is not None


def download_and_extract(url):
    rules = set()
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")

            # ✅ Fichier TLD spécial
            if "red.flag.domains_fr.txt" in url:
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("||*.") and "^" in line:
                        tld_match = re.search(r"\|\|\*\.(.*?)\^", line)
                        if tld_match:
                            tld = "." + tld_match.group(1).lower()  # ex: ".agency"
                            rules.add(tld)
                return rules

            # ✅ Bloclists normales
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
    except Exception as e:
        print(f"Erreur lors du téléchargement de {url} : {e}")
    return rules


# Téléchargement parallèle
all_entries = set()
tld_entries = set()

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, blocklist_urls)
    for url, entry_set in zip(blocklist_urls, results):
        if "red.flag.domains_fr.txt" in url:
            tld_entries.update(entry_set)
        else:
            all_entries.update(entry_set)

# ✅ On ajoute les TLDs au set global
all_entries.update(tld_entries)


# --- Gestion du Trie pour suppression des redondances ---
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
    # .agency → ["agency"]
    clean = domain.lstrip(".")
    return clean.strip().split(".")[::-1]


trie_root = DomainTrieNode()
final_entries = set()

# ✅ Tri : les TLD d’abord, ensuite les domaines
for entry in sorted(all_entries, key=lambda e: e.count(".")):
    if is_valid_domain(entry):
        if trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)

# Écriture du résultat final
total_unique_before = len(all_entries)
total_unique_after = len(final_entries)
timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {total_unique_after:06} entrées\n\n")
    for entry in sorted(final_entries):
        if entry.startswith("."):
            f.write(f"||{entry}^\n")  # ex: ||.agency^
        else:
            f.write(f"||{entry.lower()}^\n")

print(f"✅ Fichier blocklist.txt généré ({total_unique_after} entrées, TLDs inclus et redondances nettoyées)")

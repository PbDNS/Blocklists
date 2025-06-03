# blocklist.py

import urllib.request
import concurrent.futures
from datetime import datetime, timedelta
import re

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
# Dandelion Sprout's Anti-Malware List
# HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass
# AWAvenue Ads Rule
# HaGeZi's Apple Tracker DNS Blocklist
# d3Host
# AdGuard DNS filter
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
# Perso

# 📥 Liste des blocklists
blocklist_urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/popupads.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.amazon.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.tiktok.extended.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",
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
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/refs/heads/master/FrenchFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/refs/heads/master/FrenchFilter/sections/adservers_firstparty.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_33.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
    "https://raw.githubusercontent.com/easylist/listefr/refs/heads/master/hosts.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt"
#    "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/General.txt"
]

def download_and_extract(url):
    try:
        print(f"🔄 Téléchargement : {url}")
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
            rules = set()
            for line in content.splitlines():
                line = line.strip()

                # Ignore les lignes vides, les commentaires et les lignes inutiles
                if not line or line.startswith("!") or line.startswith("#"):
                    continue

                # Gérer les lignes de type 0.0.0.0 <domain> # <commentaire>
                if line.startswith("0.0.0.0"):
                    parts = re.split(r"\s+", line)  # Séparer par espaces
                    if len(parts) >= 2:
                        domain = parts[1].strip()  # Extraire le domaine
                        if domain and "*" not in domain:
                            rules.add(domain)

                # Gérer les règles du format ||<domain>^
                elif line.startswith("||") and line.endswith("^"):
                    domain = line[2:-1]
                    if "*" not in domain:
                        rules.add(domain)

            return rules

    except Exception as e:
        print(f"❌ Erreur : {url} → {e}")
        return set()

# 📦 Téléchargement parallèle
all_domains = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, blocklist_urls)
    for domain_set in results:
        all_domains.update(domain_set)

print(f"\n📊 {len(all_domains)} domaines extraits avant suppression des doublons de sous-domaines.")

# 🌳 Suppression des sous-domaines redondants
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
    return domain.strip().split(".")[::-1]  # ex: ["com", "example", "ads"]

trie_root = DomainTrieNode()
final_domains = set()

for domain in sorted(all_domains, key=lambda d: d.count(".")):
    if trie_root.insert(domain_to_parts(domain)):
        final_domains.add(domain)

print(f"✅ {len(final_domains)} domaines après suppression des sous-domaines.")

# 🕒 Timestamp UTC+1
timestamp = (datetime.utcnow() + timedelta(hours=1)).strftime("%d-%m-%Y  %H:%M")

# 💾 Écriture du fichier
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {len(final_domains):06} entrées finales\n\n")
    for domain in sorted(final_domains):
        f.write(f"||{domain}^\n")

print(f"\n✅ Fichier 'blocklist.txt' généré avec succès.")
print(f"📦 {len(final_domains)} règles finales conservées.")


import urllib.request
import concurrent.futures
import socket
from datetime import datetime, timedelta

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
# Perso# 📥 Liste des blocklists

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
    "https://energized.pro/extreme/adblock.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/refs/heads/master/FrenchFilter/sections/adservers.txt",
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/refs/heads/master/FrenchFilter/sections/adservers_firstparty.txt",
    "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/General.txt"
]

def download_and_extract(url):
    try:
        print(f"🔄 Téléchargement : {url}")
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
            return [line.strip() for line in content.splitlines() if line.startswith("||") and line.endswith("^")]
    except Exception as e:
        print(f"❌ Erreur : {url} → {e}")
        return []

# 🧵 Téléchargement parallèle
all_lines = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, blocklist_urls)
    for rules in results:
        all_lines.update(rules)

print(f"\n✅ {len(all_lines)} règles valides récupérées.")

def extract_domain(rule):
    return rule[2:-1]

def domain_to_parts(domain):
    return domain.split(".")[::-1]

# 🔗 DNS check (multithread)
def is_domain_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

print("\n🔍 Vérification DNS des domaines...")
domains_to_check = list(set(extract_domain(r) for r in all_lines))

# Paralléliser DNS check
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    domain_results = dict(zip(domains_to_check, executor.map(is_domain_resolvable, domains_to_check)))

# ✅ Seuls les domaines résolvables sont conservés
filtered_lines = {f"||{domain}^" for domain, ok in domain_results.items() if ok}
print(f"✅ {len(filtered_lines)} domaines DNS résolvables conservés.")

# 🧠 Suppression des sous-domaines redondants
class DomainTrieNode:
    def __init__(self):
        self.children = {}
        self.is_terminal = False

    def insert(self, parts):
        node = self
        for part in parts:
            if node.is_terminal:
                return False
            if part not in node.children:
                node.children[part] = DomainTrieNode()
            node = node.children[part]
        node.is_terminal = True
        return True

trie_root = DomainTrieNode()
final_domains = set()

for rule in sorted(filtered_lines, key=lambda r: extract_domain(r).count(".")):
    domain = extract_domain(rule)
    if trie_root.insert(domain_to_parts(domain)):
        final_domains.add(rule)

# 🕒 Timestamp UTC+1
timestamp = (datetime.utcnow() + timedelta(hours=1)).strftime("%d-%m-%Y  %H:%M")

# 💾 Écriture dans le fichier blocklist.txt
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp}\n")
    f.write(f"! {len(final_domains):06} entrées finales\n\n")
    for rule in sorted(final_domains):
        f.write(f"{rule}\n")

print(f"\n✅ Fichier 'blocklist.txt' généré avec succès.")
print(f"📦 {len(final_domains)} règles finales conservées.")


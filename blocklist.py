# blocklist.py

import urllib.request
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
# Energized Pro Extreme
# Phishing URL Blocklist (PhishTank and OpenPhish)
# Malicious URL Blocklist (URLHaus)
# Scam Blocklist by DurableNapkin
# AdGuard French adservers
# AdGuard French adservers first party
# Perso

# Blocklists à fusionner
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

# Téléchargement des règles valides (||domaine^)
raw_filtered_lines = set()

for url in blocklist_urls:
    try:
        print(f"Téléchargement depuis {url}")
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8', errors='ignore')
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("||") and line.endswith("^"):
                    raw_filtered_lines.add(line)
    except Exception as e:
        print(f"❌ Erreur lors du téléchargement de {url}: {e}")

print(f"\n✔️ {len(raw_filtered_lines)} règles initiales chargées.\n")

# 🔍 Extraction des domaines bruts (sans || et ^)
def extract_domain(rule):
    return rule[2:-1]

# 🔁 Vérifie si un domaine est un sous-domaine d’un autre
def is_subdomain(sub, parent):
    return sub == parent or sub.endswith("." + parent)

# 💡 Suppression des règles redondantes
all_domains = set(extract_domain(rule) for rule in raw_filtered_lines)
sorted_domains = sorted(all_domains, key=lambda d: d.count('.'))  # du plus général au plus spécifique

non_redundant_domains = set()

for domain in sorted_domains:
    if not any(is_subdomain(domain, kept) for kept in non_redundant_domains):
        non_redundant_domains.add(domain)

# 🧾 Reconstruction des règles Adblock
final_rules = {f"||{domain}^" for domain in non_redundant_domains}

# 📅 Horodatage
now_utc_plus1 = datetime.utcnow() + timedelta(hours=1)
timestamp_str = now_utc_plus1.strftime("%d-%m-%Y  %H:%M")

# 💾 Écriture dans le fichier
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation - {timestamp_str}\n")
    f.write(f"! {len(final_rules):06} entrées après nettoyage\n\n")
    for entry in sorted(final_rules):
        f.write(f"{entry}\n")

print("✅ Fichier blocklist.txt généré avec succès.")
print(f"➤ {len(final_rules)} règles finales conservées.")

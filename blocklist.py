# blocklist.py

import urllib.request
from datetime import datetime, timedelta

# HaGeZi's Normal DNS Blocklist
# HaGeZi's Pop-Up Ads DNS Blocklist
# HaGeZi's Amazon Tracker DNS Blocklist
# HaGeZi's TikTok Extended Fingerprinting DNS Blocklist
# HaGeZi's Badware Hoster Blocklist
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
# Perso

# Liste des URLs des blocklists à fusionner
blocklist_urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/popupads.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.amazon.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/native.tiktok.extended.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt",
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
    "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/General.txt"
]

# Conteneur pour les lignes valides
filtered_lines = set()

for url in blocklist_urls:
    try:
        print(f"Téléchargement depuis {url}")
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8')
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("||") and line.endswith("^"):
                    filtered_lines.add(line)
    except Exception as e:
        print(f"Erreur lors du téléchargement de {url}: {e}")

# Horodatage UTC+1
now_utc_plus1 = datetime.utcnow() + timedelta(hours=1)
timestamp_str = now_utc_plus1.strftime("%d-%m-%Y  %H:%M")

# Écriture dans le fichier
with open("blocklist.txt", "w") as f:
    f.write(f"! Agrégation - {timestamp_str}\n")
    f.write(f"! {len(filtered_lines):06} entrées\n\n")  # Ligne vide avant les filtres
    for entry in sorted(filtered_lines):
        f.write(f"{entry}\n")

print("blocklist.txt générée avec succès.")

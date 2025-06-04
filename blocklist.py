import urllib.request
import concurrent.futures
from datetime import datetime, timedelta
import re
import ipaddress
import os

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
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt"
]

def is_valid_domain(domain):
    return re.match(r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$", domain)

def is_valid_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4 and not (
            ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or
            ip_obj.is_reserved or ip_obj.is_multicast
        )
    except ValueError:
        return False

def download_and_extract(url):
    try:
        print(f"🔄 Téléchargement : {url}")
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
                        if "*" not in target and (is_valid_domain(target) or is_valid_ip(target)):
                            rules.add(target)
                elif line.startswith("||") and line.endswith("^"):
                    target = line[2:-1]
                    if "*" not in target and (is_valid_domain(target) or is_valid_ip(target)):
                        rules.add(target)
                elif re.match(r"^[a-zA-Z0-9.-]+$", line):
                    if "*" not in line and (is_valid_domain(line) or is_valid_ip(line)):
                        rules.add(line)
            return rules
    except Exception as e:
        print(f"❌ Erreur : {url} → {e}")
        return set()

# 🔁 Télécharger les blocklists
all_entries = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, blocklist_urls)
    for entry_set in results:
        all_entries.update(entry_set)

print(f"\n📊 {len(all_entries)} entrées extraites des blocklists.")

# 📖 Lecture et nettoyage de General.txt
general_file_path = "General.txt"
if not os.path.isfile(general_file_path):
    print("❌ Fichier General.txt introuvable.")
    exit(1)

raw_general = set()
with open(general_file_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        if line.startswith("||") and line.endswith("^"):
            line = line[2:-1]
        if is_valid_domain(line) or is_valid_ip(line):
            raw_general.add(line)

cleaned_general = raw_general - all_entries
print(f"✅ {len(cleaned_general)} entrées conservées dans General.txt après nettoyage.")

# 🕒 Timestamp UTC+1
timestamp = (datetime.utcnow() + timedelta(hours=1)).strftime("%d-%m-%Y  %H:%M")

# 💾 Écriture du fichier blocklist.txt (format ||domain^)
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Généré automatiquement - {timestamp}\n")
    f.write(f"! {len(cleaned_general):06} entrées\n\n")
    for entry in sorted(cleaned_general):
        f.write(f"||{entry}^\n")

# 💾 Réécriture de General.txt (format brut)
with open("General.txt", "w", encoding="utf-8") as f:
    for entry in sorted(cleaned_general):
        f.write(f"{entry}\n")

print("\n✅ Fichier 'blocklist.txt' généré.")
print("✅ Fichier 'General.txt' nettoyé et mis à jour.")

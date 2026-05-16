import urllib.request
import concurrent.futures
from datetime import datetime
import locale
import re
import ipaddress

locale.setlocale(locale.LC_TIME, "fr_FR.UTF-8")

########### listes IP incluses ###########
# HaGeZi's TIF IP Blocklist
# Data-Shield IPv4 Blocklist
# FireHOL Level 1 Netset (via GitHub raw)

ip_list_urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/ips/tif.txt",
    "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


def parse_entry(token):
    """Retourne un objet ip_address ou ip_network valide, ou None."""
    token = token.strip()
    if not token:
        return None
    try:
        if "/" in token:
            return ipaddress.ip_network(token, strict=False)
        else:
            return ipaddress.ip_address(token)
    except ValueError:
        return None


def download_and_extract(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
        entries = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";") or line.startswith("!"):
                continue
            obj = parse_entry(line)
            if obj is not None:
                entries.add(obj)
        return entries
    except Exception as e:
        print(f"Erreur lors du téléchargement de {url} : {e}")
        return set()


# ── Agrégation parallèle ──────────────────────────────────────────────────────
all_entries = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, ip_list_urls)
    for entry_set in results:
        all_entries.update(entry_set)

total_unique_before = len(all_entries)

# ── Séparation IPs simples / plages CIDR ─────────────────────────────────────
networks = [e for e in all_entries if isinstance(e, ipaddress.IPv4Network)]
single_ips = [e for e in all_entries if isinstance(e, ipaddress.IPv4Address)]

# ── Dédoublonnage ─────────────────────────────────────────────────────────────
# 1. Fusionner/compacter les plages CIDR entre elles
collapsed = list(ipaddress.collapse_addresses(networks))

# 2. Supprimer les IPs simples déjà couvertes par une plage
def ip_in_any_network(ip, nets):
    for net in nets:
        if ip in net:
            return True
    return False

final_ips = [ip for ip in single_ips if not ip_in_any_network(ip, collapsed)]

# Tri numérique
final_networks = sorted(collapsed)
final_ips_sorted = sorted(final_ips)

total_unique_after = len(final_networks) + len(final_ips_sorted)

# ── Écriture du fichier de sortie ─────────────────────────────────────────────
timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

with open("ip-blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"# Agrégation IP - {timestamp}\n")
    f.write(f"# {total_unique_after:06} entrées ({len(final_networks)} plages CIDR + {len(final_ips_sorted)} IPs)\n\n")
    for net in final_networks:
        f.write(f"{net}\n")
    for ip in final_ips_sorted:
        f.write(f"{ip}\n")

print(f"✅ fichier ip-blocklist.txt généré: {total_unique_after} entrées")


# ── Mise à jour README ────────────────────────────────────────────────────────
def update_readme(stats):
    readme_path = "README.md"
    try:
        with open(readme_path, "r") as file:
            content = file.read()
    except FileNotFoundError:
        content = ""

    new_table_content = f"""
| **entrées uniques avant traitement** | **entrées uniques sans redondance** |
|:------------------------------------:|:-----------------------------------:|
| {stats['before']} | **{stats['after']}** |
"""

    start_tag = "<!--IP_STATS_START-->"
    end_tag = "<!--IP_STATS_END-->"

    start_position = content.find(start_tag)
    end_position = content.find(end_tag)

    if start_position != -1 and end_position != -1:
        content = (
            content[: start_position + len(start_tag)]
            + "\n"
            + new_table_content
            + "\n"
            + content[end_position:]
        )
    else:
        if start_tag not in content:
            content += f"\n{start_tag}\n"
        if end_tag not in content:
            content += f"\n{end_tag}\n"
        content = content.replace(end_tag, f"\n{new_table_content}\n{end_tag}")

    with open(readme_path, "w") as file:
        file.write(content)


stats = {
    "before": total_unique_before,
    "after": total_unique_after,
}
update_readme(stats)

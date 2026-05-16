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
# FireHOL Level 1 Netset

ip_list_urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/ips/tif.txt",
    "https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt",
    "https://iplists.firehol.org/files/firehol_level1.netset",
]


def parse_entry(token):
    """Retourne un objet ip_address ou ip_network valide, ou None."""
    token = token.strip()
    if not token:
        return None
    try:
        # Plage CIDR
        if "/" in token:
            return ipaddress.ip_network(token, strict=False)
        else:
            return ipaddress.ip_address(token)
    except ValueError:
        return None


def download_and_extract(url):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
        entries = set()
        for line in content.splitlines():
            line = line.strip()
            # Ignorer commentaires et lignes vides
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
networks = sorted(
    [e for e in all_entries if isinstance(e, ipaddress.IPv4Network)],
    key=lambda n: (n.network_address, n.prefixlen),
)
single_ips = [e for e in all_entries if isinstance(e, ipaddress.IPv4Address)]

# ── Dédoublonnage : suppression des IPs/plages couvertes par une plage plus large
#    1. Fusionner/compacter les plages CIDR entre elles
collapsed = list(ipaddress.collapse_addresses(networks))

#    2. Construire un index des plages finales pour test d'appartenance rapide
def ip_in_any_network(ip, nets):
    """Teste si une IPv4Address est couverte par au moins un des réseaux."""
    for net in nets:
        if ip in net:
            return True
    return False

# Filtrer les IPs simples redondantes avec les plages
final_ips = [ip for ip in single_ips if not ip_in_any_network(ip, collapsed)]

# Trier le tout
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

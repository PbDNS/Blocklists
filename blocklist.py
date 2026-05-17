"""
Agrégateur de blocklists DNS au format AdBlock.

Télécharge plusieurs listes de blocage, extrait les domaines valides,
élimine les sous-domaines redondants via un trie, et génère un fichier
de sortie unique ainsi qu'un README mis à jour.
"""

from __future__ import annotations

import concurrent.futures
import re
import ipaddress
import locale
import urllib.error
import urllib.request
from datetime import datetime

locale.setlocale(locale.LC_TIME, "fr_FR.UTF-8")

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

########### blocklists incluses ###########
# AWAvenue Ads Rule
# AdGuard DNS filter
# AdGuard French adservers
# Dan Pollock's List
# Dandelion Sprout's Anti Malware List
# Dandelion Sprout's Anti Push Notifications
# Easylist FR
# HaGeZi's Amazon Tracker DNS Blocklist
# HaGeZi's Apple Tracker DNS Blocklist
# HaGeZi's Badware Hoster Blocklist
# HaGeZi's DynDNS Blocklist
# HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass
# HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass DNS Blocklist
# HaGeZi's Normal DNS Blocklist
# HaGeZi's Pop-Up Ads DNS Blocklist
# HaGeZi's TikTok Extended Fingerprinting DNS Blocklist
# HaGeZi's Windows/Office Tracker DNS Blocklist
# Malicious URL Blocklist (URLHaus)
# OISD Small
# Peter Lowe's Blocklist
# Phishing Army
# Phishing URL Blocklist (PhishTank and OpenPhish)
# Red Flags Domains
# Scam Blocklist by DurableNapkin
# ShadowWhisperer's Malware List
# Stalkerware Indicators List
# Steven Black's List
# The Big List of Hacked Malware Web Sites
# d3Host

BLOCKLIST_URLS: list[str] = [
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
    "https://dl.red.flag.domains/red.flag.domains_fr.txt",
]

# Regex pré-compilées au niveau module pour éviter la recompilation à chaque appel
_RE_WHITESPACE = re.compile(r"\s+")
_RE_DOMAIN_ONLY = re.compile(r"^[a-zA-Z0-9.-]+$")
_RE_VALID_DOMAIN = re.compile(
    r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
)

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; blocklist-aggregator/1.0)"}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def is_valid_domain(domain: str) -> bool:
    """Retourne True si `domain` est un nom de domaine valide (ni IP ni wildcard)."""
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    return _RE_VALID_DOMAIN.match(domain) is not None


# ---------------------------------------------------------------------------
# Téléchargement & extraction
# ---------------------------------------------------------------------------


def download_and_extract(url: str) -> set[str]:
    """
    Télécharge une blocklist et extrait les domaines valides.

    Supporte les formats :
    - hosts (0.0.0.0 / 127.0.0.1 <domaine>)
    - AdBlock (||domaine^)
    - liste brute de domaines
    """
    try:
        req = urllib.request.Request(url, headers=_DEFAULT_HEADERS)
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        print(f"Erreur HTTP {exc.code} lors du téléchargement de {url}")
        return set()
    except urllib.error.URLError as exc:
        print(f"Erreur réseau lors du téléchargement de {url} : {exc.reason}")
        return set()
    except TimeoutError:
        print(f"Délai dépassé pour {url}")
        return set()

    rules: set[str] = set()

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("!") or line.startswith("#"):
            continue

        if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
            # Format hosts
            host_parts = _RE_WHITESPACE.split(line)
            if len(host_parts) >= 2:
                target = host_parts[1].strip()
                if "*" not in target and is_valid_domain(target):
                    rules.add(target)

        elif line.startswith("||") and line.endswith("^"):
            # Format AdBlock
            target = line[2:-1]
            if "*" not in target and is_valid_domain(target):
                rules.add(target)

        elif _RE_DOMAIN_ONLY.match(line):
            # Domaine brut
            if "*" not in line and is_valid_domain(line):
                rules.add(line)

    return rules


# ---------------------------------------------------------------------------
# Trie de domaines (déduplication des sous-domaines)
# ---------------------------------------------------------------------------


class DomainTrieNode:
    """Nœud d'un trie de domaines inversés pour éliminer les redondances."""

    __slots__ = ("children", "is_terminal")

    def __init__(self) -> None:
        self.children: dict[str, "DomainTrieNode"] = {}
        self.is_terminal: bool = False

    def insert(self, parts: list[str]) -> bool:
        """
        Insère un domaine (sous forme de labels inversés) dans le trie.

        Retourne False si un domaine parent est déjà présent (redondance).
        """
        node = self
        for part in parts:
            if node.is_terminal:
                return False
            node = node.children.setdefault(part, DomainTrieNode())
        node.is_terminal = True
        return True


def domain_to_parts(domain: str) -> list[str]:
    """Convertit un domaine en liste de labels inversés (ex: 'a.b.com' → ['com','b','a'])."""
    return domain.strip().split(".")[::-1]


# ---------------------------------------------------------------------------
# Écriture de la blocklist
# ---------------------------------------------------------------------------


def write_blocklist(
    entries: set[str],
    output_path: str = "blocklist.txt",
    timestamp: str = "",
) -> None:
    """Écrit les entrées triées dans un fichier au format AdBlock."""
    count = len(entries)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(f"! Agrégation - {timestamp}\n")
        fh.write(f"! {count:06} entrées\n\n")
        for entry in sorted(entries):
            fh.write(f"||{entry.lower()}^\n")


# ---------------------------------------------------------------------------
# Mise à jour du README
# ---------------------------------------------------------------------------


def update_readme(stats: dict[str, int], readme_path: str = "README.md") -> None:
    """Met à jour le tableau de statistiques dans le README entre deux balises HTML."""
    start_tag = "<!-- STATS_START -->"
    end_tag = "<!-- STATS_END -->"

    new_table = (
        "\n"
        "| **filtres uniques sans redondance** |\n"
        "|:------------------------------------:|\n"
        f"| **{stats['after']}** |\n"
    )

    try:
        with open(readme_path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        print(f"README introuvable : {readme_path}")
        return

    start_pos = content.find(start_tag)
    end_pos = content.find(end_tag)

    if start_pos != -1 and end_pos != -1:
        content = content[: start_pos + len(start_tag)] + new_table + content[end_pos:]
    else:
        # Balises absentes : on les ajoute en fin de fichier
        content += f"\n{start_tag}{new_table}{end_tag}\n"

    with open(readme_path, "w", encoding="utf-8") as fh:
        fh.write(content)


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------


def main() -> None:
    """Orchestre le téléchargement, la déduplication et l'écriture de la blocklist."""
    # 1. Téléchargement parallèle
    all_entries: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for entry_set in executor.map(download_and_extract, BLOCKLIST_URLS):
            all_entries.update(entry_set)

    # 2. Déduplication via trie (suppression des sous-domaines redondants)
    trie_root = DomainTrieNode()
    final_entries: set[str] = set()

    for entry in sorted(all_entries, key=lambda e: e.count(".")):
        if is_valid_domain(entry) and trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)

    # 3. Statistiques
    total = len(final_entries)
    timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

    # 4. Écriture de la blocklist
    write_blocklist(final_entries, timestamp=timestamp)
    print(f"✅ blocklist.txt généré : {total} entrées")

    # 5. Mise à jour du README
    update_readme({"after": total})


if __name__ == "__main__":
    main()


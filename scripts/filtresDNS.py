"""
Agrégateur de blocklists DNS au format AdBlock.

Ce script construit une blocklist DNS unique à partir de plusieurs sources
distantes, puis produit un fichier final nettoyé et dédupliqué.

Mécanique générale
------------------
1. Charge les exclusions locales depuis `exclusions.txt`.
2. Télécharge en parallèle toutes les blocklists définies dans `BLOCKLIST_URLS`.
3. Extrait uniquement les domaines valides depuis trois formats supportés :
   - hosts (`0.0.0.0 domaine` ou `127.0.0.1 domaine`)
   - AdBlock (`||domaine^`)
   - domaine brut (`example.com`)
4. Ignore tout ce qui n'est pas un domaine exploitable :
   - lignes vides
   - commentaires
   - IP
   - wildcards (`*`)
   - domaines invalides ou mal formés
5. Applique les exclusions AVANT la déduplication :
   - retire le domaine exact s'il est dans `exclusions.txt`
   - retire aussi tous ses sous-domaines
6. Déduplique ensuite par couverture DNS :
   - si `example.com` est conservé, `sub.example.com` devient redondant
   - seuls les domaines les plus généraux utiles sont gardés
7. Écrit le résultat final dans `filtresDNS.txt` au format AdBlock.
8. Met à jour le `README.md` avec le nombre final d'entrées.

Ce qui est inclus
-----------------
- Les domaines valides extraits des URLs de `BLOCKLIST_URLS`
- Les entrées au format hosts, AdBlock et domaine brut
- Les domaines uniques non exclus
- Les domaines parents conservés en priorité sur leurs sous-domaines

Ce qui est exclu ou ignoré
--------------------------
- Les lignes vides
- Les commentaires
- Les adresses IP
- Les règles contenant `*`
- Les domaines invalides selon le validateur du script
- Les domaines présents dans `exclusions.txt`
- Les sous-domaines d'un domaine exclu

Ce qui est retiré du résultat final
-----------------------------------
- Les entrées invalides détectées à l'extraction
- Les entrées explicitement exclues
- Les sous-domaines rendus inutiles par la présence d'un domaine parent

Exemple
-------
Si une source contient :
- `example.com`
- `ads.example.com`
- `track.ads.example.com`

alors le fichier final ne conservera que `example.com`, car il couvre déjà
les sous-domaines dans la logique de blocage DNS utilisée ici.
"""

from __future__ import annotations

import concurrent.futures
import re
import ipaddress
import locale
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

locale.setlocale(locale.LC_TIME, "fr_FR.UTF-8")

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

########### Listes incluses ###########
# AWAvenue Ads Rule
# AdGuard DNS filter
# AdGuard French adservers
# AdGuard French adservers (first-party)
# Dan Pollock's List
# Dandelion Sprout's Anti Push Notifications
# Dandelion Sprout's Anti-Malware List
# EasyList FR
# HaGeZi's Amazon Tracker DNS Blocklist
# HaGeZi's Apple Tracker DNS Blocklist
# HaGeZi's Badware Hoster Blocklist
# HaGeZi's DynDNS Blocklist
# HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass
# HaGeZi's Fake DNS Blocklist
# HaGeZi's Normal DNS Blocklist
# HaGeZi's Pop-Up Ads DNS Blocklist
# HaGeZi's TikTok Extended Fingerprinting DNS Blocklist
# HaGeZi's Windows/Office Tracker DNS Blocklist
# Malicious URL Blocklist (URLHaus)
# OISD Small
# PbDNS Additional Rules
# Peter Lowe's Blocklist
# Phishing Army
# Phishing URL Blocklist (PhishTank/OpenPhish)
# Red Flag Domains
# Red Flag Domains (FR)
# Scam Blocklist by DurableNapkin
# ShadowWhisperer's Malware List
# Stalkerware Indicators List
# Steven Black's List
# The Big List of Hacked Malware Web Sites
# d3Host

BLOCKLIST_URLS: list[str] = [
"https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/fake.txt",
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
# Chargement des exclusions
# ---------------------------------------------------------------------------

def load_exclusions(exclusions_path: str = "exclusions.txt") -> set[str]:
    """
    Charge les exclusions depuis un fichier local.

    - Ignore les lignes vides et les lignes commençant par '!'.
    - Accepte deux formats :
        * Format AdBlock allowlist : @@||domaine^
        * Format domaine brut      : domaine.tld  (rétrocompatibilité)
    - Retourne un ensemble de domaines en minuscules.
    """
    path = Path(exclusions_path)
    if not path.exists():
        print(f"⚠️ Fichier d'exclusions introuvable : {exclusions_path} — aucune exclusion appliquée")
        return set()

    exclusions: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("!"):
                continue
            # Format AdBlock allowlist : @@||domaine^
            if line.startswith("@@||") and line.endswith("^"):
                domain = line[4:-1]
            else:
                # Rétrocompatibilité : domaine brut sans décorateurs
                domain = line
            exclusions.add(domain.lower())

    print(f"📋 Exclusions chargées : {len(exclusions)} domaine(s)")
    return exclusions

def is_excluded(domain: str, exclusions: set[str]) -> bool:
    """
    Retourne True si `domain` (ou l'un de ses domaines parents) est dans les exclusions.

    Exemple : sub.example.com est exclu si example.com est dans les exclusions,
    car bloquer example.com bloquerait aussi sub.example.com via le trie.
    Cette vérification est symétrique : on retire aussi le domaine exact
    ainsi que tout sous-domaine d'un domaine exclu.
    """
    if domain in exclusions:
        return True
    # Vérifie si un domaine parent est exclu (évite les faux positifs du trie)
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in exclusions:
            return True
    return False

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
    output_path: str = "filtresDNS.txt",
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
    """Met à jour le bloc de statistiques dans le README entre deux balises HTML."""
    start_tag = "<!-- STATS_START -->"
    end_tag = "<!-- STATS_END -->"

    count = stats["after"]
    count_formatted = f"{count:,}".replace(",", "%2C")
    source_count = len(BLOCKLIST_URLS)

    new_table = (
        '<div align="center">\n'
        "\n"
        f"![filtres](https://img.shields.io/badge/filtres%20uniques-{count_formatted}-A43836?style=for-the-badge)\n"
        f"![listes](https://img.shields.io/badge/sources-{source_count}%20listes-E9BD98?style=for-the-badge)\n"
        "![fréquence](https://img.shields.io/badge/mise%20%C3%A0%20jour-quotidienne-F5E6CA?style=for-the-badge)\n"
        "\n"
        "</div>\n"
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
    # 0. Chargement des exclusions
    exclusions = load_exclusions("exclusions.txt")

    # 1. Téléchargement parallèle
    all_entries: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for entry_set in executor.map(download_and_extract, BLOCKLIST_URLS):
            all_entries.update(entry_set)

    # 2. Filtrage des exclusions (avant le trie pour éviter les faux négatifs liés
    #    à la déduplication des sous-domaines)
    if exclusions:
        before_filter = len(all_entries)
        all_entries = {
            domain for domain in all_entries
            if not is_excluded(domain.lower(), exclusions)
        }
        removed = before_filter - len(all_entries)
        print(f"🚫 Exclusions : {removed} domaine(s) retiré(s) de la liste agrégée")

    # 3. Déduplication via trie (suppression des sous-domaines redondants)
    trie_root = DomainTrieNode()
    final_entries: set[str] = set()

    for entry in sorted(all_entries, key=lambda e: e.count(".")):
        if is_valid_domain(entry) and trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)

    # 4. Statistiques
    total = len(final_entries)
    timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

    # 5. Écriture de la blocklist
    write_blocklist(final_entries, timestamp=timestamp)
    print(f"✅ filtresDNS.txt généré : {total} entrées")

    # 6. Mise à jour du README
    update_readme({"after": total})

if __name__ == "__main__":
    main()

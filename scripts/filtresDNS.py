"""
Agrégateur de blocklists DNS au format AdBlock.

Ce script construit une blocklist DNS unique à partir de plusieurs sources
distantes, puis produit un fichier final nettoyé et dédupliqué.

Mécanique générale
------------------
1. Télécharge en parallèle toutes les blocklists définies dans `BLOCKLIST_URLS`.
2. Extrait uniquement les domaines valides depuis trois formats supportés :
   - hosts (`0.0.0.0 domaine` ou `127.0.0.1 domaine`)
   - AdBlock (`||domaine^`)
   - domaine brut (`example.com`)
3. Ignore tout ce qui n'est pas un domaine exploitable :
   - lignes vides
   - commentaires
   - IP
   - wildcards (`*`)
   - domaines invalides ou mal formés
4. Déduplique par couverture DNS :
   - si `example.com` est conservé, `sub.example.com` devient redondant
   - seuls les domaines les plus généraux utiles sont gardés
5. Écrit le résultat final dans `filtresDNS.txt` au format AdBlock.
6. Met à jour le `README.md` avec le nombre final d'entrées.

Ce qui est inclus
-----------------
- Les domaines valides extraits des URLs de `BLOCKLIST_URLS`
- Les entrées au format hosts, AdBlock et domaine brut
- Les domaines uniques
- Les domaines parents conservés en priorité sur leurs sous-domaines

Ce qui est exclu ou ignoré
--------------------------
- Les lignes vides
- Les commentaires
- Les adresses IP
- Les règles contenant `*`
- Les domaines invalides selon le validateur du script

Ce qui est retiré du résultat final
-----------------------------------
- Les entrées invalides détectées à l'extraction
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
import socket
import ssl
import time
import http.client
import urllib.error
import urllib.request
from dataclasses import dataclass
from itertools import islice
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
# KADhosts
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
    "https://raw.githubusercontent.com/FiltersHeroes/KADhosts/refs/heads/master/KADomains.txt",
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

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; blocklist-aggregator/1.1)"}
_REQUEST_TIMEOUT = 30
_MAX_RETRIES = 4
_MAX_WORKERS = 5
_BACKOFF_BASE = 2


@dataclass(slots=True)
class DownloadResult:
    """Résultat détaillé d'un téléchargement de source."""

    url: str
    entries: set[str]
    success: bool
    error: str | None = None
    attempts: int = 1


@dataclass(slots=True)
class DeduplicationStats:
    """Statistiques détaillées de la phase de suppression des redondances."""

    total_examined: int = 0
    total_valid: int = 0
    total_invalid: int = 0
    total_kept: int = 0
    total_redundant: int = 0

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

def download_and_extract(url: str) -> DownloadResult:
    """
    Télécharge une blocklist et extrait les domaines valides.

    Supporte les formats :
      - hosts (0.0.0.0 / 127.0.0.1 <domaine>)
      - AdBlock (||domaine^)
      - liste brute de domaines

    Robustesse ajoutée :
      - plusieurs tentatives en cas d'erreur réseau transitoire
      - backoff exponentiel
      - capture des erreurs SSL / socket / reset de connexion
      - retour structuré pour ne jamais interrompre tout le pipeline
    """
    last_error: str | None = None

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=_DEFAULT_HEADERS)
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as response:
                content = response.read().decode("utf-8", errors="ignore")

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

            return DownloadResult(url=url, entries=rules, success=True, attempts=attempt)

        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            print(f"Erreur HTTP {exc.code} lors du téléchargement de {url} (tentative {attempt}/{_MAX_RETRIES})")
        except urllib.error.URLError as exc:
            last_error = f"URLError: {exc.reason}"
            print(f"Erreur réseau lors du téléchargement de {url} : {exc.reason} (tentative {attempt}/{_MAX_RETRIES})")
        except (
            TimeoutError,
            socket.timeout,
            ConnectionResetError,
            ConnectionAbortedError,
            ConnectionRefusedError,
            ssl.SSLError,
            http.client.HTTPException,
            OSError,
        ) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            print(f"Erreur transitoire pour {url} : {last_error} (tentative {attempt}/{_MAX_RETRIES})")

        if attempt < _MAX_RETRIES:
            time.sleep(_BACKOFF_BASE ** (attempt - 1))

    return DownloadResult(url=url, entries=set(), success=False, error=last_error, attempts=_MAX_RETRIES)

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


def deduplicate_with_logs(entries: set[str]) -> tuple[set[str], DeduplicationStats]:
    """Déduplique les domaines et journalise l'activité de suppression des redondances."""
    trie_root = DomainTrieNode()
    final_entries: set[str] = set()
    stats = DeduplicationStats(total_examined=len(entries))

    sorted_entries = sorted(entries, key=lambda e: (e.count("."), e))
    progress_step = max(1, len(sorted_entries) // 20)
    invalid_examples: list[str] = []

    print(f"🔎 Début de la suppression des redondances : {len(sorted_entries)} domaines candidats")

    for index, entry in enumerate(sorted_entries, start=1):
        if not is_valid_domain(entry):
            stats.total_invalid += 1
            if len(invalid_examples) < 10:
                invalid_examples.append(entry)
            continue

        stats.total_valid += 1

        if trie_root.insert(domain_to_parts(entry)):
            final_entries.add(entry)
            stats.total_kept += 1
        else:
            stats.total_redundant += 1

        if index % progress_step == 0 or index == len(sorted_entries):
            print(
                f"🔁 Déduplication : {index}/{len(sorted_entries)} | "
                f"conservés={stats.total_kept} | redondants={stats.total_redundant} | invalides={stats.total_invalid}"
            )

    print(
        f"✅ Fin de la suppression des redondances : "
        f"{stats.total_kept} conservés, {stats.total_redundant} redondants retirés, {stats.total_invalid} invalides ignorés"
    )


    if invalid_examples:
        print("🧪 Exemples de domaines invalides ignorés : " + ", ".join(invalid_examples))

    return final_entries, stats

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
        "\n"
        '<p align="center">\n'
        f'  <img src="https://img.shields.io/badge/filtres%20uniques-{count_formatted}-A43836?style=for-the-badge" alt="filtres">\n'
        f'  <img src="https://img.shields.io/badge/sources-{source_count}%20listes-E9BD98?style=for-the-badge" alt="listes">\n'
        '  <img src="https://img.shields.io/badge/mise%20%C3%A0%20jour-quotidienne-F5E6CA?style=for-the-badge" alt="fréquence">\n'
        "</p>\n"
        "\n"
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
        content += f"\n{start_tag}{new_table}{end_tag}\n"

    with open(readme_path, "w", encoding="utf-8") as fh:
        fh.write(content)

# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main() -> None:
    """Orchestre le téléchargement, la déduplication et l'écriture de la blocklist."""
    # 1. Téléchargement parallèle, avec isolation des erreurs par source
    all_entries: set[str] = set()
    results: list[DownloadResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        futures = {executor.submit(download_and_extract, url): url for url in BLOCKLIST_URLS}

        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # filet de sécurité supplémentaire
                result = DownloadResult(
                    url=url,
                    entries=set(),
                    success=False,
                    error=f"Unhandled {type(exc).__name__}: {exc}",
                )

            results.append(result)
            all_entries.update(result.entries)

            if result.success:
                print(
                    f"OK: {url} -> {len(result.entries)} domaines "
                    f"(tentative {result.attempts}/{_MAX_RETRIES})"
                )
            else:
                print(f"ÉCHEC: {url} -> {result.error}")

    # 2. Déduplication via trie (suppression des sous-domaines redondants)
    final_entries, dedup_stats = deduplicate_with_logs(all_entries)

    # 3. Statistiques
    total = len(final_entries)
    timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")
    success_count = sum(1 for r in results if r.success)
    failure_count = len(results) - success_count

    # 4. Écriture de la blocklist
    write_blocklist(final_entries, timestamp=timestamp)
    print(f"✅ filtresDNS.txt généré : {total} entrées")
    print(f"Sources OK : {success_count}/{len(results)} | Sources en échec : {failure_count}")
    print(
        f"Déduplication : examinés={dedup_stats.total_examined} | valides={dedup_stats.total_valid} | "
        f"conservés={dedup_stats.total_kept} | redondants={dedup_stats.total_redundant} | invalides={dedup_stats.total_invalid}"
    )

    # 5. Mise à jour du README
    update_readme({"after": total})

    # 6. Échec global uniquement si aucune source n'a pu être récupérée
    if success_count == 0:
        raise SystemExit("Aucune source n'a pu être téléchargée.")


if __name__ == "__main__":
    main()

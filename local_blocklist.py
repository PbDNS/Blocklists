"""
Agrégateur de filtres AdBlock pour usage local (AdGuard / uBlock Origin).

Télécharge plusieurs listes de filtrage AdBlock (tracking, privacy, popups,
annoyances, anti-adblock, paywall), supprime les doublons stricts, les lignes
vides et les commentaires.

Déduplication avancée :
  - Doublons stricts (set)
  - Règles de blocage de domaine redondantes via trie (||sous.domaine^ absorbé
    si ||domaine^ est déjà présent)
  - Règles d'exception en doublon (@@||…^)
  - Normalisation de casse pour les règles purement textuelles
"""

from __future__ import annotations

import concurrent.futures
import re
import ipaddress
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

########### Listes incluses ###########
# AdGuard Tracking Protection Filter
# Easy Privacy
# Online Security Filter
# AdGuard Popup Annoyances
# AdGuard Other Annoyances
# Anti Adblock List
# ByPass Paywalls Clean Filter

BLOCKLIST_URLS: list[tuple[str, str]] = [
    ("AdGuard Tracking Protection Filter",   "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/3_optimized.txt"),
    ("Easy Privacy",                         "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/118_optimized.txt"),
    ("Online Security Filter",               "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/208_optimized.txt"),
    ("AdGuard Popup Annoyances",             "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/19_optimized.txt"),
    ("AdGuard Other Annoyances",             "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/21_optimized.txt"),
    ("Anti Adblock List",                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/207_optimized.txt"),
    ("ByPass Paywalls Clean Filter",         "https://bpc-filter-proxy.wmailrelayb8d890.workers.dev"),
]

OUTPUT_FILE = "local.txt"

# ---------------------------------------------------------------------------
# Regex pré-compilées
# ---------------------------------------------------------------------------

_RE_WHITESPACE       = re.compile(r"\s+")
_RE_DOMAIN_ONLY      = re.compile(r"^[a-zA-Z0-9.-]+$")
_RE_VALID_DOMAIN     = re.compile(
    r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
)
# Règle de blocage de domaine pur (sans options, sans chemin)
_RE_PURE_DOMAIN_RULE = re.compile(r"^\|\|([a-zA-Z0-9._-]+)\^$")
# Règle d'exception de domaine pur
_RE_PURE_ALLOW_RULE  = re.compile(r"^@@\|\|([a-zA-Z0-9._-]+)\^$")

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; local-blocklist/1.0)"}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def is_valid_domain(domain: str) -> bool:
    """Retourne True si *domain* est un FQDN valide (ni IP, ni wildcard)."""
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    return bool(_RE_VALID_DOMAIN.match(domain))


# ---------------------------------------------------------------------------
# Trie de domaines (déduplication des sous-domaines dans les règles ||…^)
# ---------------------------------------------------------------------------

class DomainTrieNode:
    """Nœud d'un trie de domaines inversés."""

    __slots__ = ("children", "is_terminal")

    def __init__(self) -> None:
        self.children: dict[str, "DomainTrieNode"] = {}
        self.is_terminal: bool = False

    def insert(self, parts: list[str]) -> bool:
        """
        Insère un domaine (labels inversés) dans le trie.
        Retourne False si un domaine parent est déjà présent (redondance).
        """
        node = self
        for part in parts:
            if node.is_terminal:
                return False          # parent déjà bloqué → sous-domaine inutile
            node = node.children.setdefault(part, DomainTrieNode())
        node.is_terminal = True
        return True


def _domain_parts(domain: str) -> list[str]:
    """'sub.example.com' → ['com', 'example', 'sub']"""
    return domain.lower().strip().split(".")[::-1]


# ---------------------------------------------------------------------------
# Téléchargement
# ---------------------------------------------------------------------------

def download_list(name: str, url: str) -> list[str]:
    """
    Télécharge une liste et retourne ses lignes brutes (hors commentaires
    et lignes vides).  Les lignes de métadonnées (! Title:, ! Expires:…)
    sont filtrées ici.
    """
    try:
        req = urllib.request.Request(url, headers=_DEFAULT_HEADERS)
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        print(f"  ✗ HTTP {exc.code}  {name}")
        return []
    except urllib.error.URLError as exc:
        print(f"  ✗ Réseau  {name} : {exc.reason}")
        return []
    except TimeoutError:
        print(f"  ✗ Timeout  {name}")
        return []

    lines: list[str] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("!") or line.startswith("#"):
            continue
        lines.append(line)

    print(f"  ✓ {name} — {len(lines):>6} règles brutes")
    return lines


# ---------------------------------------------------------------------------
# Déduplication avancée
# ---------------------------------------------------------------------------

def deduplicate(all_lines: list[str]) -> list[str]:
    """
    Déduplique les règles en plusieurs passes :

    1. Doublon strict (set) — O(1) par règle.
    2. Règles de blocage ||domaine^ : trie pour supprimer les sous-domaines
       redondants (||ads.example.com^ absorbé si ||example.com^ existe).
    3. Règles d'exception @@||domaine^ : même logique par trie séparé.
    4. Normalisation de la casse des règles ||…^ et @@||…^ (tout en minuscules).

    Les règles cosmétiques (##, #@#, #%#…), les règles de réécriture ($),
    les regex (/ … /) et les autres règles avancées sont conservées telles
    quelles après déduplication stricte — elles ne peuvent pas être comparées
    sémantiquement sans un vrai moteur AdBlock.
    """

    # Passe 1 : déduplication stricte + normalisation de casse des domaines
    seen: set[str] = set()
    unique_lines: list[str] = []
    for line in all_lines:
        # Normalisation de casse pour les règles de domaine uniquement
        norm = line
        if _RE_PURE_DOMAIN_RULE.match(line) or _RE_PURE_ALLOW_RULE.match(line):
            norm = line.lower()
        if norm not in seen:
            seen.add(norm)
            unique_lines.append(norm)

    # Passe 2 : séparation des règles de domaine pur des autres
    block_domain_rules: list[str] = []
    allow_domain_rules: list[str] = []
    other_rules: list[str] = []

    for line in unique_lines:
        if _RE_PURE_DOMAIN_RULE.match(line):
            block_domain_rules.append(line)
        elif _RE_PURE_ALLOW_RULE.match(line):
            allow_domain_rules.append(line)
        else:
            other_rules.append(line)

    # Passe 3 : trie sur les règles de blocage ||domaine^
    # Trier par nombre de labels (domaines parents d'abord) pour que le parent
    # soit inséré avant ses sous-domaines.
    block_trie = DomainTrieNode()
    final_block: list[str] = []
    for rule in sorted(block_domain_rules, key=lambda r: r.count(".")):
        m = _RE_PURE_DOMAIN_RULE.match(rule)
        if m:
            domain = m.group(1)
            if is_valid_domain(domain) and block_trie.insert(_domain_parts(domain)):
                final_block.append(rule)

    # Passe 4 : trie sur les règles d'exception @@||domaine^
    allow_trie = DomainTrieNode()
    final_allow: list[str] = []
    for rule in sorted(allow_domain_rules, key=lambda r: r.count(".")):
        m = _RE_PURE_ALLOW_RULE.match(rule)
        if m:
            domain = m.group(1)
            if is_valid_domain(domain) and allow_trie.insert(_domain_parts(domain)):
                final_allow.append(rule)

    return final_block + final_allow + other_rules


# ---------------------------------------------------------------------------
# Écriture
# ---------------------------------------------------------------------------

def write_output(rules: list[str], path: str = OUTPUT_FILE) -> None:
    """Écrit les règles triées dans *path* sans en-tête ni commentaire."""
    # Tri stable : règles de blocage d'abord, puis exceptions, puis le reste
    block   = sorted(r for r in rules if _RE_PURE_DOMAIN_RULE.match(r))
    allow   = sorted(r for r in rules if _RE_PURE_ALLOW_RULE.match(r))
    others  = sorted(r for r in rules
                     if not _RE_PURE_DOMAIN_RULE.match(r)
                     and not _RE_PURE_ALLOW_RULE.match(r))

    with open(path, "w", encoding="utf-8") as fh:
        for rule in block + allow + others:
            fh.write(rule + "\n")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main() -> None:
    print("⬇  Téléchargement des listes…")
    all_raw: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(download_list, name, url): name
                   for name, url in BLOCKLIST_URLS}
        for fut in concurrent.futures.as_completed(futures):
            all_raw.extend(fut.result())

    raw_count = len(all_raw)
    print(f"\n📥 Total brut : {raw_count:,} règles")

    print("🔍 Déduplication…")
    final_rules = deduplicate(all_raw)
    final_count = len(final_rules)

    print(f"✅ Règles finales : {final_count:,}  "
          f"(−{raw_count - final_count:,} redondances supprimées)")

    write_output(final_rules, OUTPUT_FILE)
    print(f"💾 Fichier généré : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

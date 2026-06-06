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

Sortie — deux fichiers sémantiquement distincts :
  - local_network.txt  : règles réseau  (||domaine^, @@||domaine^, règles $options,
                          regex /…/, règles de réécriture)
  - local_cosmetic.txt : règles cosmétiques (##, #@#, #%#//scriptlet, ##+js(…))
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
# AdGuard DNS Filter
# AdGuard Tracking Protection Filter
# Easy Privacy
# Online Security Filter
# AdGuard Popup Annoyances
# AdGuard Other Annoyances
# Anti Adblock List
# ByPass Paywalls Clean Filter

BLOCKLIST_URLS: list[tuple[str, str]] = [
    ("AdGuard DNS Filter",
     "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/2_optimized.txt"),
    ("AdGuard Tracking Protection Filter",
     "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/3_optimized.txt"),
    ("Easy Privacy",
     "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/118_optimized.txt"),
    ("Online Security Filter",
     "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/208_optimized.txt"),
    ("AdGuard Popup Annoyances",
     "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/19_optimized.txt"),
    ("AdGuard Other Annoyances",
     "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/21_optimized.txt"),
    ("Anti Adblock List",
     "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/207_optimized.txt"),
    ("ByPass Paywalls Clean Filter",
     "https://bpc-filter-proxy.wmailrelayb8d890.workers.dev"),
]

OUTPUT_NETWORK  = "local_network.txt"
OUTPUT_COSMETIC = "local_cosmetic.txt"

# ---------------------------------------------------------------------------
# Regex pré-compilées
# ---------------------------------------------------------------------------

_RE_VALID_DOMAIN     = re.compile(
    r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
)
# Règle de blocage de domaine pur  : ||example.com^
_RE_PURE_DOMAIN_RULE = re.compile(r"^\|\|([a-zA-Z0-9._-]+)\^$")
# Règle d'exception de domaine pur : @@||example.com^
_RE_PURE_ALLOW_RULE  = re.compile(r"^@@\|\|([a-zA-Z0-9._-]+)\^$")

# Règles cosmétiques / scriptlets — tout ce qui contient ## #@# #%# ##+js
# On détecte intentionnellement large pour ne rien rater.
_RE_COSMETIC = re.compile(
    r"(?:^|[^!])(?:##|#@#|#\?#|#%#|##\+js\(|#@#\+js\()"
)

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
                return False   # parent déjà bloqué → sous-domaine inutile
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
    et lignes vides).
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
# Classification réseau / cosmétique
# ---------------------------------------------------------------------------

def classify(all_lines: list[str]) -> tuple[list[str], list[str]]:
    """
    Sépare les règles en deux catégories :
      - network  : règles réseau (||…^, @@||…^, /regex/, règles $options, …)
      - cosmetic : règles cosmétiques et scriptlets (##, #@#, #%#, ##+js)

    Critère de classification :
      Une règle est cosmétique si elle contient un séparateur cosmétique
      (##+js, ##, #@#, #?#, #%#) hors contexte de commentaire.
      Tout le reste est réseau.
    """
    network: list[str] = []
    cosmetic: list[str] = []

    for line in all_lines:
        if _RE_COSMETIC.search(line):
            cosmetic.append(line)
        else:
            network.append(line)

    return network, cosmetic


# ---------------------------------------------------------------------------
# Déduplication avancée
# ---------------------------------------------------------------------------

def deduplicate_network(lines: list[str]) -> list[str]:
    """
    Déduplique les règles réseau en trois passes :

    1. Doublon strict (set) + normalisation de casse des règles ||…^ et @@||…^.
    2. Trie sur les règles ||domaine^ pures : sous-domaines redondants supprimés.
    3. Trie sur les règles @@||domaine^ pures : idem.
    """
    # Passe 1 : déduplication stricte
    seen: set[str] = set()
    unique: list[str] = []
    for line in lines:
        norm = line.lower() if (_RE_PURE_DOMAIN_RULE.match(line)
                                or _RE_PURE_ALLOW_RULE.match(line)) else line
        if norm not in seen:
            seen.add(norm)
            unique.append(norm)

    block_pure:  list[str] = []
    allow_pure:  list[str] = []
    other_net:   list[str] = []

    for line in unique:
        if _RE_PURE_DOMAIN_RULE.match(line):
            block_pure.append(line)
        elif _RE_PURE_ALLOW_RULE.match(line):
            allow_pure.append(line)
        else:
            other_net.append(line)

    # Passe 2 : trie blocage
    block_trie = DomainTrieNode()
    final_block: list[str] = []
    for rule in sorted(block_pure, key=lambda r: r.count(".")):
        m = _RE_PURE_DOMAIN_RULE.match(rule)
        if m:
            domain = m.group(1)
            if is_valid_domain(domain) and block_trie.insert(_domain_parts(domain)):
                final_block.append(rule)

    # Passe 3 : trie exceptions
    allow_trie = DomainTrieNode()
    final_allow: list[str] = []
    for rule in sorted(allow_pure, key=lambda r: r.count(".")):
        m = _RE_PURE_ALLOW_RULE.match(rule)
        if m:
            domain = m.group(1)
            if is_valid_domain(domain) and allow_trie.insert(_domain_parts(domain)):
                final_allow.append(rule)

    return final_block + final_allow + other_net


def deduplicate_cosmetic(lines: list[str]) -> list[str]:
    """
    Déduplique les règles cosmétiques par déduplication stricte uniquement.

    Une comparaison sémantique complète nécessiterait un vrai moteur AdBlock ;
    on se limite donc à l'égalité de chaîne (insensible à la casse pour les
    sélecteurs purement ASCII).
    """
    seen: set[str] = set()
    unique: list[str] = []
    for line in lines:
        norm = line.lower()
        if norm not in seen:
            seen.add(norm)
            unique.append(line)   # on conserve la casse d'origine
    return unique


# ---------------------------------------------------------------------------
# Écriture
# ---------------------------------------------------------------------------

def write_output(rules: list[str], path: str) -> None:
    """Écrit les règles dans *path* sans en-tête ni commentaire."""
    with open(path, "w", encoding="utf-8") as fh:
        for rule in rules:
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
    print(f"\n📥 Total brut       : {raw_count:,} règles")

    # Classification
    print("🗂  Classification réseau / cosmétique…")
    network_raw, cosmetic_raw = classify(all_raw)
    print(f"   réseau brut      : {len(network_raw):,} règles")
    print(f"   cosmétique brut  : {len(cosmetic_raw):,} règles")

    # Déduplication
    print("🔍 Déduplication…")
    final_network  = deduplicate_network(network_raw)
    final_cosmetic = deduplicate_cosmetic(cosmetic_raw)

    # Tri final
    def _sort_key_net(r: str) -> tuple[int, str]:
        if _RE_PURE_DOMAIN_RULE.match(r):  return (0, r)
        if _RE_PURE_ALLOW_RULE.match(r):   return (1, r)
        return (2, r)

    final_network.sort(key=_sort_key_net)
    final_cosmetic.sort(key=str.lower)

    net_count = len(final_network)
    cos_count = len(final_cosmetic)

    print(f"\n✅ local_network.txt  : {net_count:,} règles "
          f"(−{len(network_raw)  - net_count:,} redondances)")
    print(f"✅ local_cosmetic.txt : {cos_count:,} règles "
          f"(−{len(cosmetic_raw) - cos_count:,} redondances)")
    print(f"   Total final        : {net_count + cos_count:,} règles")

    write_output(final_network,  OUTPUT_NETWORK)
    write_output(final_cosmetic, OUTPUT_COSMETIC)
    print(f"\n💾 {OUTPUT_NETWORK} et {OUTPUT_COSMETIC} générés.")


if __name__ == "__main__":
    main()

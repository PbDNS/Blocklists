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

Compression par TLD :
  Si le nombre de règles dépasse RULE_LIMIT (150 000), les règles ||domaine^
  dont le TLD figure dans RARE_TLDS sont remplacées par une règle wildcard
  ||*.tld^ unique. Les règles d'exception @@||domaine^ sur ces TLDs sont
  conservées intactes (principe de moindre surprise).
"""

from __future__ import annotations

import concurrent.futures
import re
import ipaddress
import urllib.error
import urllib.request

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

OUTPUT_FILE = "local.txt"

# Seuil de déclenchement de la compression par TLD
RULE_LIMIT = 150_000

# ---------------------------------------------------------------------------
# TLDs rares — à adapter selon les résultats de tests
# Pays asiatiques à faible trafic occidental :
#   .vn  Vietnam
#   .kh  Cambodge
#   .mm  Myanmar
#   .la  Laos
#   .mn  Mongolie
# ---------------------------------------------------------------------------

RARE_TLDS: set[str] = {
    "vn",   # Vietnam
    "kh",   # Cambodge
    "mm",   # Myanmar
    "la",   # Laos
    "mn",   # Mongolie
}

# ---------------------------------------------------------------------------
# Regex pré-compilées
# ---------------------------------------------------------------------------

_RE_VALID_DOMAIN     = re.compile(
    r"^(?!-)(?!.*--)(?!.*\.$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
)
_RE_PURE_DOMAIN_RULE = re.compile(r"^\|\|([a-zA-Z0-9._-]+)\^$")
_RE_PURE_ALLOW_RULE  = re.compile(r"^@@\|\|([a-zA-Z0-9._-]+)\^$")

_DEFAULT_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; local-blocklist/1.0)"}

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def is_valid_domain(domain: str) -> bool:
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    return bool(_RE_VALID_DOMAIN.match(domain))


# ---------------------------------------------------------------------------
# Trie de domaines
# ---------------------------------------------------------------------------

class DomainTrieNode:
    __slots__ = ("children", "is_terminal")

    def __init__(self) -> None:
        self.children: dict[str, "DomainTrieNode"] = {}
        self.is_terminal: bool = False

    def insert(self, parts: list[str]) -> bool:
        node = self
        for part in parts:
            if node.is_terminal:
                return False
            node = node.children.setdefault(part, DomainTrieNode())
        node.is_terminal = True
        return True


def _domain_parts(domain: str) -> list[str]:
    return domain.lower().strip().split(".")[::-1]


# ---------------------------------------------------------------------------
# Téléchargement
# ---------------------------------------------------------------------------

def download_list(name: str, url: str) -> list[str]:
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
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        lines.append(line)

    print(f"  ✓ {name} — {len(lines):>6} règles brutes")
    return lines


# ---------------------------------------------------------------------------
# Déduplication avancée
# ---------------------------------------------------------------------------

def deduplicate(all_lines: list[str]) -> list[str]:
    """
    Passe 1 : déduplication stricte + normalisation de casse ||…^ / @@||…^.
    Passe 2 : trie sur les règles ||domaine^ pures.
    Passe 3 : trie sur les règles @@||domaine^ pures.
    """
    seen: set[str] = set()
    unique: list[str] = []
    for line in all_lines:
        norm = line.lower() if (_RE_PURE_DOMAIN_RULE.match(line)
                                or _RE_PURE_ALLOW_RULE.match(line)) else line
        if norm not in seen:
            seen.add(norm)
            unique.append(norm)

    block_pure:  list[str] = []
    allow_pure:  list[str] = []
    other_rules: list[str] = []

    for line in unique:
        if _RE_PURE_DOMAIN_RULE.match(line):
            block_pure.append(line)
        elif _RE_PURE_ALLOW_RULE.match(line):
            allow_pure.append(line)
        else:
            other_rules.append(line)

    block_trie = DomainTrieNode()
    final_block: list[str] = []
    for rule in sorted(block_pure, key=lambda r: r.count(".")):
        m = _RE_PURE_DOMAIN_RULE.match(rule)
        if m:
            domain = m.group(1)
            if is_valid_domain(domain) and block_trie.insert(_domain_parts(domain)):
                final_block.append(rule)

    allow_trie = DomainTrieNode()
    final_allow: list[str] = []
    for rule in sorted(allow_pure, key=lambda r: r.count(".")):
        m = _RE_PURE_ALLOW_RULE.match(rule)
        if m:
            domain = m.group(1)
            if is_valid_domain(domain) and allow_trie.insert(_domain_parts(domain)):
                final_allow.append(rule)

    return final_block + final_allow + other_rules


# ---------------------------------------------------------------------------
# Compression par TLD
# ---------------------------------------------------------------------------

def compress_by_tld(rules: list[str], rare_tlds: set[str]) -> list[str]:
    """
    Remplace les règles ||domaine.tld^ dont le TLD est dans `rare_tlds` par
    une règle wildcard unique ||*.tld^.

    - Les règles @@||domaine.tld^ (exceptions) sont conservées intactes.
    - Les autres règles (cosmétiques, regex, $options…) ne sont pas touchées.
    """
    kept: list[str] = []
    tlds_to_wildcard: set[str] = set()

    for rule in rules:
        m = _RE_PURE_DOMAIN_RULE.match(rule)
        if m:
            domain = m.group(1)
            tld = domain.rsplit(".", 1)[-1].lower()
            if tld in rare_tlds:
                tlds_to_wildcard.add(tld)
                continue   # règle individuelle abandonnée
        kept.append(rule)

    wildcards = sorted(f"||*.{tld}^" for tld in tlds_to_wildcard)

    print(f"  TLDs compressés    : {sorted(tlds_to_wildcard)}")
    print(f"  Règles wildcard    : {len(wildcards)}")

    return wildcards + kept


# ---------------------------------------------------------------------------
# Écriture
# ---------------------------------------------------------------------------

def _sort_key(r: str) -> tuple[int, str]:
    if r.startswith("||*.")          : return (0, r)   # wildcards TLD en tête
    if _RE_PURE_DOMAIN_RULE.match(r) : return (1, r)
    if _RE_PURE_ALLOW_RULE.match(r)  : return (2, r)
    return (3, r)


def write_output(rules: list[str], path: str = OUTPUT_FILE) -> None:
    """Écrit les règles triées dans *path* sans en-tête ni commentaire."""
    with open(path, "w", encoding="utf-8") as fh:
        for rule in sorted(rules, key=_sort_key):
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

    print("🔍 Déduplication…")
    final_rules = deduplicate(all_raw)
    dedup_count = len(final_rules)
    print(f"   Après dédup      : {dedup_count:,} règles"
          f"  (−{raw_count - dedup_count:,} redondances)")

    if dedup_count > RULE_LIMIT:
        print(f"\n⚠️  Limite {RULE_LIMIT:,} dépassée ({dedup_count:,})."
              f" Compression par TLD…")
        final_rules = compress_by_tld(final_rules, RARE_TLDS)
        final_count = len(final_rules)
        print(f"   Après compression : {final_count:,} règles"
              f"  (−{dedup_count - final_count:,} règles remplacées)")
    else:
        final_count = dedup_count
        print(f"✅ Limite non atteinte ({dedup_count:,} ≤ {RULE_LIMIT:,})"
              f" — compression inutile.")

    write_output(final_rules, OUTPUT_FILE)
    print(f"\n💾 {OUTPUT_FILE} généré : {final_count:,} règles.")


if __name__ == "__main__":
    main()

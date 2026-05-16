import urllib.request
import concurrent.futures
from datetime import datetime
import locale
import re

locale.setlocale(locale.LC_TIME, "fr_FR.UTF-8")

########### listes incluses ###########
# AdGuard Base filter (Safari optimized)
# AdGuard Tracking Protection filter (Safari optimized)
# AdGuard Annoyances filter (Safari optimized)

filter_urls = [
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/2_optimized.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/3_optimized.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/platforms/extension/safari/filters/118_optimized.txt",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}

# Regex : ligne de type ||domain^ (blocage DNS pur)
DOMAIN_BLOCK_RE = re.compile(r"^\|\|[^/\s]+\^[\$|]?.*$")

# Regex : lignes commentaires (!, #) ou metadata AdGuard ([ ... ])
COMMENT_RE = re.compile(r"^[!#]|^\[")


def download_and_extract(url):
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode("utf-8", errors="ignore")
        rules = set()
        for line in content.splitlines():
            line = line.strip()
            # Ignorer lignes vides
            if not line:
                continue
            # Ignorer commentaires et métadonnées
            if COMMENT_RE.match(line):
                continue
            # Ignorer les règles ||domain^
            if DOMAIN_BLOCK_RE.match(line):
                continue
            rules.add(line)
        return rules
    except Exception as e:
        print(f"Erreur lors du téléchargement de {url} : {e}")
        return set()


# ── Agrégation parallèle ──────────────────────────────────────────────────────
all_rules = set()
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(download_and_extract, filter_urls)
    for rule_set in results:
        all_rules.update(rule_set)

total = len(all_rules)
timestamp = datetime.now().strftime("%A %d %B %Y, %H:%M")

# ── Écriture du fichier de sortie ─────────────────────────────────────────────
with open("local-blocklist.txt", "w", encoding="utf-8") as f:
    f.write(f"! Agrégation locale - {timestamp}\n")
    f.write(f"! {total:06} filtres\n\n")
    for rule in sorted(all_rules):
        f.write(f"{rule}\n")

print(f"✅ fichier local-blocklist.txt généré : {total} filtres")


# ── Mise à jour README ────────────────────────────────────────────────────────
def update_readme(total_rules):
    readme_path = "README.md"
    try:
        with open(readme_path, "r") as file:
            content = file.read()
    except FileNotFoundError:
        content = ""

    new_table_content = f"""
| **filtres uniques** |
|:-------------------:|
| **{total_rules}** |
"""

    start_tag = "<!--LOCAL_STATS_START-->"
    end_tag = "<!--LOCAL_STATS_END-->"

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


update_readme(total)

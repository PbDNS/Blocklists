# blocklist.py

import urllib.request
from datetime import datetime

# Liste des URLs des blocklists à fusionner
blocklist_urls = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/popupads.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt",
    "https://small.oisd.nl/"
]

# Conteneur pour les lignes valides
filtered_lines = set()

for url in blocklist_urls:
    try:
        print(f"Téléchargement depuis {url}")
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8')
            for line in content.splitlines():
                line = line.strip()
                # Filtre : ne garder que les lignes commençant par '||' et finissant par '^'
                if line.startswith("||") and line.endswith("^"):
                    filtered_lines.add(line)
    except Exception as e:
        print(f"Erreur lors du téléchargement de {url}: {e}")

# Écriture dans le fichier de sortie
with open("blocklist.txt", "w") as f:
    f.write(f"! Blocklist filtrée - générée le {datetime.utcnow().isoformat()} UTC\n")
    for entry in sorted(filtered_lines):
        f.write(entry + "\n")

print("blocklist.txt générée avec succès.")

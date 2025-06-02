import re
import requests

# Télécharger les fichiers General.txt et blocklist.txt
general_url = 'https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/General.txt'
blocklist_url = 'https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt'

general_txt = requests.get(general_url).text.splitlines()
blocklist_txt = requests.get(blocklist_url).text.splitlines()

# Nettoyage des filtres identiques
general_txt_clean = [line for line in general_txt if line not in blocklist_txt]

# Fonction pour supprimer les sous-domaines
def remove_subdomains_from_general(general_lines, blocklist_lines):
    new_general_lines = []
    for line in general_lines:
        should_add = True
        for block in blocklist_lines:
            # On vérifie si le filtre dans blocklist est un domaine générique (ex: ||example.com^)
            if block.startswith("||") and block.endswith("^"):
                domain = block[2:-1]  # Récupère "example.com" dans "||example.com^"
                if domain in line and re.match(r"^(\|\|)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", line):
                    # Si la ligne dans General.txt contient ce domaine sous forme de sous-domaine
                    if domain not in line:
                        should_add = False
                        break
        if should_add:
            new_general_lines.append(line)
    return new_general_lines

# Enlever les sous-domaines en fonction des filtres de blocklist
general_txt_clean = remove_subdomains_from_general(general_txt_clean, blocklist_txt)

# Sauvegarder le fichier nettoyé
with open('General_clean.txt', 'w') as f:
    for line in general_txt_clean:
        f.write(line + "\n")

print("Le fichier General_clean.txt a été créé avec succès.")

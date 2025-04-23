import urllib.request

def telecharger_blocklist(url):
    with urllib.request.urlopen(url) as response:
        contenu = response.read().decode('utf-8')  # Décoder les octets en texte
    return set(contenu.splitlines())

def ecrire_blocklist(fichier, lignes):
    with open(fichier, 'w') as f:
        for ligne in sorted(lignes):
            f.write(ligne + '\n')

def fusionner_blocklists(urls, fichier_sortie):
    blocklist_combinee = set()

    for url in urls:
        blocklist_combinee.update(telecharger_blocklist(url))

    ecrire_blocklist(fichier_sortie, blocklist_combinee)

if __name__ == "__main__":
    # Liste des URLs des blocklists à fusionner
    urls = [
        'https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt',
        'https://sebsauvage.net/hosts/hosts-adguard',
        'https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/adblock/multi.txt'
    ]

    # Fichier de sortie pour la blocklist fusionnée
    fichier_sortie = 'blocklist_fusionnee.txt'

    fusionner_blocklists(urls, fichier_sortie)
    print(f"La blocklist fusionnée a été écrite dans {fichier_sortie}")

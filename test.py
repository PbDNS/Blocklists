import requests

def nettoyer_fichier(url, output_file):
    # Télécharger le fichier depuis l'URL
    print("Téléchargement du fichier...")
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Erreur lors du téléchargement du fichier : {response.status_code}")
        return

    # Initialiser la liste pour stocker les lignes filtrées
    lignes_filtrées = []

    # Parcourir chaque ligne du fichier téléchargé
    for ligne in response.text.splitlines():
        # Ignorer les lignes de commentaires qui commencent par '!'
        if ligne.startswith('!'):
            continue
        
        # Ignorer les lignes commençant par '||' et finissant par '^'
        if ligne.startswith('||') and ligne.endswith('^'):
            continue
        
        # Ajouter la ligne à la liste si elle ne correspond à aucune condition de suppression
        lignes_filtrées.append(ligne)

    # Effacer le contenu actuel du fichier avant d'écrire les nouvelles lignes
    print(f"Effacement du contenu actuel du fichier '{output_file}'...")

    # Sauvegarder les lignes filtrées dans le fichier de sortie
    print(f"Enregistrement des lignes filtrées dans '{output_file}'...")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for ligne in lignes_filtrées:
                f.write(f"{ligne}\n")
        print(f"Le fichier nettoyé a été sauvegardé dans '{output_file}'.")
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier : {e}")

# URL du fichier à télécharger depuis GitHub
url = 'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt'

# Fichier de sortie
output_file = 'test.txt'

# Exécuter la fonction pour nettoyer le fichier
nettoyer_fichier(url, output_file)

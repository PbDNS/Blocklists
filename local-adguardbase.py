import os
import requests

# URL du fichier source
url = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
# Nom du fichier local
local_file = "local-adguardbase.txt"

def fetch_filter_data():
    """Télécharge les données du fichier source"""
    response = requests.get(url)
    response.raise_for_status()  # Vérifie que la requête a bien réussi
    return response.text.splitlines()

def filter_lines(lines):
    """Filtre les lignes selon les critères définis"""
    return [
        line for line in lines
        if not (line.startswith("||") and line.endswith("^"))  # Ignore les filtres de type DND
        and not line.startswith("!")  # Ignore les commentaires
    ]

def read_local_file():
    """Lit le fichier local pour récupérer les lignes existantes"""
    try:
        with open(local_file, "r") as file:
            return set(file.read().splitlines())
    except FileNotFoundError:
        return set()  # Si le fichier n'existe pas, on retourne un ensemble vide

def write_local_file(new_lines):
    """Écrit les lignes filtrées dans le fichier local"""
    print(f"Écriture du fichier {local_file}...")  # Débogage pour confirmer l'écriture
    with open(local_file, "w") as file:
        file.write("\n".join(new_lines) + "\n")
    print(f"{local_file} écrit avec succès.")  # Confirmer que l'écriture a eu lieu

def update_local_file():
    """Met à jour le fichier local en comparant avec les nouvelles données"""
    try:
        new_lines = filter_lines(fetch_filter_data())
        print(f"Lignes filtrées obtenues : {len(new_lines)}")  # Affichage du nombre de lignes filtrées

        local_lines = read_local_file()

        # Ajouter les nouvelles lignes et supprimer les anciennes
        updated_lines = list(set(new_lines))  # On utilise un set pour éviter les doublons

        if new_lines != local_lines:  # Si les lignes sont différentes, on met à jour le fichier
            write_local_file(updated_lines)
        else:
            print("Le fichier est déjà à jour, aucune modification nécessaire.")
    except Exception as e:
        print(f"Erreur lors de la mise à jour du fichier : {e}")

if __name__ == "__main__":
    update_local_file()

import requests

# URL du fichier source
url = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
# Nom du fichier local
local_file = "local-adguardbase.txt"

def fetch_filter_data():
    """Télécharge les données du fichier source"""
    response = requests.get(url)
    response.raise_for_status()
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
        return set()

def write_local_file(new_lines):
    """Écrit les lignes filtrées dans le fichier local"""
    with open(local_file, "w") as file:
        file.write("\n".join(new_lines) + "\n")

def update_local_file():
    """Met à jour le fichier local en comparant avec les nouvelles données"""
    new_lines = filter_lines(fetch_filter_data())
    local_lines = read_local_file()

    # Trouver les lignes à ajouter et à supprimer
    lines_to_add = set(new_lines) - local_lines
    lines_to_remove = local_lines - set(new_lines)

    # Ajouter les nouvelles lignes et supprimer les anciennes
    updated_lines = list(set(new_lines))

    # Écrire les résultats dans le fichier local
    write_local_file(updated_lines)

    # Afficher les modifications
    print(f"Lignes ajoutées: {lines_to_add}")
    print(f"Lignes supprimées: {lines_to_remove}")

if __name__ == "__main__":
    update_local_file()

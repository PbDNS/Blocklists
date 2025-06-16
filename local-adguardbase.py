#!/usr/bin/env python3
import requests
import os
import subprocess

# URLs des fichiers sources
BASE_URL = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
BLOCKLIST_URL = "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt"

# Nom du fichier de sortie
OUTPUT_FILE = "local-adguardbase.txt"

def download_file(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.text.splitlines()

def clean_filter(base_lines, blocklist_lines):
    # Supprimer les commentaires
    base_cleaned = [line for line in base_lines if not line.strip().startswith("!")]
    blocklist_cleaned = {line.strip() for line in blocklist_lines if not line.strip().startswith("!")}

    # Supprimer les lignes du blocklist
    filtered_lines = [
        line for line in base_lines
        if line.strip().startswith("!") or line.strip() not in blocklist_cleaned
    ]
    return filtered_lines

def write_output_file(lines):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.writelines(line + "\n" for line in lines)

def update_git():
    try:
        subprocess.run(["git", "add", OUTPUT_FILE], check=True)
        subprocess.run(["git", "commit", "-m", "Update local-adguardbase.txt"], check=True)
        subprocess.run(["git", "push"], check=True)
        print("Fichier mis à jour et envoyé sur GitHub.")
    except subprocess.CalledProcessError as e:
        print("Erreur Git :", e)

def main():
    print("Téléchargement des fichiers...")
    base_lines = download_file(BASE_URL)
    blocklist_lines = download_file(BLOCKLIST_URL)

    print("Nettoyage des filtres...")
    cleaned_lines = clean_filter(base_lines, blocklist_lines)

    print(f"Écriture dans {OUTPUT_FILE}...")
    write_output_file(cleaned_lines)

    print("Mise à jour Git...")
    update_git()

if __name__ == "__main__":
    main()

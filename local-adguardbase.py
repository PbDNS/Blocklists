import requests
import subprocess

BASE_URL = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
BLOCKLIST_URL = "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt"
OUTPUT_FILE = "local-adguardbase.txt"

def download_file(url):
    print(f"🔽 Téléchargement : {url}")
    response = requests.get(url)
    response.raise_for_status()
    return response.text.splitlines()

def clean_filter(base_lines, blocklist_lines):
    # Créer un ensemble des lignes à filtrer (sans les commentaires)
    blocklist_set = {
        line.strip() for line in blocklist_lines
        if line.strip() and not line.strip().startswith("!")
    }

    print(f"📦 Règles à exclure (hors commentaires) : {len(blocklist_set)}")

    # Ne conserver que les lignes non commentées et non présentes dans la blocklist
    result = [
        line for line in base_lines
        if line.strip() and not line.strip().startswith("!") and line.strip() not in blocklist_set
    ]

    print(f"✅ Lignes conservées dans la sortie : {len(result)}")
    return result

def write_output_file(lines):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    print(f"💾 Fichier écrit : {OUTPUT_FILE}")

def git_commit_and_push():
    print("🔁 Vérification des modifications Git...")
    subprocess.run(["git", "add", OUTPUT_FILE], check=True)

    diff_check = subprocess.run(["git", "diff", "--cached", "--quiet"])
    if diff_check.returncode == 0:
        print("📭 Aucun changement détecté. Pas de commit.")
    else:
        subprocess.run(["git", "config", "user.name", "github-actions[bot]"], check=True)
        subprocess.run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], check=True)
        subprocess.run(["git", "commit", "-m", "🔄 Mise à jour automatique de local-adguardbase.txt"], check=True)
        subprocess.run(["git", "push"], check=True)
        print("🚀 Modifications poussées sur GitHub.")

def main():
    try:
        base_lines = download_file(BASE_URL)
        blocklist_lines = download_file(BLOCKLIST_URL)
        cleaned_lines = clean_filter(base_lines, blocklist_lines)
        write_output_file(cleaned_lines)
        git_commit_and_push()
    except Exception as e:
        print(f"❌ Erreur : {e}")
        exit(1)

if __name__ == "__main__":
    main()

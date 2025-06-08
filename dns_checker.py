import sys
import os
import dns.resolver

def check_domain(domain):
    try:
        # Vérifier les enregistrements DNS A
        answers = dns.resolver.resolve(domain, 'A')
        return False  # Domaine vivant (a des enregistrements A)
    except dns.resolver.NXDOMAIN:
        return True  # Domaine mort (non trouvé)
    except dns.resolver.NoAnswer:
        return True  # Pas de réponse, on considère mort
    except dns.resolver.Timeout:
        return False  # Timeout, on considère vivant (ou re-tester ?)
    except Exception:
        return False  # En cas d'autres erreurs, on suppose vivant

def load_dead(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_dead(filename, lines):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

def main():
    if len(sys.argv) < 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1]
    input_file = "blocklist.txt"
    dead_file = "dead.txt"

    if not os.path.exists(input_file):
        print(f"Fichier {input_file} introuvable")
        sys.exit(1)

    # Lire tous les domaines
    with open(input_file, 'r', encoding='utf-8') as f:
        all_domains = [line.strip() for line in f if line.strip()]

    # Filtrer domaines qui commencent par les préfixes donnés
    filtered_domains = [d for d in all_domains if d[0].lower() in prefixes.lower()]

    # Vérifier les domaines et garder ceux "morts"
    dead_domains = []
    for domain in filtered_domains:
        if check_domain(domain):
            dead_domains.append(domain)

    # Charger dead.txt existant
    existing_dead = load_dead(dead_file)

    # Supprimer dans existing_dead toutes les lignes qui commencent par ces préfixes
    updated_dead = [line for line in existing_dead if line[0].lower() not in prefixes.lower()]

    # Ajouter les nouveaux domaines morts
    updated_dead.extend(dead_domains)

    # Trier et enlever doublons éventuels
    updated_dead = sorted(set(updated_dead))

    # Sauvegarder
    save_dead(dead_file, updated_dead)

if __name__ == "__main__":
    main()

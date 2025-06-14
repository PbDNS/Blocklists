import argparse
import urllib.request
import urllib.parse
import re
import dns.resolver
import ssl
import certifi
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Configuration ===
dns_resolvers = [
    '1.1.1.1',         # Cloudflare
    '8.8.8.8',         # Google
    '9.9.9.9',         # Quad9
    '208.67.222.222',  # OpenDNS
]

adblock_url = 'https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt'

rdtypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']  # Types d'enregistrements à tester

max_workers = 10
tries_per_domain = 3
retry_delay_base = 1
max_retry_delay = 10

# === Fonctions ===

def download_content(url):
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(url, context=ssl_context) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        raise SystemExit(f'Erreur lors du téléchargement : {e}')

def extract_domains(content):
    pattern = re.compile(r'^\|\|([^\^\/]+)\^', re.MULTILINE)
    return set(re.findall(pattern, content))

def resolve_doh(domain, record_type='A'):
    base_url = 'https://cloudflare-dns.com/dns-query'
    params = {'name': domain, 'type': record_type}
    url = f'{base_url}?{urllib.parse.urlencode(params)}'
    headers = {'Accept': 'application/dns-json'}

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.load(response)
            return 'Answer' in data and len(data['Answer']) > 0
    except Exception:
        return False

def _try_resolve(domain, record_type):
    for resolver_ip in dns_resolvers:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        resolver.nameservers = [resolver_ip]
        try:
            answers = resolver.resolve(domain, record_type)
            if answers.rrset:
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue

    # Test via DoH if UDP resolution fails
    if resolve_doh(domain, record_type):
        return True

    return False

def is_domain_resolvable(domain, record_type, tries=tries_per_domain):
    retry_delay = retry_delay_base
    for attempt in range(tries):
        if _try_resolve(domain, record_type):
            return True
        time.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, max_retry_delay)
    return False

def check_domain(domain, record_type):
    if not is_domain_resolvable(domain, record_type):
        return domain, False
    return domain, True

def read_dead_txt():
    try:
        with open('dead.txt', 'r') as file:
            return file.readlines()
    except FileNotFoundError:
        return []

def update_dead_txt(existing_lines, dead_domains, prefixes):
    updated_lines = []
    for line in existing_lines:
        if not any(line.startswith(prefix) for prefix in prefixes):
            updated_lines.append(line)

    for domain in dead_domains:
        if any(domain.startswith(prefix) for prefix in prefixes):
            updated_lines.append(f"{domain}\n")
    
    with open("dead.txt", "w") as f:
        f.writelines(updated_lines)

    print("dead.txt a été mis à jour avec les nouveaux domaines morts.")

def test_domains_with_record_type(domains, record_type):
    dead_domains = []
    total = len(domains)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_domain, domain, record_type): domain for domain in sorted(domains)}
        for i, future in enumerate(as_completed(futures), 1):
            domain, is_alive = future.result()
            if not is_alive:
                dead_domains.append(domain)
                print(f'[{i}/{total}] ❌ Domaine mort : {domain}')
            else:
                print(f'[{i}/{total}] ✅ Domaine actif : {domain}')
    return dead_domains

def main(args):
    print('📥 Téléchargement de la liste des domaines...')
    content = download_content(adblock_url)

    print('🔍 Extraction des domaines...')
    domains = extract_domains(content)

    if args.prefixes:
        print(f'Filtrage des domaines avec les préfixes : {", ".join(args.prefixes)}')
        domains = {domain for domain in domains if any(domain.startswith(prefix) for prefix in args.prefixes)}

    existing_lines = read_dead_txt()

    # Tester les domaines avec chaque type d'enregistrement DNS séquentiellement
    remaining_domains = domains
    for record_type in rdtypes:
        print(f"\n🚀 Test des domaines avec l'enregistrement {record_type}...")
        remaining_domains = test_domains_with_record_type(remaining_domains, record_type)

        # Si aucun domaine ne reste, on peut arrêter
        if not remaining_domains:
            break

    # Mettre à jour dead.txt avec les domaines morts restants
    update_dead_txt(existing_lines, remaining_domains, args.prefixes)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vérifie la disponibilité des domaines avec possibilité de filtrage par préfixe.")
    parser.add_argument(
        'prefixes', 
        nargs='*', 
        help="Liste des préfixes pour filtrer les domaines (par exemple, 'abc', 'xyz'). Par défaut, filtre '0'."
    )

    import sys
    if len(sys.argv) == 1:
        sys.argv.append("0")
    
    args = parser.parse_args()
    main(args)

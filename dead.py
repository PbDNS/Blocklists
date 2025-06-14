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

# === Liste des résolveurs DNS publics non filtrants ===
dns_resolvers = [
    '1.1.1.1',         # Cloudflare
    '1.0.0.1',         # Cloudflare
    '8.8.8.8',         # Google DNS
    '8.8.4.4',         # Google DNS
    '9.9.9.9',         # Quad9
    '208.67.222.222',  # OpenDNS
    '208.67.220.220',  # OpenDNS
    '84.200.69.80',    # DNS.WATCH
    '84.200.70.40',    # DNS.WATCH
    '94.140.14.14',    # AdGuard DNS
    '94.140.15.15',    # AdGuard DNS
    '2606:4700:4700::1111',  # Cloudflare IPv6
    '2606:4700:4700::1001',  # Cloudflare IPv6
    '2001:4860:4860::8888',  # Google IPv6
    '2001:4860:4860::8844',  # Google IPv6
    '2620:fe::fe',            # Quad9 IPv6
    '2620:119:35::35',        # OpenDNS IPv6
    '2620:119:53::53',        # OpenDNS IPv6
    '2001:1608:10:25::1c04:b12f', # DNS.WATCH IPv6
    '2001:1608:10:25::9249:39f6', # DNS.WATCH IPv6
    '2a10:50c0::ad1:ff',      # AdGuard DNS IPv6
    '2a10:50c0::ad2:ff',      # AdGuard DNS IPv6
]

adblock_url = 'https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt'

rdtypes = ('A', 'AAAA', 'CNAME', 'MX', 'TXT')

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

def test_resolvers(dns_resolvers):
    valid_resolvers = []
    test_domain = 'google.com'
    for resolver_ip in dns_resolvers:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        resolver.nameservers = [resolver_ip]
        
        try:
            resolver.resolve(test_domain, 'A')  # Test un simple enregistrement A
            valid_resolvers.append(resolver_ip)
            print(f"✅ Résolveur valide : {resolver_ip}")
        except Exception as e:
            print(f"❌ Résolveur invalide : {resolver_ip} (Erreur: {e})")
    
    return valid_resolvers

def _try_resolve(domain, rdtype, resolvers):
    for resolver_ip in resolvers:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        resolver.nameservers = [resolver_ip]
        
        try:
            answers = resolver.resolve(domain, rdtype)
            if answers.rrset:
                return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.resolver.NoNameservers):
            continue
        except dns.resolver.Timeout as e:
            print(f"❌ Problème de connexion au résolveur DNS {resolver_ip} pour {domain}: {e}")
            continue
        except dns.resolver.NoNameservers as e:
            print(f"❌ Aucun serveur de noms disponible pour {domain} avec le résolveur {resolver_ip}: {e}")
            continue
        except Exception as e:
            print(f"❌ Erreur inconnue avec le résolveur {resolver_ip} pour {domain}: {e}")
            continue

    # Si les résolveurs DNS classiques échouent, essayez la méthode DNS-over-HTTPS
    try:
        if resolve_doh(domain, rdtype):
            return True
    except Exception as e:
        print(f"❌ Erreur de connexion DNS-over-HTTPS pour {domain}: {e}")
    
    return False

def is_domain_resolvable(domain, rdtype, resolvers, tries=tries_per_domain):
    retry_delay = retry_delay_base
    for attempt in range(tries):
        if _try_resolve(domain, rdtype, resolvers):
            return True
        time.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, max_retry_delay)
    return False

def check_domain(domain, rdtype, resolvers):
    if not is_domain_resolvable(domain, rdtype, resolvers):
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

    print(f"dead.txt a été mis à jour avec {len(dead_domains)} nouveaux domaines morts.")

def main(args):
    print('📥 Téléchargement de la liste des domaines...')
    content = download_content(adblock_url)

    print('🔍 Extraction des domaines...')
    domains = extract_domains(content)

    if args.prefixes:
        print(f'Filtrage des domaines avec les préfixes : {", ".join(args.prefixes)}')
        domains = {domain for domain in domains if any(domain.startswith(prefix) for prefix in args.prefixes)}

    print(f'⏳ Vérification des {len(domains)} domaines en parallèle...')

    # Tester les résolveurs DNS avant de commencer les tests
    valid_resolvers = test_resolvers(dns_resolvers)
    if not valid_resolvers:
        print("Aucun résolveur DNS valide trouvé !")
        return

    dead_domains = []
    total = len(domains)

    # Test des domaines avec les différents types de records
    for rdtype in rdtypes:
        print(f'\n🔄 Test des domaines avec le type de record {rdtype}...')

        # Tester les domaines avec ce type de record
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_domain, domain, rdtype, valid_resolvers): domain for domain in sorted(domains)}
            for i, future in enumerate(as_completed(futures), 1):
                domain, is_alive = future.result()
                if not is_alive:
                    dead_domains.append(domain)
                    print(f'[{i}/{total}] ❌ Domaine mort : {domain}')
                else:
                    print(f'[{i}/{total}] ✅ Domaine actif : {domain}')

        # Affichage du nombre de domaines morts après chaque test
        remaining_dead_domains = [domain for domain in dead_domains if domain not in domains]
        print(f"\nAprès le test {rdtype}, {len(remaining_dead_domains)} domaines sont morts.")
        
        # Ne garder que les morts pour le test suivant
        domains = remaining_dead_domains

    print('\n📋 Domaines morts détectés :')
    for dead in dead_domains:
        print(f"- {dead}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Vérifier les domaines morts dans une blocklist.')
    parser.add_argument('--prefixes', nargs='*', help='Préfixes de domaine à filtrer')
    args = parser.parse_args()
    
    main(args)

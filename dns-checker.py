import urllib.request
import re
import dns.resolver
import concurrent.futures
import random
import time
import argparse

# -- CONFIG --
MAX_THREADS = 5  # Limité à 5 threads pour s'assurer que le processus ne surcharge pas GitHub Actions
BATCH_SIZE = 200  # Taille du lot pour chaque exécution en parallèle
TIMEOUT = 1.0  # Timeout pour les résolveurs DNS
CHECK_INTERVAL = 2  # Intervalle entre les vérifications pour éviter la surcharge
TOP_RESOLVERS_COUNT = 5  # Choisir les 5 meilleurs résolveurs DNS

# Liste des résolveurs DNS publics
dns_resolvers_raw = [
    "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
    "208.67.222.222", "208.67.220.220", "2620:0:ccc::2", "2620:0:ccd::2",
    "64.6.64.6", "64.6.65.6", "2620:74:1b::1:1", "2620:74:1c::2:2",
    "84.200.69.80", "84.200.70.40",
    # Ajoute d'autres résolveurs selon tes besoins
]

adblock_url = "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt"

def download_filters(url):
    """Télécharge la liste des filtres depuis l'URL spécifiée."""
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")

def extract_domains(content):
    """Extrait les domaines à partir du contenu du fichier de blocage."""
    pattern = re.compile(r"^\|\|([^\^\/]+)\^", re.MULTILINE)
    return list(set(re.findall(pattern, content)))

def is_resolver_alive(ip):
    """Teste si un résolveur DNS est vivant en vérifiant une résolution de domaine."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ip]
    resolver.timeout = 1.0
    resolver.lifetime = 1.0
    try:
        resolver.resolve('example.com', 'A')
        return True
    except Exception:
        return False

def test_resolver_speed(ip):
    """Teste la vitesse d'un résolveur DNS en mesurant le temps de réponse."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ip]
    start_time = time.time()
    try:
        resolver.resolve('example.com', 'A')
        return time.time() - start_time  # Retourne le temps en secondes
    except Exception:
        return float('inf')  # Si l'appel échoue, retourne une valeur infinie

def filter_best_resolvers(resolvers):
    """Filtre les meilleurs résolveurs DNS en fonction de leur vitesse de réponse."""
    speeds = {ip: test_resolver_speed(ip) for ip in resolvers}
    sorted_resolvers = sorted(speeds.items(), key=lambda x: x[1])
    best_resolvers = [resolver[0] for resolver in sorted_resolvers[:TOP_RESOLVERS_COUNT]]
    return best_resolvers

def prepare_resolvers(resolver_ips):
    """Prépare un objet dns.resolver.Resolver pour chaque IP de résolveur."""
    resolvers = []
    for ip in resolver_ips:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT + 0.3
        resolvers.append(resolver)
    return resolvers

def is_domain_resolvable(domain, resolvers):
    """Vérifie si un domaine est résolvable à l'aide des résolveurs DNS."""
    record_types = ['A', 'AAAA', 'MX', 'TXT']
    for resolver in resolvers:
        for rtype in record_types:
            try:
                resolver.resolve(domain, rtype)
                return True
            except Exception:
                continue
    return False

def check_domain(domain, resolvers):
    """Vérifie la résolution d'un domaine avec un délai entre les vérifications."""
    try:
        if is_domain_resolvable(domain, resolvers):
            return (domain, True)
    except Exception:
        pass
    return (domain, False)

def check_domain_batch(domains, resolvers):
    """Vérifie un lot de domaines en parallèle avec une pause entre les requêtes."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_domain = {executor.submit(check_domain, domain, resolvers): domain for domain in domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain, alive = future.result()
            results[domain] = alive
            time.sleep(CHECK_INTERVAL)  # Ajout d'un délai entre les vérifications pour éviter la surcharge
    return results

def main(batch):
    """Exécute le script principal."""
    content = download_filters(adblock_url)
    domains = extract_domains(content)
    # domains = filter_domains_starting_with_a(domains)  # Filtrer les domaines commençant par "a" - À supprimer !

    alive_resolver_ips = filter_best_resolvers(dns_resolvers_raw)  # Sélectionner les meilleurs résolveurs
    if not alive_resolver_ips:
        print("Aucun résolveur DNS vivant trouvé.")
        return

    resolvers = prepare_resolvers(alive_resolver_ips)

    dead_domains = []
    total = len(domains)

    # Traitement des domaines par lot
    batch_start = batch * BATCH_SIZE
    batch_end = batch_start + BATCH_SIZE
    batch_domains = domains[batch_start:batch_end]
    
    results = check_domain_batch(batch_domains, resolvers)
    for domain, alive in results.items():
        if not alive:
            dead_domains.append(domain)

    # Enregistrer les domaines morts dans un fichier
    with open(f"dead_batch_{batch}.txt", "w") as f:
        for dead in dead_domains:
            f.write(f"{dead}\n")
    print(f"Batch {batch} traité ({batch_start + len(batch_domains)} / {total})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--batch', type=int, required=True, help="Le numéro du batch à traiter")
    args = parser.parse_args()

    main(args.batch)

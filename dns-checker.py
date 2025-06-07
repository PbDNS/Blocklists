import urllib.request
import re
import dns.resolver
import concurrent.futures
import random
import time

# -- CONFIG --
MAX_THREADS = 2  # Réduit à 2 threads pour éviter de surcharger GitHub Actions
BATCH_SIZE = 500  # Réduit la taille des lots pour réduire la charge
TIMEOUT = 1.0  # Augmente le timeout pour les résolveurs DNS
CHECK_INTERVAL = 2  # Intervalle entre les requêtes de vérification de domaine pour éviter les erreurs DNS liées à la surcharge

# Liste des résolveurs DNS publics
dns_resolvers_raw = [
      "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
    "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
    "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
    "208.67.222.222", "208.67.220.220", "2620:0:ccc::2", "2620:0:ccd::2",
    "64.6.64.6", "64.6.65.6", "2620:74:1b::1:1", "2620:74:1c::2:2",
    "84.200.69.80", "84.200.70.40",
    "77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff",
    "94.140.14.14", "94.140.15.15",
    "195.46.39.39", "2a05:d014::",
    "8.26.56.26", "8.20.247.20",
    "37.235.1.174", "37.235.1.177",
    "91.239.100.100", "89.233.43.71",
    "208.76.50.50", "208.76.51.51",
    "156.154.70.1", "156.154.71.1",
    "199.85.126.10", "199.85.127.10",
    "9.9.9.10", "149.112.112.10",
    "185.228.168.9", "185.228.169.9", "2a0d:2a00:1::2", "2a0d:2a00:2::2",
    "76.76.2.0", "76.76.10.0", "2606:1a40::", "2606:1a40:1::",
    "76.76.19.19", "76.223.122.150",
    "194.242.2.2", "2a07:e340::2",
    "185.121.177.177", "169.239.202.202", "94.247.43.254", "192.71.245.208",
    "176.9.93.198", "176.9.1.117", "2a01:4f8:13b:1::119", "2a01:4f8:13b:1::120",
    "193.183.98.66", "2a00:5884:8209::66",
    "38.132.106.139", "194.187.251.67",
    "45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::",
    "116.202.176.26", "116.202.176.26", "2a03:4000:38:1f6::26",
    "8.34.34.34", "8.8.8.8", "8.8.4.4",
    "208.67.222.123", "208.67.220.123",
    "185.222.222.222", "45.11.45.11", "2a09:8840:10::1:1:1", "2a09:8840:10::1:0:1",
    "74.82.42.42", "2001:470:20::2",
    "216.146.35.35", "216.146.36.36",
    "109.69.8.51", "2a00:1508:0:4::9",
    "4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4", "4.2.2.5", "4.2.2.6",
    "149.112.121.10", "2620:10a:80bb::10",
    "156.154.70.5", "156.154.71.5"
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
    resolver.timeout = 0.7
    resolver.lifetime = 1.0
    try:
        resolver.resolve('example.com', 'A')
        return True
    except Exception:
        return False

def filter_alive_resolvers(resolvers):
    """Filtre les résolveurs vivants en parallèle."""
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(is_resolver_alive, ip): ip for ip in resolvers}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                alive.append(futures[future])
    return alive

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

def main():
    """Exécute le script principal."""
    content = download_filters(adblock_url)
    domains = extract_domains(content)

    alive_resolver_ips = filter_alive_resolvers(dns_resolvers_raw)
    if not alive_resolver_ips:
        print("Aucun résolveur DNS vivant trouvé.")
        return

    # Limite à 5 résolveurs vivants choisis aléatoirement
    random.shuffle(alive_resolver_ips)
    selected_resolver_ips = alive_resolver_ips[:5]
    resolvers = prepare_resolvers(selected_resolver_ips)

    dead_domains = []
    total = len(domains)

    for batch_start in range(0, total, BATCH_SIZE):
        batch = domains[batch_start:batch_start + BATCH_SIZE]
        results = check_domain_batch(batch, resolvers)
        for domain, alive in results.items():
            if not alive:
                dead_domains.append(domain)
        print(f"Batch {batch_start // BATCH_SIZE + 1} traité ({batch_start + len(batch)} / {total})")

    # Enregistrer les domaines morts dans un fichier
    with open("dead.txt", "w") as f:
        for dead in dead_domains:
            f.write(f"{dead}\n")
    print(f"Processus terminé. {len(dead_domains)} domaines morts trouvés.")

if __name__ == "__main__":
    main()

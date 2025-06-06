import urllib.request
import re
import dns.resolver
import concurrent.futures

# -- CONFIG --
MAX_THREADS = 100     # Nombre maximum de threads pour accélérer
BATCH_SIZE = 15000    # Taille des lots pour l'exécution par lots
TIMEOUT = 0.7         # Timeout plus court pour les requêtes DNS

# Liste élargie de résolveurs DNS publics "non filtrants"
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
]

adblock_url = "https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/add.txt"

def download_filters(url):
    """Télécharge les filtres depuis l'URL spécifiée."""
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")

def extract_domains(content):
    """Extrait les domaines au format ||example.com^ depuis le contenu des filtres."""
    pattern = re.compile(r"^\|\|([^\^\/]+)\^", re.MULTILINE)
    return list(set(re.findall(pattern, content)))

def is_resolver_alive(ip):
    """Teste si le résolveur DNS spécifié est vivant."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ip]
    resolver.timeout = 0.4
    resolver.lifetime = 0.5
    try:
        resolver.resolve('example.com', 'A')
        return True
    except Exception:
        return False

def filter_alive_resolvers(resolvers):
    """Filtre les résolveurs DNS vivants."""
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(is_resolver_alive, ip): ip for ip in resolvers}
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                alive.append(futures[future])
    return alive

def is_domain_resolvable(domain, resolvers):
    """Vérifie si un domaine est résolvable avec les résolveurs DNS spécifiés."""
    for resolver_ip in resolvers:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolver_ip]
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT + 0.3
        try:
            resolver.resolve(domain, 'A')
            return True
        except Exception:
            pass
        try:
            resolver.resolve(domain, 'AAAA')
            return True
        except Exception:
            pass
        try:
            resolver.resolve(domain, 'MX')
            return True
        except Exception:
            pass
        try:
            resolver.resolve(domain, 'TXT')
            return True
        except Exception:
            pass
    return False

def check_domain(domain, resolvers):
    """Vérifie si un domaine est valide ou mort."""
    try:
        return (domain, is_domain_resolvable(domain, resolvers))
    except Exception:
        return (domain, False)

def main():
    """Fonction principale pour télécharger les filtres, extraire les domaines et les vérifier."""
    content = download_filters(adblock_url)
    domains = extract_domains(content)

    resolvers = filter_alive_resolvers(dns_resolvers_raw)
    if not resolvers:
        return

    dead_domains = []
    total = len(domains)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for batch_start in range(0, total, BATCH_SIZE):
            batch = domains[batch_start:batch_start + BATCH_SIZE]
            futures = {executor.submit(check_domain, d, resolvers): d for d in batch}

            for future in concurrent.futures.as_completed(futures):
                domain, alive = future.result()
                if not alive:
                    dead_domains.append(domain)

    with open("dead.txt", "w") as f:
        for dead in dead_domains:
            f.write(f"{dead}\n")

if __name__ == "__main__":
    main()

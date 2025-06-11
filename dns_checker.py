import dns.resolver
import httpx
import asyncio
import re
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# Liste de résolveurs DNS publics
DNS_SERVERS = [
    "8.8.8.8",    # Google DNS IPv4
    "8.8.4.4",    # Google DNS IPv4
    "1.1.1.1",    # Cloudflare DNS IPv4
    "1.0.0.1",    # Cloudflare DNS IPv4
    "9.9.9.9",    # Quad9 DNS IPv4
    "2001:4860:4860::8888",  # Google DNS IPv6
    "2001:4860:4860::8844",  # Google DNS IPv6
    "2606:4700:4700::1111",  # Cloudflare DNS IPv6
    "2606:4700:4700::1001",  # Cloudflare DNS IPv6
]

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
DNS_TIMEOUT = 8
HTTP_TIMEOUT = 10
MAX_CONCURRENT_DNS = 20  # Augmenter pour plus de parallélisation
MAX_CONCURRENT_HTTP = 10
RETRY_COUNT = 2

# Fonction pour extraire les domaines
def extract_domain(line):
    match = re.match(r"\|\|([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])\^?", line.strip())
    if not match:
        return None
    domain = match.group(1)
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        return domain

# Fonction pour lire les domaines à partir du fichier
def read_domains(prefixes):
    prefixes = tuple(prefixes.lower()) if isinstance(prefixes, str) else tuple()
    domains = set()
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain[0].lower() in prefixes:
                domains.add(domain.lower())
    return sorted(domains)

# Sauvegarde du fichier dead.txt
def save_dead(lines):
    with open(DEAD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(lines))) + '\n')

# Mise à jour de dead.txt
def update_dead_file(prefix, new_dead):
    if os.path.exists(DEAD_FILE):
        with open(DEAD_FILE, 'r', encoding='utf-8') as f:
            existing_dead = [line.strip() for line in f if line.strip()]
    else:
        existing_dead = []

    remaining = [d for d in existing_dead if not d.startswith(prefix)]
    updated = remaining + [d for d in new_dead if d not in remaining]

    save_dead(updated)

# Fonction de vérification DNS avec plusieurs résolveurs
async def dns_check_with_resolvers(domain, record_type):
    for attempt in range(RETRY_COUNT):
        for server in DNS_SERVERS:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [server]
            resolver.lifetime = DNS_TIMEOUT
            try:
                resolver.resolve(domain, record_type)
                return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except Exception:
                if attempt < RETRY_COUNT - 1:
                    continue
                return False  # considérer comme mort si échec

    return False

# Vérification DNS pour un type d'enregistrement
async def filter_dns_dead(domains, record_type):
    print(f"📡 Vérification DNS {record_type} sur {len(domains)} domaines...")
    dead = []
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_DNS)

    async def task(domain):
        async with semaphore:
            alive = await dns_check_with_resolvers(domain, record_type)
            return domain if not alive else None

    tasks = [task(domain) for domain in domains]
    filtered = await asyncio.gather(*tasks)
    return [d for d in filtered if d]

# Vérification HTTP (reste inchangé)
async def check_http(domain):
    VALID_STATUS_CODES = {200, 301, 302, 403, 404, 500}
    urls = [f"http://{domain}", f"https://{domain}"]

    for attempt in range(RETRY_COUNT):
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            for url in urls:
                try:
                    resp = await client.head(url)
                    if resp.status_code in VALID_STATUS_CODES:
                        return True
                except httpx.RequestError:
                    pass

                try:
                    resp = await client.get(url)
                    if resp.status_code in VALID_STATUS_CODES:
                        return True
                except httpx.RequestError:
                    pass
        if attempt < RETRY_COUNT - 1:
            await asyncio.sleep(0.5)

    return False

# Vérification HTTP des domaines morts
async def filter_http_dead(domains):
    print("🌐 Vérification HTTP des domaines...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_HTTP)

    async def task(domain):
        async with semaphore:
            alive = await check_http(domain)
            return domain if not alive else None

    tasks = [task(domain) for domain in domains]
    filtered = await asyncio.gather(*tasks)
    dead_count = len([d for d in filtered if d])
    print(f"→ {dead_count} domaines morts détectés via HTTP.")
    return [d for d in filtered if d]

# Fonction principale
async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1].lower()
    print(f"📥 Chargement des domaines pour les préfixes: {prefixes}")
    domains = read_domains(prefixes)
    print(f"🔎 {len(domains)} domaines à tester.")

    # Vérifications DNS
    dead = await filter_dns_dead(domains, "A")
    update_dead_file(prefixes, dead)

    dead = await filter_dns_dead(dead, "AAAA")
    update_dead_file(prefixes, dead)

    dead = await filter_dns_dead(dead, "MX")
    update_dead_file(prefixes, dead)

    # Vérification HTTP
    dead = await filter_http_dead(dead)
    update_dead_file(prefixes, dead)

    print(f"✅ Final : {len(dead)} domaines morts pour les préfixes {prefixes}.")

if __name__ == "__main__":
    asyncio.run(main())

import sys
import os
import re
import dns.resolver
import httpx
import asyncio
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import time

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
DNS_TIMEOUT = 8
HTTP_TIMEOUT = 10
MAX_CONCURRENT_DNS = 15
MAX_CONCURRENT_HTTP = 10
RETRY_COUNT = 2

# DNS publics IPv4 et IPv6
PUBLIC_DNS_IPV4 = [
    "1.1.1.1",       # Cloudflare
    "8.8.8.8",       # Google
    "9.9.9.9",       # Quad9
    "208.67.222.222",  # OpenDNS
    "94.140.14.14"   # AdGuard
]

PUBLIC_DNS_IPV6 = [
    "2606:4700:4700::1111",  # Cloudflare
    "2001:4860:4860::8888",  # Google
    "2620:fe::fe",           # Quad9
    "2620:119:35::35",       # OpenDNS
    "2a10:50c0::ad1:ff"      # AdGuard
]

def extract_domain(line):
    match = re.match(r"\|\|([a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9])\^?", line.strip())
    if not match:
        return None
    domain = match.group(1)
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        return domain.lower()

def read_domains(prefixes):
    prefixes = tuple(prefixes.lower()) if isinstance(prefixes, str) else tuple()
    domains = set()
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain[0].lower() in prefixes:
                domains.add(domain)
    print(f"Domains found for prefixes {prefixes}: {len(domains)} domains")
    return sorted(domains)

def clean_blocklist(prefixes):
    if not os.path.exists(BLOCKLIST_FILE):
        return
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    filtered = []
    for line in lines:
        domain = extract_domain(line)
        if domain and domain[0].lower() in prefixes:
            continue
        filtered.append(line.strip())
    with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
        if filtered:
            f.write('\n'.join(filtered) + '\n')
        else:
            f.write('')
    print(f"After cleaning, blocklist has {len(filtered)} lines.")

def append_to_blocklist(domains):
    """Ajoute les nouveaux domaines morts dans blocklist.txt au format ||domain^"""
    with open(BLOCKLIST_FILE, "a", encoding="utf-8") as f:
        for domain in sorted(set(domains)):
            f.write(f"||{domain}^\n")
    print(f"Appended {len(domains)} new dead domains to blocklist.txt")

def load_dead():
    if not os.path.exists(DEAD_FILE):
        return []
    with open(DEAD_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_dead(lines):
    with open(DEAD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(lines))) + '\n')

def benchmark_dns_servers(servers, test_domain="google.com", timeout=DNS_TIMEOUT):
    print("⏳ Benchmark DNS pour choisir les meilleurs serveurs...")
    results = []
    resolver_tmp = dns.resolver.Resolver()
    resolver_tmp.lifetime = timeout

    for server in servers:
        resolver_tmp.nameservers = [server]
        start = time.time()
        try:
            resolver_tmp.resolve(test_domain, 'A')
            latency = time.time() - start
            results.append((server, latency))
            print(f"  {server} -> {latency:.3f}s")
        except Exception:
            results.append((server, float('inf')))
            print(f"  {server} -> Timeout/Erreur")

    results.sort(key=lambda x: x[1])
    best_servers = [srv for srv, lat in results if lat != float('inf')]
    return best_servers

def configure_resolver_with_best_dns():
    best_ipv4 = benchmark_dns_servers(PUBLIC_DNS_IPV4)
    best_ipv6 = benchmark_dns_servers(PUBLIC_DNS_IPV6)

    # Prendre 2 meilleurs IPv4 et 2 meilleurs IPv6
    selected_ipv4 = best_ipv4[:2]
    selected_ipv6 = best_ipv6[:2]

    final_servers = selected_ipv4 + selected_ipv6

    # Si pas assez d'IPv4 ou IPv6, compléter avec l'autre type
    if len(selected_ipv4) < 2:
        needed = 2 - len(selected_ipv4)
        final_servers += best_ipv6[:needed]
    if len(selected_ipv6) < 2:
        needed = 2 - len(selected_ipv6)
        final_servers += best_ipv4[:needed]

    # Eviter doublons et limiter à max 4 serveurs
    final_servers = list(dict.fromkeys(final_servers))[:4]

    if not final_servers:
        print("⚠️ Aucun serveur DNS performant trouvé, utilisation des serveurs par défaut.")
        final_servers = PUBLIC_DNS_IPV4[:2] + PUBLIC_DNS_IPV6[:2]

    resolver.nameservers = final_servers
    print(f"✅ Serveurs DNS sélectionnés : {final_servers}")

# Initialisation du resolver global
resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT

def dns_check(domain, record_type):
    for attempt in range(RETRY_COUNT):
        try:
            resolver.resolve(domain, record_type)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            if attempt < RETRY_COUNT - 1:
                continue
            return True  # considérer vivant si doute

def filter_dns_dead(domains, record_type):
    print(f"📡 Vérification DNS {record_type} sur {len(domains)} domaines...")
    dead = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DNS) as executor:
        results = list(executor.map(lambda d: (d, dns_check(d, record_type)), domains))
    for domain, alive in results:
        if not alive:
            dead.append(domain)
    print(f"→ {len(dead)} domaines morts détectés pour DNS {record_type}.")
    return dead

async def check_http(domain):
    VALID_STATUS_CODES = set(range(200, 400))
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
                except Exception as e:
                    print(f"[HEAD] Erreur pour {url} : {e}")
                try:
                    resp = await client.get(url)
                    if resp.status_code in VALID_STATUS_CODES:
                        return True
                except httpx.RequestError:
                    pass
                except Exception as e:
                    print(f"[GET] Erreur pour {url} : {e}")
        if attempt < RETRY_COUNT - 1:
            await asyncio.sleep(0.5)
    return False

async def filter_http_dead(domains):
    print("🌐 Vérification HTTP des domaines...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    async def task(domain):
        async with semaphore:
            alive = await check_http(domain)
            return domain if not alive else None
    tasks = [task(domain) for domain in domains]
    filtered = await asyncio.gather(*tasks)
    dead = [d for d in filtered if d]
    print(f"→ {len(dead)} domaines morts détectés via HTTP.")
    return dead

async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1].lower()

    configure_resolver_with_best_dns()

    print(f"📥 Chargement des domaines pour les préfixes: {prefixes}")
    domains = read_domains(prefixes)
    print(f"🔎 {len(domains)} domaines à tester.")

    dead = filter_dns_dead(domains, "A")
    dead = filter_dns_dead(dead, "AAAA")
    dead = filter_dns_dead(dead, "MX")
    dead = await filter_http_dead(dead)

    print(f"📥 Nettoyage dans blocklist.txt des domaines avec préfixes : {prefixes}")
    clean_blocklist(prefixes)

    print(f"📥 Ajout des domaines morts détectés pour les préfixes : {prefixes}")
    append_to_blocklist(dead)

    print(f"✅ Final : {len(dead)} domaines morts détectés pour les préfixes '{prefixes}'.")

if __name__ == "__main__":
    asyncio.run(main())

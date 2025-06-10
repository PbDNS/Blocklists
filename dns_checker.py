import sys
import os
import re
import dns.resolver
import httpx
import asyncio
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
DNS_TIMEOUT = 8
HTTP_TIMEOUT = 10
MAX_CONCURRENT_DNS = 15
MAX_CONCURRENT_HTTP = 10
RETRY_COUNT = 2
DEBUG = False  # Passe à True pour logs détaillés

# Liste DNS publics non filtrants
PUBLIC_DNS_SERVERS = [
    "1.1.1.1",        # Cloudflare
    "1.0.0.1",        # Cloudflare secondary
    "8.8.8.8",        # Google DNS
    "8.8.4.4",        # Google secondary
    "9.9.9.9",        # Quad9
    "149.112.112.112",# Quad9 secondary
    "208.67.222.222", # OpenDNS
    "208.67.220.220", # OpenDNS secondary
    "64.6.64.6",      # Verisign
    "64.6.65.6",      # Verisign secondary
]

resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT

dns_server_list = []
dns_server_index = 0

def test_dns_latency(dns_ip, test_domain="example.com", record_type="A"):
    test_resolver = dns.resolver.Resolver()
    test_resolver.nameservers = [dns_ip]
    test_resolver.lifetime = 2
    try:
        start = time.monotonic()
        test_resolver.resolve(test_domain, record_type)
        duration = time.monotonic() - start
        if DEBUG:
            print(f"DNS {dns_ip} latency: {duration:.3f}s")
        return duration
    except Exception:
        if DEBUG:
            print(f"DNS {dns_ip} failed latency test")
        return None

def rank_dns_servers(dns_servers):
    latencies = []
    to_test = dns_servers[:5]  # limiter le benchmark à 5 serveurs max
    for dns_ip in to_test:
        latency = test_dns_latency(dns_ip)
        if latency is not None:
            latencies.append((dns_ip, latency))
    latencies.sort(key=lambda x: x[1])
    rest = [ip for ip in dns_servers if ip not in [ip for ip, _ in latencies]]
    ranked = [ip for ip, _ in latencies] + rest
    if DEBUG:
        print("DNS servers ranked by latency:", ranked)
    return ranked

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

def read_domains(prefixes):
    prefixes = tuple(prefixes.lower()) if isinstance(prefixes, str) else tuple()
    domains = set()
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain[0].lower() in prefixes:
                domains.add(domain)
    if DEBUG:
        print(f"Domains found for prefixes {prefixes}: {len(domains)} domains")
    return sorted(domains)

def load_dead():
    if not os.path.exists(DEAD_FILE):
        return []
    with open(DEAD_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_dead(lines):
    with open(DEAD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(lines))) + '\n')

def clean_blocklist(prefixes):
    prefixes = tuple(prefixes.lower()) if isinstance(prefixes, str) else tuple()
    if not os.path.exists(BLOCKLIST_FILE):
        return
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    filtered_lines = [line for line in lines if not (line.startswith("||") and len(line) > 2 and line[2].lower() in prefixes)]
    with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
        f.writelines(filtered_lines)
    print(f"📥 Nettoyage dans {BLOCKLIST_FILE} des domaines avec préfixes : {''.join(prefixes)}")

def update_dead_file(prefixes, new_dead):
    existing_dead = load_dead()
    filtered_dead = [d for d in existing_dead if d[0].lower() not in prefixes]
    updated = filtered_dead + new_dead
    save_dead(updated)

def get_next_dns_server():
    global dns_server_index
    if not dns_server_list:
        return None
    server = dns_server_list[dns_server_index]
    dns_server_index = (dns_server_index + 1) % len(dns_server_list)
    return server

def dns_check(domain, record_type):
    for attempt in range(RETRY_COUNT):
        try:
            dns_server = get_next_dns_server()
            if dns_server:
                resolver.nameservers = [dns_server]
            resolver.resolve(domain, record_type)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            if attempt < RETRY_COUNT - 1:
                continue
            return True

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
                    if DEBUG:
                        print(f"[HEAD] Erreur pour {url} : {e}")

                try:
                    resp = await client.get(url)
                    if resp.status_code in VALID_STATUS_CODES:
                        return True
                except httpx.RequestError:
                    pass
                except Exception as e:
                    if DEBUG:
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
    dead_count = len([d for d in filtered if d])
    print(f"→ {dead_count} domaines morts détectés via HTTP.")
    return [d for d in filtered if d]

async def main():
    global dns_server_list

    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1].lower()

    print(f"📥 Nettoyage dans {BLOCKLIST_FILE} des domaines avec préfixes : {prefixes}")
    clean_blocklist(prefixes)

    print(f"📥 Chargement des domaines pour les préfixes: {prefixes}")
    domains = read_domains(prefixes)
    print(f"🔎 {len(domains)} domaines à tester.")

    # Trier et choisir les DNS avant les vérifications
    print("⏳ Benchmark DNS pour choisir les meilleurs serveurs...")
    dns_server_list = rank_dns_servers(PUBLIC_DNS_SERVERS)

    dead = filter_dns_dead(domains, "A")
    update_dead_file(prefixes, dead)

    dead = filter_dns_dead(dead, "AAAA")
    update_dead_file(prefixes, dead)

    dead = filter_dns_dead(dead, "MX")
    update_dead_file(prefixes, dead)

    dead = await filter_http_dead(dead)
    update_dead_file(prefixes, dead)

    print(f"✅ Final : {len(dead)} domaines morts détectés pour les préfixes '{prefixes}'.")

if __name__ == "__main__":
    asyncio.run(main())

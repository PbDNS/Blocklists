import sys
import os
import re
import dns.resolver
import httpx
import asyncio
import ipaddress
from pathlib import Path

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
DNS_TIMEOUT = 3
HTTP_TIMEOUT = 3
MAX_CONCURRENT_QUERIES = 50
MAX_CONCURRENT_HTTP = 30

def extract_domain(line):
    match = re.match(r"\|\|([a-zA-Z0-9\.-]+)\^?", line.strip())
    if not match:
        return None
    domain = match.group(1)
    try:
        ipaddress.ip_address(domain)  # Ignore IP addresses
        return None
    except ValueError:
        return domain.lower()

def read_domains(prefixes):
    prefixes = tuple(prefixes.lower())
    domains = set()
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain[0].lower() in prefixes:
                domains.add(domain)
    return sorted(domains)

def load_dead():
    if not os.path.exists(DEAD_FILE):
        return []
    with open(DEAD_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def save_dead(lines):
    with open(DEAD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(lines))) + '\n')

def update_dead_file(prefixes, new_dead):
    existing_dead = load_dead()
    filtered_dead = [d for d in existing_dead if d[0].lower() not in prefixes]
    updated = filtered_dead + new_dead
    save_dead(updated)

def dns_check(domain, record_type):
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = DNS_TIMEOUT
        resolver.resolve(domain, record_type)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except:
        return True  # Considérer vivant en cas de doute

def filter_dns_dead(domains, record_type):
    print(f"📡 Vérification DNS {record_type} sur {len(domains)} domaines...")
    dead = []
    for domain in domains:
        if not dns_check(domain, record_type):
            dead.append(domain)
    return dead

async def check_http(domain):
    urls = [f"http://{domain}", f"https://{domain}"]
    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
                resp = await client.head(url)
                if resp.status_code < 500:
                    return True
        except:
            continue
    return False

async def filter_http_dead(domains):
    print("🌐 Vérification HTTP des domaines...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_HTTP)
    results = []

    async def task(domain):
        async with semaphore:
            alive = await check_http(domain)
            return domain if not alive else None

    tasks = [task(domain) for domain in domains]
    filtered = await asyncio.gather(*tasks)
    return [d for d in filtered if d]

async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1].lower()
    domains = read_domains(prefixes)

    print(f"🔎 {len(domains)} domaines à tester pour les préfixes: {prefixes}")

    dead = filter_dns_dead(domains, "A")
    update_dead_file(prefixes, dead)

    dead = filter_dns_dead(dead, "AAAA")
    update_dead_file(prefixes, dead)

    dead = filter_dns_dead(dead, "MX")
    update_dead_file(prefixes, dead)

    dead = await filter_http_dead(dead)
    update_dead_file(prefixes, dead)

    print(f"✅ Final : {len(dead)} domaines morts pour les préfixes {prefixes}.")

if __name__ == "__main__":
    asyncio.run(main())

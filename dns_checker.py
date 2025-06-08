import sys
import os
import re
import dns.resolver
import httpx
import asyncio
import ipaddress
import whois
from concurrent.futures import ThreadPoolExecutor

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
DNS_TIMEOUT = 3
HTTP_TIMEOUT = 3
MAX_CONCURRENT_DNS = 50
MAX_CONCURRENT_HTTP = 50

def extract_domain(line):
    match = re.match(r"\|\|([a-zA-Z0-9.-]+)\^?", line.strip())
    if not match:
        return None
    domain = match.group(1)
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        return domain

def read_domains(prefixes):
    prefixes = tuple(prefixes.lower())
    domains = set()
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain[0].lower() in prefixes:
                domains.add(domain.lower())
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

resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT

def dns_check(domain, record_type):
    try:
        resolver.resolve(domain, record_type)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except:
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
    VALID_STATUS_CODES = {200, 301, 302}
    urls = [f"http://{domain}", f"https://{domain}"]
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

def is_expired(domain):
    try:
        info = whois.whois(domain)
        if not info or not info.domain_name:
            return True
        if hasattr(info, 'text') and info.text:
            text_upper = info.text.upper()
            if "NO MATCH FOR" in text_upper or "NOT FOUND" in text_upper:
                return True
        return False
    except Exception as e:
        print(f"[WHOIS] Erreur pour {domain} : {e}")
        return False

def filter_whois_dead(domains):
    print("🔍 Vérification WHOIS des domaines...")
    dead = []
    for domain in domains:
        if is_expired(domain):
            dead.append(domain)
    print(f"→ {len(dead)} domaines morts détectés via WHOIS.")
    return dead

async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1].lower()

    print(f"📥 Chargement des domaines pour les préfixes: {prefixes}")
    domains = read_domains(prefixes)
    print(f"🔎 {len(domains)} domaines à tester.")

    dead = filter_dns_dead(domains, "A")
    update_dead_file(prefixes, dead)

    dead = filter_dns_dead(dead, "AAAA")
    update_dead_file(prefixes, dead)

    dead = filter_dns_dead(dead, "MX")
    update_dead_file(prefixes, dead)

    dead = await filter_http_dead(dead)
    update_dead_file(prefixes, dead)

    dead = filter_whois_dead(dead)
    update_dead_file(prefixes, dead)

    print(f"✅ Final : {len(dead)} domaines morts pour les préfixes {prefixes}.")

if __name__ == "__main__":
    asyncio.run(main())

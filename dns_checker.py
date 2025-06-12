import sys
import os
import re
import dns.resolver
import httpx
import asyncio
from concurrent.futures import ThreadPoolExecutor

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
DNS_TIMEOUT = 3
HTTP_TIMEOUT = 3
MAX_CONCURRENT_DNS = 10
MAX_CONCURRENT_HTTP = 5
DNS_RETRIES = 2
HTTP_RETRIES = 2

def extract_domain(line):
    match = re.match(r"\|\|([a-zA-Z0-9.-]+)\^?", line.strip())
    return match.group(1) if match else None

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
    for attempt in range(1, DNS_RETRIES + 1):
        try:
            resolver.resolve(domain, record_type)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception as e:
            if attempt == DNS_RETRIES:
                # En cas d’erreur persistante, considérer vivant par prudence
                return True
            # Sinon, retry
    return True  # Par défaut, considérer vivant

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
    urls = [f"http://{domain}", f"https://{domain}"]
    valid_codes = {200, 301, 302, 401, 403}

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        for url in urls:
            for attempt in range(1, HTTP_RETRIES + 1):
                try:
                    resp = await client.get(url)
                    if resp.status_code in valid_codes:
                        return True
                    else:
                        # Code non valide => ne continue pas avec ce url, essaie le suivant
                        break
                except Exception:
                    if attempt == HTTP_RETRIES:
                        # Dernier essai raté, on continue avec url suivant ou retourne False si tous échouent
                        continue
                    # Retry sur la même url
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

    print(f"✅ Final : {len(dead)} domaines morts pour les préfixes {prefixes}.")

if __name__ == "__main__":
    asyncio.run(main())

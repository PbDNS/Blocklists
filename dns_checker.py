import sys
import os
import re
import dns.resolver
import httpx
import asyncio
import whois
from concurrent.futures import ThreadPoolExecutor

# Fichiers
BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"

# Réglages
DNS_TIMEOUT = 10
HTTP_TIMEOUT = 10
MAX_CONCURRENT_DNS = 8
MAX_CONCURRENT_HTTP = 5
DNS_RETRIES = 2
HTTP_RETRIES = 2
WHOIS_WORKERS = 8

# WHOIS : TLDs non fiables
SKIP_WHOIS_TLDS = [".dev", ".app", ".page", ".ai", ".xyz", ".cloud", ".online", ".store"]

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

# DNS
resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT

def dns_check(domain, record_type):
    for attempt in range(1, DNS_RETRIES + 1):
        try:
            resolver.resolve(domain, record_type)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            if attempt == DNS_RETRIES:
                return True
    return True

def filter_dns_dead(domains, record_type):
    print(f"📡 Étape DNS {record_type} — Début avec {len(domains)} domaines...")
    dead = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DNS) as executor:
        results = list(executor.map(lambda d: (d, dns_check(d, record_type)), domains))

    for domain, alive in results:
        if not alive:
            dead.append(domain)

    print(f"🧹 Supprimés (DNS {record_type}) : {len(dead)} — Restants : {len(domains) - len(dead)}\n")
    return dead

# HTTP
async def check_http(domain):
    urls = [f"http://{domain}", f"https://{domain}"]
    valid_codes = {200, 301, 302, 401, 403}

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        for url in urls:
            for attempt in range(HTTP_RETRIES):
                try:
                    resp = await client.get(url)
                    if resp.status_code in valid_codes:
                        return True
                    else:
                        break
                except:
                    continue
    return False

async def filter_http_dead(domains):
    print(f"🌐 Étape HTTP — Début avec {len(domains)} domaines...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_HTTP)

    async def task(domain):
        async with semaphore:
            alive = await check_http(domain)
            return domain if not alive else None

    tasks = [task(domain) for domain in domains]
    results = await asyncio.gather(*tasks)
    dead = [d for d in results if d]
    print(f"🧹 Supprimés (HTTP) : {len(dead)} — Restants : {len(domains) - len(dead)}\n")
    return dead

# WHOIS
def is_tld_ignored(domain):
    return any(domain.endswith(tld) for tld in SKIP_WHOIS_TLDS)

def whois_check(domain):
    if is_tld_ignored(domain):
        print(f"⏭️ TLD ignoré pour WHOIS : {domain}")
        return None  # Ne pas inclure dans les morts

    try:
        info = whois.whois(domain)
        if not info or not info.domain_name:
            return domain
    except Exception:
        return domain
    return None

def filter_whois_dead(domains):
    print(f"🔍 Étape WHOIS — Début avec {len(domains)} domaines...")
    dead = []
    ignored_tlds_count = 0
    with ThreadPoolExecutor(max_workers=WHOIS_WORKERS) as executor:
        results = list(executor.map(whois_check, domains))

    for domain, result in zip(domains, results):
        if is_tld_ignored(domain):
            ignored_tlds_count += 1
        elif result:
            dead.append(result)

    print(f"⏭️ TLD ignorés : {ignored_tlds_count}")
    print(f"🧹 Supprimés (WHOIS) : {len(dead)} — Restants : {len(domains) - len(dead) - ignored_tlds_count}\n")
    return dead

# MAIN
async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker_plus.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1].lower()
    print(f"Préfixes utilisés : {prefixes}")
    domains = read_domains(prefixes)
    print(f"🔎 Total initial : {len(domains)} domaines à tester.\n")

    dead_all = set()

    # DNS A
    dead_dns_a = filter_dns_dead(domains, "A")
    dead_all.update(dead_dns_a)
    domains = [d for d in domains if d not in dead_dns_a]

    # DNS AAAA
    dead_dns_aaaa = filter_dns_dead(domains, "AAAA")
    dead_all.update(dead_dns_aaaa)
    domains = [d for d in domains if d not in dead_dns_aaaa]

    # DNS MX
    dead_dns_mx = filter_dns_dead(domains, "MX")
    dead_all.update(dead_dns_mx)
    domains = [d for d in domains if d not in dead_dns_mx]

    # HTTP
    dead_http = await filter_http_dead(domains)
    dead_all.update(dead_http)
    domains = [d for d in domains if d not in dead_http]

    # WHOIS
    dead_whois = filter_whois_dead(domains)
    dead_all.update(dead_whois)
    domains = [d for d in domains if d not in dead_whois]

    print(f"✅ Analyse terminée : {len(dead_all)} domaines morts détectés.\n")

    update_dead_file(prefixes, list(dead_all))
    print(f"💾 Mise à jour dans {DEAD_FILE}")

if __name__ == "__main__":
    asyncio.run(main())

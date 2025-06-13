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
    return match.group(1).lower() if match else None

def read_domains(prefixes):
    prefixes_set = set(prefixes.lower())
    domains = set()
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain[0].lower() in prefixes_set:
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

def update_dead_file(prefixes_str, new_dead):
    prefixes = set(prefixes_str.lower())
    existing_dead = load_dead()
    # Supprimer les domaines existants avec ces préfixes
    filtered_dead = [d for d in existing_dead if d[0].lower() not in prefixes]
    # Ajouter uniquement les nouveaux domaines morts
    updated = sorted(set(filtered_dead + list(new_dead)))
    save_dead(updated)

# DNS
resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT

def dns_check(domain, record_type):
    for attempt in range(DNS_RETRIES):
        try:
            resolver.resolve(domain, record_type)
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            if attempt == DNS_RETRIES - 1:
                return True
    return True

def filter_dns_dead(domains, record_type):
    print(f"\n📡 Étape DNS {record_type} — Début avec {len(domains)} domaines...")
    dead = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DNS) as executor:
        results = list(executor.map(lambda d: (d, dns_check(d, record_type)), domains))
    for domain, alive in results:
        if not alive:
            dead.append(domain)
    alive = [d for d, ok in results if ok]
    print(f"🧹 Supprimés (DNS {record_type}) : {len(dead)} — Restants : {len(alive)}")
    return alive, dead

# HTTP
async def check_http(domain):
    urls = [f"http://{domain}", f"https://{domain}"]
    valid_codes = {200, 301, 302, 401, 403}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        for url in urls:
            for _ in range(HTTP_RETRIES):
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
    print(f"\n🌐 Étape HTTP — Début avec {len(domains)} domaines...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_HTTP)

    async def task(domain):
        async with semaphore:
            alive = await check_http(domain)
            return (domain, alive)

    results = await asyncio.gather(*[task(d) for d in domains])
    alive = [d for d, ok in results if ok]
    dead = [d for d, ok in results if not ok]
    print(f"🧹 Supprimés (HTTP) : {len(dead)} — Restants : {len(alive)}")
    return alive, dead

# WHOIS
def is_tld_ignored(domain):
    return any(domain.endswith(tld) for tld in SKIP_WHOIS_TLDS)

def whois_check(domain):
    if is_tld_ignored(domain):
        return None, True
    try:
        info = whois.whois(domain)
        if not info or not info.domain_name:
            return domain, False
    except Exception:
        return domain, False
    return None, False

def filter_whois_dead(domains):
    print(f"\n🔍 Étape WHOIS — Début avec {len(domains)} domaines...")
    dead = []
    ignored = 0
    with ThreadPoolExecutor(max_workers=WHOIS_WORKERS) as executor:
        results = executor.map(whois_check, domains)
        for result, was_ignored in results:
            if was_ignored:
                print(f"⏭️ TLD ignoré pour WHOIS : {result}")
                ignored += 1
            elif result:
                dead.append(result)
    alive = [d for d in domains if d not in dead and not is_tld_ignored(d)]
    print(f"🧹 Supprimés (WHOIS) : {len(dead)} — Restants : {len(alive)}")
    print(f"⏭️ TLD ignorés : {ignored}")
    return alive, dead + [d for d in domains if is_tld_ignored(d)]  # considérer les ignorés comme morts aussi

# MAIN
async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1]
    print(f"Préfixes utilisés : {prefixes}")
    domains = read_domains(prefixes)
    total_initial = len(domains)
    print(f"\n🔎 Total initial : {total_initial} domaines à tester.")

    # On fait passer les domaines par les filtres DNS, HTTP, WHOIS
    domains, _ = filter_dns_dead(domains, "A")
    domains, _ = filter_dns_dead(domains, "AAAA")
    domains, _ = filter_dns_dead(domains, "MX")
    domains, _ = await filter_http_dead(domains)
    domains, dead_whois = filter_whois_dead(domains)

    # Le nombre de domaines morts correspond à ceux éliminés après WHOIS (incluant ignorés)
    dead_total = set(dead_whois)

    print(f"\n✅ Analyse terminée : {len(dead_total)} domaines morts détectés.")
    update_dead_file(prefixes, dead_total)
    print("💾 Mise à jour dans dead.txt")

if __name__ == "__main__":
    asyncio.run(main())

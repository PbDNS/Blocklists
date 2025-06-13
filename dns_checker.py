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

# WHOIS : TLDs non fiables (ignorés dans test WHOIS, considérés vivants donc exclus des morts)
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

def update_dead_file(prefixes_str, dead_domains):
    prefixes = set(prefixes_str.lower())
    existing_dead = load_dead()
    # Enlève anciens domaines avec ces préfixes
    filtered_dead = [d for d in existing_dead if d[0].lower() not in prefixes]
    # Ajoute nouveaux morts
    updated = sorted(set(filtered_dead + list(dead_domains)))
    save_dead(updated)

# DNS
resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT

def dns_check(domain, record_type):
    for attempt in range(DNS_RETRIES):
        try:
            resolver.resolve(domain, record_type)
            return True  # vivant
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False  # mort
        except Exception:
            if attempt == DNS_RETRIES - 1:
                return True  # on suppose vivant si erreur persistante
    return True

def filter_dns_dead(domains, record_type):
    print(f"\n📡 Étape DNS {record_type} — Début avec {len(domains)} domaines...")
    dead = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DNS) as executor:
        results = list(executor.map(lambda d: (d, dns_check(d, record_type)), domains))
    for domain, alive in results:
        if not alive:
            dead.append(domain)
    print(f"🧹 Domaines morts (DNS {record_type}) : {len(dead)}")
    return sorted(dead)  # on ne garde QUE les morts

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
                        return True  # vivant
                    else:
                        break
                except:
                    continue
    return False  # mort

async def filter_http_dead(domains):
    print(f"\n🌐 Étape HTTP — Début avec {len(domains)} domaines...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_HTTP)

    async def task(domain):
        async with semaphore:
            alive = await check_http(domain)
            return (domain, alive)

    results = await asyncio.gather(*[task(d) for d in domains])
    dead = [d for d, ok in results if not ok]
    print(f"🧹 Domaines morts (HTTP) : {len(dead)}")
    return sorted(dead)

# WHOIS
def is_tld_ignored(domain):
    return any(domain.endswith(tld) for tld in SKIP_WHOIS_TLDS)

def whois_check(domain):
    if is_tld_ignored(domain):
        # Ignoré : considéré vivant donc exclu des morts
        return None, True
    try:
        info = whois.whois(domain)
        if not info or not info.domain_name:
            return domain, False  # mort
    except Exception:
        return domain, False  # mort
    return None, False  # vivant

def filter_whois_dead(domains):
    print(f"\n🔍 Étape WHOIS — Début avec {len(domains)} domaines...")
    dead = []
    ignored_count = 0
    with ThreadPoolExecutor(max_workers=WHOIS_WORKERS) as executor:
        results = executor.map(whois_check, domains)
        for result, was_ignored in results:
            if was_ignored:
                # On incrémente juste le compteur, sans afficher
                ignored_count += 1
            elif result:
                dead.append(result)
    alive = [d for d in domains if d not in dead and not is_tld_ignored(d)]

    print(f"🧹 Supprimés (WHOIS) : {len(dead)} — Restants : {len(alive)}")
    print(f"⏭️ TLD ignorés : {ignored_count}")

    return alive, dead

# MAIN
async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1]
    print(f"Préfixes utilisés : {prefixes}")

    # 1. Chargement initial
    domains = read_domains(prefixes)
    print(f"\n🔎 Total initial : {len(domains)} domaines à tester.")

    # 2. DNS A
    domains = filter_dns_dead(domains, "A")

    # 3. DNS AAAA
    domains = filter_dns_dead(domains, "AAAA")

    # 4. DNS MX
    domains = filter_dns_dead(domains, "MX")

    # 5. HTTP
    domains = await filter_http_dead(domains)

    # 6. WHOIS
    domains = filter_whois_dead(domains)

    print(f"\n✅ Analyse terminée : {len(domains)} domaines morts détectés.")
    update_dead_file(prefixes, domains)
    print("💾 Mise à jour dans dead.txt")

if __name__ == "__main__":
    asyncio.run(main())

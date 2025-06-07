import asyncio
import aiodns
import os
import random
import re
from pathlib import Path

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
DNS_TIMEOUT = 3
MAX_CONCURRENT_QUERIES = 50  # ← réduit pour éviter plantage GitHub Actions

# Liste de résolveurs DNS publics (IPv4 + IPv6)
RESOLVERS = [
    "1.1.1.1", "1.0.0.1",                      # Cloudflare
    "8.8.8.8", "8.8.4.4",                      # Google
    "9.9.9.9", "149.112.112.112",              # Quad9
    "208.67.222.222", "208.67.220.220",        # OpenDNS
    "94.140.14.14", "94.140.15.15",            # AdGuard
    "185.228.168.9", "185.228.169.9",          # CleanBrowsing
    "84.200.69.80", "84.200.70.40",            # DNS.Watch
    "76.76.2.0", "76.76.10.0",                 # ControlD
    "77.88.8.8", "77.88.8.1",                  # Yandex
    "2620:fe::fe", "2620:fe::9",               # Quad9 IPv6
    "2001:4860:4860::8888", "2001:4860:4860::8844", # Google IPv6
    "2606:4700:4700::1111", "2606:4700:4700::1001", # Cloudflare IPv6
]

def extract_domain(line):
    match = re.match(r"\|\|([a-zA-Z0-9.-]+)\^?", line.strip())
    return match.group(1) if match else None

def read_blocklist_by_letter(letter):
    domains = set()
    with open(BLOCKLIST_FILE, "r") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain.lower().startswith(letter.lower()):
                domains.add(domain)
    return sorted(domains)

def write_dead_domains(domains):
    with open(DEAD_FILE, "w") as f:
        for domain in sorted(domains):
            f.write(domain + "\n")

async def test_resolver(resolver_ip):
    try:
        resolver = aiodns.DNSResolver(nameservers=[resolver_ip], timeout=2)
        await resolver.query("example.com", "A")
        return resolver_ip
    except:
        return None

async def get_working_resolvers():
    print("⏳ Test des résolveurs...")
    tested = await asyncio.gather(*(test_resolver(ip) for ip in RESOLVERS))
    return [r for r in tested if r]

async def resolve_domain(domain, resolvers, record_type, semaphore):
    async with semaphore:
        resolver_ip = random.choice(resolvers)
        try:
            resolver = aiodns.DNSResolver(nameservers=[resolver_ip], timeout=DNS_TIMEOUT)
            await resolver.query(domain, record_type)
            return domain, True
        except:
            return domain, False

async def filter_dead(domains, resolvers, record_type):
    print(f"🔍 Test {record_type} sur {len(domains)} domaines...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)
    tasks = [resolve_domain(domain, resolvers, record_type, semaphore) for domain in domains]
    results = await asyncio.gather(*tasks)
    return [domain for domain, ok in results if not ok]

async def main():
    Path(DEAD_FILE).touch(exist_ok=True)

    print("📥 Chargement des domaines depuis blocklist.txt...")
    domains = read_blocklist_by_letter("a")
    print(f"✅ {len(domains)} domaines valides trouvés commençant par 'a'.")

    # Optionnel pour tests : limiter
    # domains = domains[:100]

    resolvers = await get_working_resolvers()
    if not resolvers:
        print("❌ Aucun résolveur fonctionnel trouvé.")
        return
    print(f"✅ {len(resolvers)} résolveurs DNS prêts.")

    dead = await filter_dead(domains, resolvers, "A")
    dead = await filter_dead(dead, resolvers, "AAAA")
    dead = await filter_dead(dead, resolvers, "MX")

    print(f"☠️ {len(dead)} domaines toujours morts après tous les tests.")

    print("💾 Écriture dans dead.txt...")
    write_dead_domains(dead)
    print("✅ Terminé.")

if __name__ == "__main__":
    asyncio.run(main())

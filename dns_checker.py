import asyncio
import dns.resolver
import random
import re
from pathlib import Path
import httpx

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
MAX_CONCURRENT_QUERIES = 50
DNS_TIMEOUT = 3

RESOLVERS = [
    "1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4", "149.112.112.112",
    "208.67.222.222", "84.200.69.80", "94.140.14.14", "185.228.168.9",
    "76.76.2.0", "77.88.8.8", "2001:4860:4860::8888", "2606:4700:4700::1111"
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

def sync_dns_query(domain, record_type, resolver_ip):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [resolver_ip]
    resolver.lifetime = DNS_TIMEOUT
    try:
        resolver.resolve(domain, record_type)
        return True
    except:
        return False

async def resolve_domain(domain, record_type, semaphore):
    async with semaphore:
        resolver_ip = random.choice(RESOLVERS)
        return domain, await asyncio.to_thread(sync_dns_query, domain, record_type, resolver_ip)

async def filter_dead(domains, record_type):
    print(f"🔍 Test {record_type} sur {len(domains)} domaines...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)
    tasks = [resolve_domain(domain, record_type, semaphore) for domain in domains]
    results = await asyncio.gather(*tasks)
    return [domain for domain, ok in results if not ok]

async def check_http(domain):
    urls = [f"http://{domain}", f"https://{domain}"]
    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.head(url, follow_redirects=True)
                if response.status_code < 500:
                    return True
        except:
            continue
    return False

async def filter_really_dead(domains):
    print("🌐 Vérification HTTP des domaines morts...")
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)
    tasks = []
    for domain in domains:
        async def task(domain=domain):
            async with semaphore:
                alive = await check_http(domain)
                return domain, alive
        tasks.append(task())
    results = await asyncio.gather(*tasks)
    return [domain for domain, is_alive in results if not is_alive]

async def main():
    Path(DEAD_FILE).touch(exist_ok=True)

    print("📥 Lecture blocklist.txt...")
    domains = read_blocklist_by_letter("a")
    print(f"✅ {len(domains)} domaines valides trouvés commençant par 'a'.")

    dead = await filter_dead(domains, "A")
    dead = await filter_dead(dead, "AAAA")
    dead = await filter_dead(dead, "MX")
    dead = await filter_really_dead(dead)

    print(f"☠️ {len(dead)} domaines définitivement morts.")
    write_dead_domains(dead)
    print("✅ Fichier dead.txt mis à jour.")

if __name__ == "__main__":
    asyncio.run(main())

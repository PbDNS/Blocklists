import sys
import os
import re
import dns.resolver
import httpx
import asyncio
import ipaddress
from concurrent.futures import ThreadPoolExecutor

BLOCKLIST_FILE = "blocklist.txt"
DEAD_FILE = "dead.txt"
DNS_TIMEOUT = 8
HTTP_TIMEOUT = 10
MAX_CONCURRENT_DNS = 5  # réduit pour GitHub Actions
MAX_CONCURRENT_HTTP = 3  # réduit pour GitHub Actions
RETRY_COUNT = 2
BATCH_SIZE = 50  # taille des batches

# Extraction d’un domaine (avec sous-domaines) depuis le format ||domaine^
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

# Lecture des domaines selon préfixes donnés (ex: a, b, c...)
def read_domains(prefixes):
    prefixes = tuple(prefixes.lower()) if isinstance(prefixes, str) else tuple()
    domains = set()
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain[0].lower() in prefixes:
                domains.add(domain)
    return sorted(domains)

# Chargement du fichier dead.txt existant
def load_dead():
    if not os.path.exists(DEAD_FILE):
        return []
    with open(DEAD_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

# Sauvegarde du fichier dead.txt
def save_dead(lines):
    with open(DEAD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(lines))) + '\n')

# Mise à jour de dead.txt en conservant les anciens préfixes exclus
def update_dead_file(prefixes, new_dead):
    existing_dead = load_dead()
    filtered_dead = [d for d in existing_dead if d[0].lower() not in prefixes]
    updated = filtered_dead + new_dead
    save_dead(updated)

# Suppression des domaines avec les préfixes donnés dans blocklist.txt avant traitement
def clean_blocklist(prefixes):
    if not os.path.exists(BLOCKLIST_FILE):
        return
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    filtered = []
    for line in lines:
        domain = extract_domain(line)
        if domain and domain[0].lower() in prefixes:
            # on exclut cette ligne (supprime)
            continue
        filtered.append(line.strip())
    with open(BLOCKLIST_FILE, "w", encoding="utf-8") as f:
        f.write('\n'.join(filtered) + ('\n' if filtered else ''))

# Ajoute les domaines morts dans blocklist.txt (au format ||domaine^)
def append_to_blocklist(domains):
    if not domains:
        return
    existing = set()
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
            existing = set(line.strip() for line in f if line.strip())
    with open(BLOCKLIST_FILE, "a", encoding="utf-8") as f:
        for d in domains:
            entry = f"||{d}^"
            if entry not in existing:
                f.write(entry + "\n")

# Configuration du résolveur DNS
resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT
# Optionnel : Utiliser DNS public pour plus de fiabilité
# resolver.nameservers = ['1.1.1.1', '8.8.8.8']

# Vérification DNS simple
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

# Vérifie quels domaines ne répondent pas pour un type d'enregistrement DNS
def filter_dns_dead(domains, record_type):
    if not domains:
        return []
    print(f"📡 Vérification DNS {record_type} sur {len(domains)} domaines...")

    dead = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DNS) as executor:
        results = list(executor.map(lambda d: (d, dns_check(d, record_type)), domains))

    for domain, alive in results:
        if not alive:
            dead.append(domain)

    print(f"→ {len(dead)} domaines morts détectés pour DNS {record_type}.")
    return dead

# Vérification HTTP/HTTPS HEAD/GET
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

# Vérifie quels domaines ne répondent pas en HTTP/HTTPS
async def filter_http_dead(domains):
    if not domains:
        return []
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

# Découpage des domaines en batches
def chunk_domains(domains, chunk_size=BATCH_SIZE):
    for i in range(0, len(domains), chunk_size):
        yield domains[i:i+chunk_size]

# Point d’entrée principal
async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1].lower()
    print(f"📥 Nettoyage dans blocklist.txt des domaines avec préfixes : {prefixes}")
    clean_blocklist(prefixes)

    print(f"📥 Chargement des domaines pour les préfixes: {prefixes}")
    domains = read_domains(prefixes)
    print(f"🔎 {len(domains)} domaines à tester.")

    all_dead = []

    # Traitement par batchs pour limiter la charge réseau
    for batch_num, batch in enumerate(chunk_domains(domains), start=1):
        print(f"\n🔄 Batch {batch_num} - {len(batch)} domaines")

        dead = filter_dns_dead(batch, "A")
        update_dead_file(prefixes, dead)

        dead = filter_dns_dead(dead, "AAAA")
        update_dead_file(prefixes, dead)

        dead = filter_dns_dead(dead, "MX")
        update_dead_file(prefixes, dead)

        dead = await filter_http_dead(dead)
        update_dead_file(prefixes, dead)

        all_dead.extend(dead)

    # Mise à jour finale du blocklist.txt avec tous les domaines morts
    append_to_blocklist(all_dead)

    print(f"\n✅ Final : {len(all_dead)} domaines morts détectés pour les préfixes '{prefixes}'.")

if __name__ == "__main__":
    asyncio.run(main())

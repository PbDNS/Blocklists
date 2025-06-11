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
MAX_CONCURRENT_DNS = 15
MAX_CONCURRENT_HTTP = 10
RETRY_COUNT = 2

# Extraction d’un domaine depuis le format ||domaine^
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

# Lecture des domaines selon préfixes donnés (ex: a, b, c...)
def read_domains(prefixes):
    prefixes = tuple(prefixes.lower()) if isinstance(prefixes, str) else tuple()
    domains = set()
    with open(BLOCKLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = extract_domain(line)
            if domain and domain[0].lower() in prefixes:
                domains.add(domain.lower())
    return sorted(domains)

# Sauvegarde du fichier dead.txt
def save_dead(lines):
    with open(DEAD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(set(lines))) + '\n')

# Mise à jour de dead.txt en supprimant les anciens domaines du préfixe et ajoutant les nouveaux
def update_dead_file(prefix, new_dead):
    # Lire les lignes actuelles de dead.txt
    if os.path.exists(DEAD_FILE):
        with open(DEAD_FILE, 'r', encoding='utf-8') as f:
            existing_dead = [line.strip() for line in f if line.strip()]  # Pas de conversion en minuscule
    else:
        existing_dead = []

    # Supprimer les anciens domaines qui commencent par le préfixe
    remaining = [d for d in existing_dead if not d.startswith(prefix)]  # Comparaison directe sans modification de casse

    # Ajouter les nouveaux domaines morts (éviter les doublons)
    updated = list(set(remaining + list(new_dead)))  # Convertir new_dead en liste avant de concaténer

    # Sauvegarder la nouvelle liste dans dead.txt
    save_dead(updated)

# Configuration du résolveur DNS
resolver = dns.resolver.Resolver()
resolver.lifetime = DNS_TIMEOUT

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
    print(f"📡 Vérification DNS {record_type} sur {len(domains)} domaines...")

    dead = set()  # Utiliser un set pour éviter les doublons
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DNS) as executor:
        results = list(executor.map(lambda d: (d, dns_check(d, record_type)), domains))

    for domain, alive in results:
        if not alive:
            dead.add(domain.lower())  # Ajouter en minuscule pour éviter les doublons de casse

    print(f"→ {len(dead)} domaines morts détectés pour DNS {record_type}.")
    return dead

# Vérification HTTP/HTTPS HEAD/GET
async def check_http(domain):
    # Limiter la plage aux codes de statut HTTP pertinents
    VALID_STATUS_CODES = {200, 301, 302, 403, 404, 500}
    urls = [f"http://{domain}", f"https://{domain}"]

    for attempt in range(RETRY_COUNT):
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            for url in urls:
                try:
                    # Vérification via la méthode HEAD
                    resp = await client.head(url)
                    if resp.status_code in VALID_STATUS_CODES:
                        return True
                except httpx.RequestError:
                    pass
                except Exception as e:
                    print(f"[HEAD] Erreur pour {url} : {e}")

                try:
                    # Vérification via la méthode GET
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

# Point d’entrée principal
async def main():
    if len(sys.argv) != 2:
        print("Usage: python dns_checker.py <prefixes>")
        sys.exit(1)

    prefixes = sys.argv[1].lower()
    print(f"📥 Chargement des domaines pour les préfixes: {prefixes}")
    domains = read_domains(prefixes)
    print(f"🔎 {len(domains)} domaines à tester.")

    # Accumuler les domaines morts
    dead = set()  # Utiliser un set pour éviter les doublons

    # Vérifications DNS pour les enregistrements A, AAAA et MX
    dead.update(filter_dns_dead(domains, "A"))
    dead.update(filter_dns_dead(dead, "AAAA"))
    dead.update(filter_dns_dead(dead, "MX"))

    # Vérification HTTP
    dead.update(await filter_http_dead(dead))

    # Mise à jour de dead.txt avec tous les domaines morts accumulés
    update_dead_file(prefixes, dead)

    print(f"✅ Final : {len(dead)} domaines morts pour les préfixes {prefixes}.")

if __name__ == "__main__":
    asyncio.run(main())

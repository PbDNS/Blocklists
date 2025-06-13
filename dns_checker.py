import asyncio
import os

from modules.load_domains import load_domains
from modules.check_dns import check_dns_a, check_dns_aaaa, check_dns_mx
from modules.check_http import check_http
from modules.check_whois import check_whois


def update_dead_file(prefixes, new_dead):
    # Lire le fichier existant
    old_lines = []
    if os.path.exists("dead.txt"):
        with open("dead.txt", "r") as f:
            old_lines = f.readlines()

    # Supprimer les lignes correspondant aux préfixes actuels
    filtered = []
    for line in old_lines:
        line = line.strip()
        if not any(line.startswith(prefix) for prefix in prefixes):
            filtered.append(line)

    # Ajouter les nouveaux morts
    updated = sorted(set(filtered + list(new_dead)))

    # Réécrire le fichier
    with open("dead.txt", "w") as f:
        for domain in updated:
            f.write(f"{domain}\n")


async def main():
    prefixes = os.getenv("PREFIXES", "0")
    prefix_list = prefixes.split(",")

    print(f"Préfixes utilisés : {prefixes}")
    domains = load_domains(prefix_list)
    print(f"🔎 Total initial : {len(domains)} domaines à tester.\n")

    print(f"📡 Étape DNS A — Début avec {len(domains)} domaines...")
    domains = await check_dns_a(domains)

    print(f"\n📡 Étape DNS AAAA — Début avec {len(domains)} domaines...")
    domains = await check_dns_aaaa(domains)

    print(f"\n📡 Étape DNS MX — Début avec {len(domains)} domaines...")
    domains = await check_dns_mx(domains)

    print(f"\n🌐 Étape HTTP — Début avec {len(domains)} domaines...")
    domains = await check_http(domains)

    print(f"\n🔍 Étape WHOIS — Début avec {len(domains)} domaines...")
    dead_domains, ignored_tlds = await check_whois(domains)

    if ignored_tlds:
        print(f"⏭️ TLD ignorés : {len(ignored_tlds)}")

    print(f"\n✅ Analyse terminée : {len(dead_domains)} domaines morts détectés.")
    update_dead_file(prefix_list, dead_domains)
    print("💾 Mise à jour dans dead.txt")


if __name__ == "__main__":
    asyncio.run(main())

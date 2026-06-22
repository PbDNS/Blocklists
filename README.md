<h1 align="center">🛡️ Listes de filtrage</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Format-Adblock%20Plus-4A919E" alt="Format">
  <img src="https://img.shields.io/badge/Compatibilit%C3%A9-AdGuard%20%7C%20Pi--hole-BED3C3" alt="Compatibilité">
</p>

<!-- STATS_START -->
<p align="center">
  <img src="https://img.shields.io/badge/filtres%20uniques-516%2C206-A43836?style=for-the-badge" alt="filtres">
  <img src="https://img.shields.io/badge/sources-33%20listes-E9BD98?style=for-the-badge" alt="listes">
  <img src="https://img.shields.io/badge/mise%20%C3%A0%20jour-quotidienne-F5E6CA?style=for-the-badge" alt="fréquence">
</p>

<!-- STATS_END -->

<p align="center">
  <a href="https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/filtresDNS.txt">
    <img src="https://img.shields.io/badge/%E2%AC%87%EF%B8%8F_T%C3%A9l%C3%A9charger_la_liste-filtresDNS.txt-01696f?style=for-the-badge" alt="Télécharger la liste">
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/assist%C3%A9%20par-Claude-D97757?style=flat&logo=claude&logoColor=white" alt="Assisté par Claude">
</p>

## Présentation

Liste de filtrage DNS au format **AdBlock Plus**, générée automatiquement chaque jour à partir de sources reconnues.

La génération repose sur plusieurs étapes de nettoyage :

- **Sélection** des entrées au format nom de domaine uniquement. Les règles cosmétiques, les modificateurs AdBlock, les URL avec chemin et les adresses IP sont exclues.
- **Déduplication** par trie de domaines inversés : si un domaine parent est déjà bloqué, ses sous-domaines sont retirés comme redondants.
- **Normalisation** des entrées au format `||domaine^`, compatible avec AdGuard et Pi-hole.
- **Suppression** des domaines présents dans la liste d’exclusion finale.

Le résultat est une liste compacte, cohérente et sans redondance, avec une attention particulière portée aux régies publicitaires et domaines frauduleux francophones.

## Objectifs de protection

| Catégorie | Ce qui est bloqué |
|---|---|
| 🚫 **Publicités** | Serveurs publicitaires, régies, annonces intrusives |
| 🕵️ **Trackers** | Fingerprinting, pistage cross-site, analytics invasifs |
| 🦠 **Malwares** | Logiciels malveillants, badware, DynDNS suspects |
| 🎣 **Phishing** | Hameçonnage, scams, typosquatting, clones de marques |
| 🔕 **Notifications** | Notifications push abusives |
| 📱 **Stalkerware** | Logiciels de surveillance préinstallés |
| 🪟 **Télémétrie** | Trackers Windows/Office, Apple, Amazon, TikTok |

## Sources incluses

<details>
  <summary>📋 Voir les 33 listes sources</summary>

### Généralistes
- **OISD Small** — liste générale de référence
- **Steven Black's List** — hosts file communautaire
- **Peter Lowe's Blocklist** — ads & tracking
- **Dan Pollock's List** — liste historique d’hôtes malveillants

### AdGuard
- **AdGuard DNS filter** — liste officielle AdGuard pour le DNS
- **AdGuard French adservers** — serveurs publicitaires francophones
- **AdGuard French adservers (first-party)** — variante first-party FR

### EasyList
- **EasyList FR** — extension francophone d’EasyList

### HaGeZi
- **HaGeZi's Normal DNS Blocklist**
- **HaGeZi's Pop-Up Ads DNS Blocklist**
- **HaGeZi's Amazon Tracker DNS Blocklist**
- **HaGeZi's Apple Tracker DNS Blocklist**
- **HaGeZi's Windows/Office Tracker DNS Blocklist**
- **HaGeZi's TikTok Extended Fingerprinting DNS Blocklist**
- **HaGeZi's Badware Hoster Blocklist**
- **HaGeZi's DynDNS Blocklist**
- **HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass**
- **HaGeZi's Fake DNS Blocklist**

### Sécurité et phishing
- **Phishing Army**
- **Phishing URL Blocklist (PhishTank/OpenPhish)**
- **Red Flag Domains**
- **Red Flag Domains (FR)** — domaines frauduleux francophones
- **Scam Blocklist by DurableNapkin**
- **Malicious URL Blocklist (URLHaus)**
- **The Big List of Hacked Malware Web Sites**
- **ShadowWhisperer's Malware List**

### Spécialisées
- **AWAvenue Ads Rule**
- **Dandelion Sprout's Anti Push Notifications**
- **Dandelion Sprout's Anti-Malware List**
- **Stalkerware Indicators List**
- **d3Host**
- **PbDNS Additional Rules** — règles personnalisées
- **KADhosts**

</details>


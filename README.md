<div align="center">

# 🛡️ Listes de filtrage

![Format](https://img.shields.io/badge/format-Adblock%20Plus-4A919E)
![Compatibilité](https://img.shields.io/badge/compatible-AdGuard%20%7C%20Pi--hole-BED3C3)

</div>

<!-- STATS_START --><div align="center">

![filtres](https://img.shields.io/badge/filtres%20uniques-531%2C131-A43836?style=for-the-badge)
![listes](https://img.shields.io/badge/sources-33%20listes-E9BD98?style=for-the-badge)
![fréquence](https://img.shields.io/badge/mise%20%C3%A0%20jour-quotidienne-F5E6CA?style=for-the-badge)

</div>
<!-- STATS_END -->

<div align="center">

![Assisté par Claude](https://img.shields.io/badge/assist%C3%A9%20par-Claude-D97757?style=flat&logo=claude&logoColor=white)

</div>

## Présentation

Liste de blocage DNS consolidée au format **AdBlock Plus**, générée automatiquement chaque jour à partir de sources reconnues.

Le pipeline de génération repose sur plusieurs étapes de nettoyage :

- **Sélection** des entrées au format nom de domaine uniquement. Les règles cosmétiques, les modificateurs AdBlock, les URLs avec chemin sont écartés ainsi que les adresses IP
- **Déduplication** par trie de domaines inversés - si un domaine parent est déjà bloqué, ses sous-domaines sont automatiquement écartés comme redondants
- **Normalisation** des entrées au format `||domaine^`, compatible nativement avec AdGuard et Pi-hole
- **Suppression** des domaines présents dans la liste d'exclusion du résultat final

Le résultat est une liste **compacte et sans redondance**, où chaque entrée est strictement nécessaire. Conçue avec une attention particulière pour le contexte francophone, elle intègre notamment des sources dédiées aux régies publicitaires et domaines frauduleux français.

[![Liste brute](https://img.shields.io/badge/⬇️_Télécharger_la_liste-blocklist.txt-01696f?style=for-the-badge)](https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt)

## Objectifs de protection

| Catégorie | Ce qui est bloqué |
|---|---|
| 🚫 **Publicités** | Serveurs de pub, régies, annonces intrusives |
| 🕵️ **Trackers** | Fingerprinting, pistage cross-site, analytics invasifs |
| 🦠 **Malwares** | Logiciels malveillants, badware, DynDNS suspects |
| 🎣 **Phishing** | Hameçonnage, scams, typosquatting et clones de marques |
| 🔕 **Notifications** | Notifications push abusives |
| 📱 **Stalkerware** | Logiciels de surveillance préinstallés |
| 🪟 **Télémétrie** | Trackers Windows/Office, Apple, Amazon, TikTok... |

## Sources incluses

<details>
<summary>📋 Voir les 33 listes sources</summary>

### Généralistes
- **OISD Small** - liste générale de référence
- **Steven Black's List** - hosts file communautaire
- **Peter Lowe's Blocklist** - ads & tracking
- **Dan Pollock's List** - liste historique d'hôtes malveillants

### AdGuard
- **AdGuard DNS filter** - liste officielle AdGuard pour le DNS
- **AdGuard French adservers** - serveurs publicitaires francophones
- **AdGuard French adservers (first-party)** - variante first-party FR

### EasyList
- **EasyList FR** - extension francophone d'EasyList

### HaGeZi (DNS precision)
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

### Sécurité & Phishing
- **Phishing Army**
- **Phishing URL Blocklist (PhishTank/OpenPhish)**
- **Red Flag Domains**
- **Red Flag Domains (FR)** - domaines frauduleux francophones
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
- **PbDNS Additional Rules** - règles personnalisées
- **KADhosts**
</details>


🔗 [blocklist.txt](https://raw.githubusercontent.com/PbDNS/Blocklists/refs/heads/main/blocklist.txt)

# Agrégation de listes de blocage internationales et francophones

Cette compilation mise à jour 2/j vise à combiner les forces de nombreuses blocklistes réputées, en une source unique, adaptée aux environnements d’analyse réseau ou de filtrage DNS personnalisés

---

## Objectif

- bloquer les publicités
- limiter la collecte de données personnelles (trackers, fingerprinting)
- bloquer les logiciels malveillants, scams, phishing
- améliorer la sécurité

---

## Blocklistes incluses

- **AdGuard DNS filter**
- **AdGuard French adservers**
- **AWAvenue Ads Rule**
- **Dandelion Sprout's Anti-Malware List**
- **Dan Pollock's List**
- **d3Host**
- **Easylist FR**
- **HaGeZi's Amazon Tracker DNS Blocklist**
- **HaGeZi's Apple Tracker DNS Blocklist**
- **HaGeZi's Badware Hoster Blocklist**
- **HaGeZi's DynDNS Blocklist**
- **HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass**
- **HaGeZi's Normal DNS Blocklist**
- **HaGeZi's Pop-Up Ads DNS Blocklist**
- **HaGeZi's TikTok Extended Fingerprinting DNS Blocklist**
- **HaGeZi's Windows/Office Tracker DNS Blocklist**
- **Malicious URL Blocklist (URLHaus)**
- **OISD Small**
- **Peter Lowe's Blocklist**
- **Phishing URL Blocklist (PhishTank and OpenPhish)**
- **Scam Blocklist by DurableNapkin**
- **ShadowWhisperer's Malware List**
- **Stalkerware Indicators List**
- **Steven Black's List**
- **The Big List of Hacked Malware Web Sites**
# Liste de Blocklists DNS

Ce projet contient une collection de blocklists DNS pour améliorer la confidentialité, la sécurité et l'expérience en ligne en bloquant les publicités, trackers, malwares, hôtes malveillants et autres contenus indésirables.

## Blocklists par Type

### 1. **Publicités (Ads)**
- **AdGuard DNS filter** : Liste de filtres publicitaires.
- **AdGuard French adservers** : Liste des serveurs publicitaires en français.
- **AWAvenue Ads Rule** : Liste de règles pour bloquer les publicités d'Avenue.
- **Easylist FR** : Liste de filtrage publicitaire pour la France.
- **HaGeZi's Pop-Up Ads DNS Blocklist** : Liste des DNS pour bloquer les pop-ups publicitaires.

### 2. **Malware et menaces (Malicious URLs, Malware, Phishing)**
- **Dandelion Sprout's Anti-Malware List** : Liste contre les malwares.
- **Dan Pollock's List** : Liste de protection contre les malwares et les sites suspects.
- **Malicious URL Blocklist (URLHaus)** : Liste des URL malveillantes.
- **Phishing URL Blocklist (PhishTank and OpenPhish)** : Liste de blocage contre les sites de phishing.
- **ShadowWhisperer's Malware List** : Liste de malwares.
- **The Big List of Hacked Malware Web Sites** : Liste des sites malveillants piratés.

### 3. **Tracking et vie privée (Trackers, Fingerprinting)**
- **HaGeZi's Amazon Tracker DNS Blocklist** : Liste des trackers d'Amazon.
- **HaGeZi's Apple Tracker DNS Blocklist** : Liste des trackers d'Apple.
- **HaGeZi's TikTok Extended Fingerprinting DNS Blocklist** : Liste de blocage des trackers et techniques de fingerprinting de TikTok.
- **HaGeZi's Windows/Office Tracker DNS Blocklist** : Liste des trackers de Windows et Office.
- **Stalkerware Indicators List** : Liste des indicateurs de stalkerware (logiciels espions).

### 4. **Serveurs, DNS et Bypass**
- **HaGeZi's DynDNS Blocklist** : Liste des serveurs DynDNS à bloquer.
- **HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass** : Liste pour bloquer les tentatives de contournement de filtres via des VPN, TOR, ou DNS cryptés.
- **HaGeZi's Normal DNS Blocklist** : Liste générique des serveurs à bloquer au niveau DNS.

### 5. **Autres**
- **OISD Small** : Liste de filtrage divers pour bloquer les contenus indésirables.
- **Peter Lowe's Blocklist** : Liste générale pour bloquer les publicités, malwares et trackers.
- **Scam Blocklist by DurableNapkin** : Liste des sites frauduleux à bloquer.
- **Steven Black's List** : Liste de blocage combinant plusieurs types de filtres (malware, publicité, trackers).
- **d3Host** : Liste de blocage de domaines associés à l'hébergement de sites malveillants.

---

## Format et utilisation

- format Adblock Plus
- sous-domaines redondants supprimés
- compatible avec des solutions comme dnsmasq, AdGuard Home, Pi-hole ou Unbound
- optimisé pour un usage DNS/adblock au niveau réseau

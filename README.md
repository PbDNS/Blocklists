# Agrégation de listes de blocage internationales et francophones

Cette compilation mise à jour 2/J vise à combiner les forces de nombreuses blocklistes réputées, en une source unique, adaptée aux environnements d’analyse réseau ou de filtrage DNS personnalisés

---

## Objectif

- Bloquer les publicités
- Limiter le suivi (trackers, fingerprinting)
- Bloquer les logiciels malveillants, scams, phishing
- Améliorer la sécurité

---

## Blocklistes incluses

- **AdGuard DNS filter**
- **AdGuard French adservers**
- **AdGuard French adservers first party**
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

---

## Format & Utilisation

- Format Adblock Plus **||exemple.com^**
- Compatible avec des solutions comme dnsmasq, AdGuard Home, Pi-hole ou Unbound
- Optimisé pour un usage DNS/adblock au niveau réseau
- Sous-domaines redondants supprimés, **||cdn.exemple.com^** si **||exemple.com^** est présent

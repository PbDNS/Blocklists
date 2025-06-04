# 🛡️ Aggregated DNS Blocklists

Une agrégation de listes DNS et URL de blocage, destinée à améliorer la confidentialité, la sécurité et à réduire la publicité et le suivi en ligne.

Cette compilation vise à combiner les forces de nombreuses blocklistes réputées, en une source unique, ordonnée et cohérente.

---

## 🔍 Objectif

L'objectif de ce projet est de fournir une **agrégation fiable de blocklists** pour :

- bloquer les publicités (même sournoises),
- limiter le suivi (trackers, fingerprinting),
- bloquer les logiciels malveillants, scams, phishing,
- neutraliser les services de contournement réseau indésirables (VPN/TOR/etc),
- améliorer la sécurité des réseaux personnels et professionnels.

---

## 📦 Blocklists incluses

Voici la liste complète des blocklists utilisées, classée par ordre alphabétique :

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
- **HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass DNS Blocklist**
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

## 📁 Format & Utilisation

Le fichier de sortie est une liste de domaines (ou d’URL), au format texte brut. Il peut être utilisé avec :

- des DNS personnalisés (Unbound, dnsmasq, AdGuard Home, Pi-hole, etc.),
- des navigateurs ou extensions compatibles avec des blocklists,
- des pare-feux ou proxy filtrants.

---

## 🧱 Organisation

- Les blocklists sont fusionnées et dédupliquées.
- Un tri alphabétique est appliqué.
- Des filtres peuvent être appliqués pour éviter les faux positifs.

---

## ⚠️ Avertissements

- Bien que ces blocklists soient soigneusement choisies, **des faux positifs peuvent toujours survenir**.
- N’utilisez pas cette liste dans un environnement critique sans vérification préalable.
- Certaines listes peuvent bloquer des services que vous souhaitez utiliser (ex. Amazon, TikTok, VPN).

---

## 📜 Licence

Chaque liste appartient à son auteur respectif et suit la licence indiquée dans ses dépôts d’origine. Cette agrégation est fournie **à titre informatif et éducatif**.

---

## 🤝 Contribuer

Les suggestions de nouvelles listes ou améliorations sont les bienvenues via des **issues** ou **pull requests**.

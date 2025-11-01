# Stratégies d'Évasion par Type de Cible

Ces stratégies affinent l'approche d'évasion en imitant non seulement un système d'exploitation, mais aussi le comportement attendu d'un type spécifique d'appareil ou
d'environnement réseau. Un pare-feu d'entreprise n'a pas les mêmes règles qu'un pare-feu protégeant un fournisseur de cloud ou un réseau d'objets connectés (IoT).

### Histoire et Contexte

La segmentation du réseau est un principe de sécurité fondamental. Les entreprises créent des zones distinctes pour leurs serveurs, leurs postes de travail et leurs
appareils invités. Des articles de magazines spécialisés comme *CSO Online* ou *Dark Reading* soulignent que les politiques de sécurité et les profils de trafic "normal"
varient considérablement entre ces segments.

Par exemple, un pare-feu protégeant un data center s'attendra à voir du trafic de serveur à serveur, tandis qu'un pare-feu de bureau s'attendra à du trafic lié à la
navigation web, aux e-mails et aux applications métier. Les stratégies de cette catégorie exploitent ces attentes pour rendre le scan encore plus crédible dans un
contexte donné.

---

### 1. `corporate-firewall-bypass`

* **Objectif** : Se fondre dans le trafic d'un réseau d'entreprise typique.
* **Paramètres Clés** :
    * `os_fingerprint: "windows11"` : Cible l'environnement de bureau le plus moderne.
    * `src_ports: [443, 3389, 1194, 1723]` : Utilise des ports associés à des applications d'entreprise courantes : HTTPS, Remote Desktop (RDP), OpenVPN et PPTP. Le
      trafic provenant de ces ports est souvent autorisé.
    * `timing_pattern: "exponential"` : Peut simuler un employé qui commence sa journée de travail, avec une activité réseau qui augmente progressivement.
    * `fake_uptime_days: 30` : Simule un poste de travail d'entreprise standard, souvent laissé allumé mais redémarré mensuellement pour les mises à jour.

---

### 2. `cloud-provider-scan`

* **Objectif** : Imiter le trafic légitime à l'intérieur d'un environnement de fournisseur de cloud (AWS, Azure, GCP).
* **Paramètres Clés** :
    * `os_fingerprint: "linux"` : La grande majorité des machines virtuelles dans le cloud fonctionnent sous Linux.
    * `fake_uptime_days: 365` : Simule un serveur avec une très longue disponibilité, ce qui est courant pour les services cloud.
    * `src_ports: [443, 8080, 8443, 9090]` : Utilise des ports couramment utilisés pour les applications web, les API et les services de gestion hébergés dans le cloud.
    * `timing_pattern: "fibonacci"` : Un modèle équilibré adapté au trafic de serveur à serveur.

---

### 3. `iot-device-scan`

* **Objectif** : Imiter le comportement réseau d'un appareil de l'Internet des Objets (IoT), comme une caméra de sécurité, un capteur ou un appareil domestique
  intelligent.
* **Paramètres Clés** :
    * `os_fingerprint: "linux"` : La plupart des appareils IoT utilisent une version allégée de Linux.
    * `window_size: 512` : Les appareils IoT ont des piles TCP/IP très limitées avec de petites tailles de fenêtre.
    * `ttl: 32` : Les appareils IoT communiquent souvent à l'intérieur d'un réseau local, utilisant des TTL plus faibles.
    * `decoys: 5` : Les appareils IoT sont généralement peu "bavards" et génèrent un trafic limité. Un grand nombre de leurres serait suspect.
    * `timing_pattern: "random"` : Le trafic IoT peut être sporadique et imprévisible.

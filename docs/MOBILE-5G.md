# Stratégies d'Évasion pour Trafic Mobile et 5G

Avec l'explosion du trafic provenant des appareils mobiles et le déploiement des réseaux 5G, une nouvelle catégorie de profils réseau est apparue. Ces stratégies sont
conçues pour imiter le comportement unique des smartphones et autres appareils connectés sur des réseaux cellulaires, qui diffère considérablement du trafic filaire
traditionnel.

### Histoire et Contexte

Le passage massif au mobile a été un sujet central dans les rapports annuels d'entreprises comme Cisco (Visual Networking Index) et Ericsson (Mobility Report) depuis des
années. Ces rapports montrent que le trafic mobile a des caractéristiques distinctes : des sessions plus courtes, une latence variable, et l'utilisation de protocoles et
de ports spécifiques aux applications mobiles.

Les réseaux 5G ajoutent une autre couche de complexité avec des concepts comme le "network slicing", où différentes applications peuvent se voir allouer des "tranches" de
réseau avec des caractéristiques de performance différentes. Les pare-feu et les systèmes de sécurité déployés par les opérateurs mobiles sont entraînés à reconnaître ces
modèles. Un article de l'IEEE, "Security in 5G Networks", souligne les nouveaux vecteurs d'attaque mais aussi les nouvelles opportunités de détection basées sur le
comportement du trafic au sein de l'infrastructure 5G.

Ces stratégies exploitent ces connaissances pour créer un trafic de scan qui ressemble à celui d'un utilisateur de smartphone légitime, un type de trafic que les pare-feu
d'entreprise et d'opérateurs sont configurés pour autoriser et prioriser.

---

### 1. `mobile-5g-profile`

* **Objectif** : Imiter un smartphone Android moderne sur un réseau 5G.
* **Paramètres Clés** :
    * `os_fingerprint: "android"` : L'empreinte la plus courante pour les appareils mobiles dans le monde.
    * `fake_uptime_days: 3` : Les smartphones sont redémarrés ou mis à jour beaucoup plus fréquemment que les serveurs ou les postes de travail. Un uptime court est plus
      crédible.
    * `timing_pattern: "exponential"` : Simule le comportement d'une application qui se lance et augmente son activité réseau.
    * `src_ports: [443, 8443, 9000]` : Utilise des ports couramment utilisés par les API de backend des applications mobiles.
    * `ttl: 64` : Une valeur de TTL commune dans les réseaux mobiles.

---

### 2. `ios-device-profile`

* **Objectif** : Se faire passer pour un iPhone ou un iPad, un profil de trafic premium sur de nombreux réseaux.
* **Paramètres Clés** :
    * `os_fingerprint: "ios"` : Utilise l'empreinte TCP/IP spécifique d'iOS, qui est distincte de celle d'Android ou de macOS.
    * `fake_uptime_days: 7` : Simule un iPhone qui n'a pas été redémarré depuis une semaine.
    * `timing_pattern: "fibonacci"` : Un modèle de trafic équilibré qui peut correspondre à une utilisation mixte (navigation, applications, etc.).
    * `decoys: 12` : Un nombre modéré de leurres, correspondant au nombre de connexions qu'un appareil iOS pourrait établir.

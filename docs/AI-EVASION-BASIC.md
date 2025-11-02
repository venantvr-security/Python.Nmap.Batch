# Stratégies d'Évasion IA de Base

Ces stratégies constituent le fondement de l'évasion des pare-feu modernes basés sur l'IA. Elles se concentrent sur l'usurpation de l'empreinte (fingerprint) de systèmes
d'exploitation courants pour que le trafic de scan paraisse légitime.

### Histoire et Contexte

Avec l'avènement des pare-feu de nouvelle génération (NGFW) et des systèmes de détection d'intrusion (IDS/IPS) utilisant l'apprentissage automatique (Machine Learning),
la simple dissimulation de paquets (comme le faisait le scan `stealth` original) n'est plus suffisante. Ces systèmes apprennent à quoi ressemble le trafic "normal" d'un
réseau.

Des publications de conférences sur la sécurité comme Black Hat et DEF CON ont montré à plusieurs reprises que les piles TCP/IP des systèmes d'exploitation ont des "tics"
uniques : la taille de la fenêtre TCP, les options TCP utilisées (comme SACK, Timestamps), la valeur du Time-to-Live (TTL), etc. Les moteurs d'IA sont entraînés à repérer
les paquets qui ne correspondent à aucune empreinte connue, les signalant comme suspects.

Ces stratégies de base contrent cette détection en imitant fidèlement les empreintes des OS les plus courants, rendant le trafic de scan indiscernable du trafic d'un
utilisateur normal.

### 1. `ai-evasion-windows10`

* **Objectif** : Se faire passer pour un ordinateur de bureau Windows 10 standard.
* **Paramètres Clés** :
    * `os_fingerprint: "windows10"` : Utilise les options TCP, la taille de fenêtre et le TTL par défaut de Windows 10.
    * `timing_pattern: "fibonacci"` : Un modèle de temporisation non linéaire qui évite les schémas répétitifs simples que l'IA pourrait détecter.
    * `decoys: 20` : Un nombre modéré de leurres pour brouiller les pistes sans paraître trop agressif.
    * `fake_uptime_days: 45` : Simule un poste de travail qui n'a pas été redémarré depuis un mois et demi, un comportement courant en entreprise.

### 2. `ai-evasion-linux`

* **Objectif** : Imiter un serveur ou un poste de travail Linux.
* **Paramètres Clés** :
    * `os_fingerprint: "linux"` : Adopte l'empreinte TCP/IP typique des noyaux Linux récents.
    * `timing_pattern: "sine"` : Un modèle de temporisation sinusoïdal, créant des vagues de trafic qui peuvent paraître plus organiques.
    * `fragment: true` : Utilise la fragmentation des paquets, une technique classique pour contourner les IDS plus anciens qui peut encore être efficace.
    * `decoys: 25` : Un peu plus de leurres, car les serveurs Linux peuvent être plus "bruyants" sur un réseau.
    * `fake_uptime_days: 120` : Simule un serveur avec une longue disponibilité, typique des infrastructures Linux.

### 3. `ai-evasion-macos`

* **Objectif** : Se fondre dans un environnement de travail créatif ou de développement en imitant un appareil macOS.
* **Paramètres Clés** :
    * `os_fingerprint: "macos"` : Réplique la pile réseau de macOS, qui diffère subtilement de Linux et Windows.
    * `timing_pattern: "prime"` : Utilise des nombres premiers pour les délais, créant un schéma très irrégulier et difficile à modéliser pour une IA.
    * `decoys: 15` : Moins de leurres, car les postes de travail individuels sont généralement moins actifs que les serveurs.
    * `fake_uptime_days: 90` : Simule un MacBook qui a été en veille et actif pendant plusieurs mois.

### 4. `ai-evasion-android`

* **Objectif** : Imiter un smartphone ou une tablette Android, un profil de plus en plus courant sur les réseaux d'entreprise et invités.
* **Paramètres Clés** :
    * `os_fingerprint: "android"` : Utilise l'empreinte réseau spécifique d'Android, qui est optimisée pour les réseaux mobiles et sans fil.
    * `timing_pattern: "exponential"` : Un modèle qui commence lentement puis accélère, pouvant simuler un utilisateur qui commence une activité sur son appareil.
    * `decoys: 30` : Un nombre élevé de leurres pour simuler le "bavardage" des nombreuses applications et services d'un smartphone moderne.
    * `fake_uptime_days: 15` : Simule un téléphone qui a été redémarré il y a deux semaines.

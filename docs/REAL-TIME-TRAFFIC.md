# Stratégies d'Évasion par Mimétisme de Trafic Temps Réel

Cette catégorie de stratégies vise à imiter des types de trafic très spécifiques et souvent hautement priorisés sur les réseaux : les jeux en ligne, la voix sur IP (VoIP)
et la navigation web interactive. Ces types de trafic ont des signatures de performance uniques que les pare-feu modernes (en particulier les pare-feu "conscients des
applications") sont configurés pour reconnaître et autoriser.

### Histoire et Contexte

La gestion de la Qualité de Service (QoS) est un aspect crucial de l'administration réseau depuis des décennies. Des protocoles comme le DiffServ (Differentiated
Services) sont utilisés pour marquer les paquets afin que les routeurs et les pare-feu puissent prioriser le trafic sensible à la latence (comme la VoIP ou les jeux) par
rapport au trafic moins urgent (comme le téléchargement de fichiers).

Des articles de *Network World* et des blogs techniques d'entreprises comme Juniper ou Cisco expliquent comment les administrateurs configurent des politiques de QoS. En
imitant les caractéristiques de ce trafic prioritaire, un scan peut non seulement éviter d'être bloqué, mais il peut même se voir allouer plus de ressources par
l'infrastructure réseau, un effet secondaire ironique.

Ces stratégies sont donc une forme d'ingénierie sociale appliquée au niveau du réseau : le scanner "prétend" être un type de trafic important pour obtenir un traitement
de faveur.

### 1. `gaming-traffic-mimicry`

* **Objectif** : Imiter le trafic d'un jeu en ligne, qui est caractérisé par de petits paquets fréquents et une faible latence.
* **Paramètres Clés** :
    * `delay: 0.3` et `timing_pattern: "exponential"` : Un délai très court avec un modèle en rafale, simulant l'envoi rapide de données de position et d'action dans un
      jeu.
    * `os_fingerprint: "windows11"` : La plateforme de jeu la plus courante.
    * `src_ports: [27015, 3074, 5222]` : Utilise des ports connus pour être associés à des services de jeux comme Steam, Xbox Live et Riot Games.
    * `decoys: 8` : Un nombre faible de leurres, car une session de jeu n'établit généralement pas un grand nombre de connexions parasites.

### 2. `voip-sip-mimicry`

* **Objectif** : Se faire passer pour du trafic de voix sur IP (VoIP), comme un appel téléphonique sur Internet.
* **Paramètres Clés** :
    * `delay: 0.5` et `timing_pattern: "sine"` : Simule le flux constant et régulier de paquets vocaux dans une conversation.
    * `src_ports: [5060, 5061]` : Utilise les ports standards pour le protocole SIP (Session Initiation Protocol), qui est la base de la plupart des systèmes VoIP.
    * `window_size: 8192` : Une taille de fenêtre commune pour les applications VoIP.
    * `os_fingerprint: "linux"` : De nombreux systèmes de téléphonie IP d'entreprise sont basés sur des serveurs Linux (comme Asterisk).

### 3. `legitimate-browser-scan` (Re-catégorisé ici pour le contexte)

* **Objectif** : Imiter le trafic d'un navigateur web moderne, le type de trafic le plus courant et le moins suspect sur n'importe quel réseau.
* **Paramètres Clés** :
    * `protocol_mimicry: true` : Le paramètre le plus important. En ajoutant une charge utile qui ressemble à une requête `GET / HTTP/1.1` ou à un `ClientHello` TLS, le
      paquet devient extrêmement difficile à distinguer d'une véritable navigation web pour un pare-feu faisant de l'inspection de paquets.
    * `os_fingerprint: "windows11"` : Cible l'environnement de bureau le plus récent.
    * `fake_uptime_days: 7` : Simule un ordinateur personnel typique.

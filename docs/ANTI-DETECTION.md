# Stratégies d'Évasion Anti-Détection et Anti-Honeypot

Cette catégorie de stratégies se concentre sur la détection et le contournement des mécanismes de défense actifs conçus spécifiquement pour piéger les attaquants, comme
les honeypots (pots de miel) et les tarpits (goudronnières).

### Histoire et Contexte

Les honeypots sont des systèmes leurres, intentionnellement vulnérables, conçus pour attirer et piéger les attaquants afin d'étudier leurs méthodes. Le **Honeynet Project
**, une organisation de recherche en sécurité, a été pionnier dans ce domaine depuis la fin des années 1990. Des articles dans des publications comme *Phrack* et des
présentations à des conférences ont détaillé comment les attaquants pouvaient potentiellement identifier ces pièges. Les honeypots modernes sont devenus très
sophistiqués, mais ils présentent souvent des caractéristiques que des scanners avertis peuvent détecter : ports inhabituels ouverts, réponses de bannières spécifiques,
ou comportement réseau trop "parfait".

Les tarpits, popularisés par des outils comme "La Brea", sont une autre forme de défense active. Ils répondent aux tentatives de connexion mais le font de manière
extrêmement lente, en maintenant les connexions ouvertes et en envoyant des paquets à un rythme très faible. L'objectif est de bloquer les ressources d'un scanner
automatisé, le ralentissant au point de le rendre inefficace.

Les stratégies de cette catégorie sont donc une forme de contre-espionnage : le scanner tente de déterminer s'il est lui-même observé ou piégé.

### 1. `honeypot-aware-scan`

* **Objectif** : Scanner une cible tout en évitant de déclencher les alertes d'un honeypot.
* **Paramètres Clés** :
    * `delay: 10.0` et `timing_pattern: "prime"` : Un scan extrêmement lent et irrégulier. Les honeypots sont conçus pour repérer les scans automatisés rapides. Ce rythme
      simule une exploration manuelle et prudente.
    * `decoys: 0` : C'est un paramètre crucial. L'utilisation de leurres (decoys) est une signature classique des scanners de réseau. En n'en utilisant aucun, cette
      stratégie évite l'un des principaux indicateurs qu'un honeypot recherche.
    * `os_fingerprint: "macos"` : Utiliser une empreinte de système d'exploitation de bureau moins courante pour un scan peut parfois déjouer les honeypots qui s'
      attendent à des scans provenant de serveurs Linux (comme Kali Linux).
    * `send_rst: true` : Assure que chaque connexion est immédiatement et proprement fermée, laissant le moins de traces possible.

### 2. `anti-tarpit-scan`

* **Objectif** : Empêcher le scanner de se faire piéger par un tarpit qui ralentirait l'ensemble du processus.
* **Paramètres Clés** :
    * `timeout: 1` : Le cœur de la stratégie. Si une réponse n'est pas reçue dans la seconde, le scanner abandonne et passe au port suivant. Cela l'empêche de rester
      bloqué sur un port piégé par un tarpit.
    * `decoys: 25` : Contrairement à la stratégie anti-honeypot, l'utilisation de leurres ici peut être bénéfique. En envoyant de nombreuses tentatives de connexion, le
      scanner peut potentiellement saturer les ressources limitées du tarpit.
    * `send_rst: true` : Aide à terminer rapidement les tentatives de connexion qui n'aboutissent pas, libérant les ressources du scanner.

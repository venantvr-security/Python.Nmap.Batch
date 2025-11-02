# Feuille de Route d'Évolution du Scanner

Ce document définit les axes d'amélioration pour faire de cet outil une plateforme avancée de test d'intrusion, avec un focus sur le contournement des défenses modernes.

## Axe 1 : Améliorations Fondamentales de Scapy

### 1.1. Replay de Session PCAP Complète

*   **Problème Actuel** : Le scanner `Pcap2` (et `ScapyScanner` avec l'option `template_pcap`) ne rejoue que le **premier paquet** du fichier `.pcap`. Cela suffit pour imiter un paquet `SYN` simple, mais échoue à reproduire des handshakes applicatifs complets (TLS, SMB, etc.), qui sont des signatures comportementales clés.
*   **Action** : Modifier la logique de `_build_packet_from_template`.
    1.  Introduire une option dans la stratégie YAML, par exemple `replay_mode: full_session` (par défaut à `first_packet` pour la compatibilité ascendante).
    2.  Si `full_session` est activé, la méthode ne doit plus retourner un seul paquet, mais une **liste de paquets** modifiés.
    3.  La boucle de modification devra être plus intelligente : elle devra remplacer les IP/ports sur **tous les paquets** de la session et, de manière cruciale, **ajuster les numéros de séquence et d'acquittement (Seq/Ack)** relatifs entre chaque paquet pour maintenir la cohérence de la session TCP.
    4.  La boucle d'envoi principale dans `scan()` devra alors itérer sur cette liste de paquets pour les envoyer séquentiellement.

## Axe 2 : Intégration d'une Logique d'Évasion Adaptative (IA)

L'évasion n'est pas un acte unique, mais un dialogue avec les défenses. L'outil doit pouvoir **réagir et adapter sa personnalité** en fonction des réponses (ou de leur absence).

### 2.1. Concept : Machine à États Finis (FSM) pour le Scan

*   **Idée** : Au lieu d'une stratégie fixe, définir une **chaîne de stratégies** qui s'exécutent en fonction des résultats de l'étape précédente.
*   **Implémentation** : Créer un nouveau méta-scanner, par exemple `AdaptiveScanner`, qui orchestrerait `ScapyScanner`.

### 2.2. Use Case Concret : Contournement d'un Pare-feu Comportemental

**Objectif** : Scanner le port 443 sur une cible protégée par un pare-feu IA qui bloque les IPs après une activité suspecte.

1.  **Phase 1 : Sonde Furtive (État `PROBING`)**
    *   **Action** : Lancer un scan `Scapy` avec une stratégie `fin-scan-fragmented` sur un port à haute probabilité d'être fermé (ex: 33890).
    *   **Objectif** : Envoyer un trafic inhabituel mais peu agressif. Le but n'est pas de trouver un port ouvert, mais de "réveiller" le pare-feu et d'observer sa réaction.

2.  **Phase 2 : Observation des Canaux Auxiliaires (État `OBSERVING`)**
    *   **Action** : Immédiatement après la sonde, effectuer une requête DNS simple vers un résolveur connu (ex: `8.8.8.8`) ou un ping.
    *   **Analyse** : La requête échoue-t-elle (timeout) ? Si oui, cela signifie que le pare-feu nous a repérés et a mis notre IP en "quarantaine" temporaire. C'est un **signal négatif**.

3.  **Phase 3 : Adaptation de la Personnalité (État `ADAPTING`)**
    *   **Action** : Le signal est négatif, l'outil doit devenir un "citoyen modèle". Il abandonne les scans agressifs.
    *   Il sélectionne automatiquement la stratégie `chrome-on-windows-impersonation` (basée sur un template PCAP) et un `timing_pattern: "human-browsing"` (simulant des délais humains : 2s, puis 5s, puis 1.5s).

4.  **Phase 4 : Scan de Confirmation (État `CONFIRMING`)**
    *   **Action** : Lancer le scan sur le port cible réel (443) en utilisant cette nouvelle personnalité hautement crédible.
    *   **Résultat** : Le pare-feu, voyant un trafic qui correspond parfaitement à une empreinte connue et légitime, est beaucoup plus susceptible de le laisser passer.

## Axe 3 : Améliorations de la Discrétion Opérationnelle (OPSEC)

Le scanner lui-même ne doit pas être une signature.

### 3.1. Dissociation des Sondes et des Scans

*   **Problème** : Les pare-feu corrèlent souvent une requête DNS pour un domaine suivie immédiatement d'un scan sur l'IP résolue. C'est une signature d'attaquant.
*   **Action** : Créer un mode de scan "dissocié".
    1.  Une première passe effectue **uniquement** les résolutions DNS pour toutes les cibles et les met en cache.
    2.  Le scanner attend un délai long et aléatoire (ex: entre 10 et 30 minutes).
    3.  Une seconde passe effectue les scans TCP/UDP en utilisant les IPs du cache, sans jamais refaire de requête DNS.

### 3.2. Distribution de la Source du Scan

*   **Problème** : Tous les paquets proviennent d'une seule IP source, ce qui est facile à corréler et à bloquer.
*   **Action** : Transformer l'outil en une architecture client/serveur légère.
    *   Le serveur web (`main.py`) devient le contrôleur.
    *   Développer un "agent" Python simple qui peut être déployé sur plusieurs machines (VPS, etc.).
    *   Le contrôleur distribue les cibles aux agents. Chaque agent scanne une petite partie des IPs.
    *   Le trafic provient alors de sources multiples et géographiquement distribuées, rendant la corrélation par l'IP source beaucoup plus difficile.

## Axe 4 : Analyse Post-Scan et Boucle de Rétroaction

L'outil doit apprendre de ses propres résultats.

### 4.1. Base de Données de Succès des Stratégies

*   **Problème** : L'opérateur choisit une stratégie, mais ne sait pas objectivement laquelle est la plus efficace dans un contexte donné.
*   **Action** :
    1.  Créer une base de données locale (SQLite est parfait pour cela) pour stocker les métadonnées des scans.
    2.  Pour chaque scan, enregistrer : la `stratégie`, le `type de cible` (déduit de la plage IP), le `taux de ports ouverts trouvés`.
    3.  Développer une nouvelle page dans l'interface ou une commande qui analyse ces données pour répondre à la question : "Contre des réseaux de type `corporate`, quelle stratégie Scapy a historiquement le meilleur taux de succès ?".
    4.  Cela transforme l'outil d'une simple plateforme d'exécution en un système d'aide à la décision stratégique.

# Plateforme de Scan Réseau Stratégique avec Dashboard en Temps Réel

Cette application fournit une interface web centralisée pour orchestrer, exécuter et superviser des scans réseau complexes sur de larges plages d'adresses IP. Conçue pour la flexibilité, elle intègre une architecture modulaire permettant de piloter différents outils de scan (Nmap, Masscan, Scapy, etc.) avec des stratégies personnalisables définies dans de simples fichiers YAML, tout en offrant un suivi des opérations en temps réel.

## Fonctionnalités Clés

  - **Architecture Modulaire et Stratégique** : Intégrez facilement n'importe quel outil de scan en ligne de commande. Chaque outil est piloté par des "stratégies" définies dans des fichiers YAML, permettant de personnaliser les commandes sans modifier le code source. (implémenté dans `main.py` et les modules du répertoire `scanners/`).
  - **Interface Web et Dashboard en Temps Réel** : Lancez et arrêtez les scans depuis une interface web intuitive. La progression, les logs de chaque thread et les résultats sont affichés en temps réel grâce à une communication par Server-Sent Events (SSE). (implémenté dans `main.py`, `templates/index.html` et `static/script.js`).
  - **Scan Parallèle et Adaptatif** : L'application exécute les scans sur plusieurs threads pour maximiser la vitesse. Le nombre de workers s'ajuste dynamiquement en fonction du taux de succès des scans pour optimiser la performance et la discrétion. (implémenté dans `main.py`).
  - **Reprise sur Interruption et Centralisation des Résultats** : La progression des scans est sauvegardée, permettant de reprendre une session interrompue sans rescanner les IP déjà traitées. Tous les résultats sont stockés de manière structurée au format JSON pour une analyse ultérieure facile. (implémenté dans `main.py`).
  - **Documentation Intégrée** : Accédez à une documentation technique détaillée pour chaque outil de scan directement depuis l'interface, facilitant le choix de la stratégie la plus adaptée. (implémenté via l'API `/scanner/info/get/` et les fichiers du répertoire `docs/`).

## Comment ça marche ?

1.  **Configuration** : L'administrateur définit les plages d'IP à scanner dans le fichier `.env` et configure les différentes stratégies de scan dans les fichiers `.yaml` du répertoire `strategies/`.
2.  **Lancement** : Le serveur principal est lancé avec `python3 main.py`.
3.  **Interface Utilisateur** : L'utilisateur accède à l'interface web, qui charge dynamiquement la liste des scanners, des stratégies et des configurations de ports disponibles via des appels API.
4.  **Exécution d'un Scan** : L'utilisateur sélectionne un outil (ex: Nmap), une stratégie (ex: "Détection OS et Vulnérabilités") et une liste de ports, puis clique sur "Démarrer".
5.  **Supervision** : Le backend lance les scans en parallèle. Le frontend affiche des "tuiles" pour chaque thread actif, montrant les logs en temps réel. Une barre de progression globale indique l'avancement sur l'ensemble des plages IP.
6.  **Stockage** : Les résultats détaillés de chaque scan sont sauvegardés dans le répertoire `results/`, organisés par type de scanner, stratégie et adresse IP.

## Configuration

La flexibilité de l'outil repose sur des fichiers de configuration simples.

### 1\. Plages d'IP (`.env`)

Définissez les cibles dans un fichier `.env` à la racine du projet.

```dotenv
IP_RANGES=192.168.1.0/24,10.0.0.0/8
```

### 2\. Stratégies de Scan (`strategies/`)

Chaque outil possède son propre fichier de stratégies. Par exemple, pour `strategies/nmap-strategies.yaml` :

```yaml
strategies:
  quick_scan:
    - "-T4"
    - "-F"
    - "<ports>"
  
  full_scan_vuln:
    - "-sS"
    - "-sV"
    - "-O"
    - "--script=vuln"
    - "-p-"
```

Le placeholder `<ports>` sera remplacé par la sélection faite dans l'interface.

### 3\. Définition des Scanners (`strategies/definitions.yaml`)

Ce fichier fait le lien entre un nom de scanner, sa classe Python et son fichier de stratégies.

```yaml
scanners:
  nmap:
    class: NmapScanner
    file: nmap-strategies.yaml
  masscan:
    class: MasscanScanner
    file: masscan-strategies.yaml
```

## Installation

1.  Clonez ce dépôt sur votre machine.
2.  Installez les dépendances Python :
    ```bash
    pip install -r requirements.txt
    ```
3.  Configurez votre fichier `.env` avec les plages d'IP à scanner.
4.  Personnalisez les fichiers de stratégies dans le répertoire `strategies/` selon vos besoins.
5.  Assurez-vous que les outils de scan (Nmap, Masscan, etc.) sont installés et accessibles dans le `PATH` système.
6.  Configurez les permissions `sudo` sans mot de passe pour les outils qui le nécessitent (voir la section Prérequis).
7.  Lancez le serveur :
    ```bash
    python3 main.py
    ```
8.  Ouvrez votre navigateur à l'adresse `http://localhost:5001`.

## Prérequis

  - **Python 3.8+** et les dépendances listées dans `requirements.txt`.

  - **Outils de Scan Externes** : `nmap`, `masscan`, `hping3`, `netcat`, `curl` doivent être installés sur le système.

  - **Privilèges Root** : Certains scanners (Nmap, Hping3, Scapy) nécessitent des privilèges élevés. Il est recommandé de configurer `sudo` pour autoriser leur exécution sans mot de passe pour l'utilisateur qui lance l'application.

    Exemple pour Nmap (à ajouter via `sudo visudo`) :

    ```
    votre_utilisateur ALL=(ALL) NOPASSWD: /usr/bin/nmap
    ```

## Licence

Ce projet est distribué sous la **licence MIT**.

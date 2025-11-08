# Plateforme Avancée de Scan Réseau et d'Évasion de Pare-feu

Cette application fournit une interface web centralisée pour orchestrer des scans réseau complexes, avec un accent particulier sur les **techniques d'évasion de pare-feu
basées sur l'IA**. Elle intègre une architecture modulaire pour piloter divers outils (Nmap, Scapy, etc.) avec des stratégies personnalisables, tout en offrant un suivi
des opérations en temps réel et une documentation complète.

## Fonctionnalités Clés

- **Moteur d'Évasion IA (Scapy)** : Implémente des dizaines de stratégies d'évasion de pointe pour contourner les pare-feu de nouvelle génération (NGFW) et les systèmes
  de détection basés sur le Machine Learning. Inclut le mimétisme d'empreintes OS, les timings polymorphiques, la dissimulation protocolaire, et plus encore.
- **Architecture Modulaire et Stratégique** : Intégrez facilement n'importe quel outil de scan. Chaque outil est piloté par des "stratégies" définies dans des fichiers
  YAML, permettant de personnaliser les commandes sans modifier le code source.
- **Interface Web et Dashboard en Temps Réel** : Lancez et arrêtez les scans depuis une interface web intuitive. La progression, les logs de chaque thread et les
  résultats sont affichés en temps réel grâce à une communication par Server-Sent Events (SSE).
- **Configuration Centralisée et Robuste** : Tous les chemins de l'application sont gérés via un fichier `config.toml`, rendant le déploiement et la maintenance plus
  simples et fiables.
- **Intégration TOR** : Vérifiez votre statut TOR, changez d'identité à la volée et configurez des changements d'identité automatiques pour anonymiser les scans.
- **Scan Parallèle et Adaptatif** : L'application exécute les scans sur plusieurs threads. Le nombre de workers s'ajuste dynamiquement en fonction du taux de succès pour
  optimiser la performance et la discrétion.
- **Documentation Stratégique Intégrée** : Accédez à une documentation technique détaillée pour chaque stratégie d'évasion et chaque outil directement depuis l'interface,
  facilitant le choix de l'approche la plus adaptée.

## Comment ça marche ?

1. **Configuration** : L'administrateur définit les chemins dans `config.toml`, les plages d'IP dans `.env`, et personnalise les stratégies de scan dans les fichiers
   `.yaml` du répertoire `strategies/`.
2. **Lancement** : Le serveur principal est lancé avec `python3 main.py`.
3. **Interface Utilisateur** : L'utilisateur accède à l'interface web, qui charge dynamiquement la liste des scanners, des stratégies, des configurations de ports et de
   la documentation via des appels API.
4. **Exécution d'un Scan** :
    * **Scan Simple** : L'utilisateur sélectionne un outil (ex: Nmap), une stratégie, des ports, et clique sur "Démarrer".
    * **Scan d'Évasion IA** : L'utilisateur choisit un préréglage d'évasion (ex: "China GFW Bypass") ou personnalise les paramètres (empreinte OS, timing) dans le menu "
      AI Evasion", puis lance un scan avec Scapy.
5. **Supervision** : Le backend lance les scans en parallèle. Le frontend affiche des "tuiles" pour chaque thread actif, montrant les logs en temps réel. Une barre de
   progression globale indique l'avancement.
6. **Stockage** : Les résultats détaillés sont sauvegardés dans le répertoire `results/`, organisés par type de scanner, stratégie et adresse IP.

## Configuration

La flexibilité de l'outil repose sur des fichiers de configuration simples.

### 1\. Chemins de l'Application (`config.toml`)

Ce fichier centralise tous les chemins utilisés par l'application.

```toml
[paths]
docs_dir = "docs"
strategies_dir = "strategies"
results_dir = "results"
progress_file = "progress.txt"
```

### 2\. Plages d'IP (`.env`)

Définissez les cibles dans un fichier `.env` à la racine du projet.

```dotenv
IP_RANGES=192.168.1.0/24,10.0.0.0/8
```

### 3\. Stratégies de Scan (`strategies/`)

Chaque outil possède son propre fichier de stratégies. Par exemple, pour `strategies/scapy-strategies.yaml` :

```yaml
strategies:
  ai-evasion-windows10:
    ports: "<ports>"
    scan_type: "syn"
    delay: 1.5
    advanced_evasion: true
    os_fingerprint: "windows10"
    timing_pattern: "fibonacci"
    # ... et bien d'autres paramètres
```

## Installation

1. Clonez ce dépôt sur votre machine.
2. Installez les dépendances Python (y compris `toml`) :
   ```bash
   pip install -r requirements.txt
   ```
3. Configurez votre fichier `config.toml` pour qu'il corresponde à votre structure de répertoires.
4. Configurez votre fichier `.env` avec les plages d'IP à scanner.
5. Assurez-vous que les outils de scan (Nmap, Masscan, Netcat, etc.) sont installés et accessibles dans le `PATH` système.
6. **Configurez les capacités Linux** pour les outils qui le nécessitent (voir la section Prérequis).
7. Lancez le serveur :
   ```bash
   python3 main.py
   ```
8. Ouvrez votre navigateur à l'adresse `http://localhost:5001`.

## Prérequis

- **Python 3.8+** et les dépendances listées dans `requirements.txt`.

- **Outils de Scan Externes** : `nmap`, `masscan`, `hping3`, `netcat`, `curl` doivent être installés.

- **Privilèges Élevés (via `setcap`)** : Certains scanners (Nmap, Hping3, Scapy, Netcat pour l'écoute sur ports bas) nécessitent des privilèges élevés. Il est recommandé
  de configurer les capacités Linux (`setcap`) pour autoriser leur exécution sans `sudo` pour l'utilisateur qui lance l'application.

  Exemple de configuration des capacités (exécuter une seule fois) :

  ```bash
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
  sudo setcap cap_net_bind_service+eip $(which nc)
  # Pour Scapy, utilisez le wrapper binaire comme décrit dans la documentation (docs/SCAPY-NMAP-ROOT.md)
  ```

## Licence

Ce projet est distribué sous la **licence MIT**.

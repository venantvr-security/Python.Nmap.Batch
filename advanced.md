# INSTALL.md

Ce document explique comment installer et configurer les dépendances nécessaires pour exécuter le projet de scan réseau
utilisant les scanners `NmapScanner`,
`NetcatScanner`, `ScapyScanner`, `MasscanScanner`, et `Hping3Scanner`. Les instructions sont basées sur un système
Ubuntu/Debian, mais peuvent être adaptées à d'autres
distributions Linux ou systèmes avec des ajustements.

## Prérequis

- **Système d'exploitation** : Ubuntu 20.04/22.04 ou Debian 11/12 recommandé.
- **Accès root** : Certaines installations nécessitent des privilèges `sudo`.
- **Python** : Version 3.8 ou supérieure.
- **Connexion Internet** : Pour télécharger les paquets et dépendances.

## Étape 1 : Mise à jour du système

Avant d’installer les dépendances, mettez à jour votre système pour éviter les conflits de paquets :

```bash
sudo apt update && sudo apt upgrade -y
```

## Étape 2 : Installation des dépendances de base

### 1. Python et pip

Installez Python et son gestionnaire de paquets `pip` si ce n’est pas déjà fait :

```bash
sudo apt install python3 python3-pip -y
```

Vérifiez les versions installées :

```bash
python3 --version
pip3 --version
```

### 2. Git (optionnel)

Si vous clonez le projet depuis un dépôt Git, installez Git :

```bash
sudo apt install git -y
```

## Étape 3 : Installation des outils de scan

Chaque scanner nécessite un outil spécifique. Installez-les comme suit :

### 1. Nmap (pour `NmapScanner`)

Nmap est un outil de scan réseau populaire :

```bash
sudo apt install nmap -y
```

Vérifiez l’installation :

```bash
nmap --version
```

### 2. Netcat (pour `NetcatScanner`)

Netcat (`nc`) est un outil léger pour tester les connexions réseau :

```bash
sudo apt install netcat -y
```

Vérifiez l’installation (selon la variante installée, cela peut être `nc.traditional` ou `nc.openbsd`) :

```bash
nc -h
```

### 3. Scapy (pour `ScapyScanner`)

Scapy est une bibliothèque Python pour manipuler les paquets réseau :

```bash
pip3 install scapy
```

Vérifiez l’installation en exécutant un script Python simple :

```python
from scapy.all import *

print("Scapy est installé")
```

**Note** : Scapy nécessite des privilèges root pour envoyer des paquets réseau. Exécutez votre script avec `sudo` si
nécessaire.

### 4. Masscan (pour `MasscanScanner`)

Masscan est un scanner rapide pour de grandes plages IP :

```bash
sudo apt install masscan -y
```

Vérifiez l’installation :

```bash
masscan --version
```

**Note** : Masscan peut nécessiter des privilèges root pour fonctionner correctement.

### 5. Hping3 (pour `Hping3Scanner`)

Hping3 est un outil pour générer des paquets personnalisés :

```bash
sudo apt install hping3 -y
```

Vérifiez l’installation :

```bash
hping3 --version
```

## Étape 4 : Installation des dépendances Python supplémentaires

Le projet utilise des bibliothèques Python pour gérer les fichiers YAML et Flask :

### 1. PyYAML

Pour lire les fichiers de stratégies YAML :

```bash
pip3 install pyyaml
```

### 2. Flask

Pour exécuter le serveur web :

```bash
pip3 install flask python-dotenv
```

### 3. Autres dépendances (optionnel)

Si vous utilisez un environnement virtuel (recommandé), créez-le et activez-le :

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # Si un fichier requirements.txt existe
```

## Étape 5 : Configuration du projet

1. **Clonez ou déplacez les fichiers du projet** :
   Si vous utilisez Git :
   ```bash
   git clone <URL-du-dépôt>
   cd <nom-du-projet>
   ```

2. **Créez le dossier `strategies/`** :
   ```bash
   mkdir -p strategies
   ```
   Ajoutez les fichiers YAML nécessaires :
    - `strategies/nmap-strategies.yaml`
    - `strategies/netcat-strategies.yaml`
    - `strategies/scapy-strategies.yaml`
    - `strategies/masscan-strategies.yaml`
    - `strategies/hping3-strategies.yaml`

   Exemple pour `nmap-strategies.yaml` :
   ```yaml
   strategies:
     basic:
       - "-v"
       - "-O"
       - "-p"
       - "80,443"
   ```

3. **Créez un fichier `.env` (optionnel)** :
   Dans le répertoire racine, définissez les plages IP à scanner :
   ```bash
   echo "IP_RANGES=192.168.1.0/24" > .env
   ```

## Étape 6 : Vérification

Testez chaque outil pour confirmer qu’il fonctionne :

- Nmap : `nmap -v localhost`
- Netcat : `nc -z localhost 80`
- Scapy : `sudo python3 -c "from scapy.all import *; print(sr1(IP(dst='localhost')/TCP(dport=80), timeout=1))"`
- Masscan : `sudo masscan localhost -p80`
- Hping3 : `sudo hping3 -S localhost -p 80 -c 10`

Si tous renvoient une sortie valide, l’installation est réussie.

## Étape 7 : Lancement du projet

Lancez le serveur Flask :

```bash
python3 app.py
```

Ouvrez un navigateur à `http://localhost:5000` pour accéder à l’interface.

## Notes supplémentaires

- **Privilèges root** : Les outils comme Scapy, Masscan, et Hping3 nécessitent souvent `sudo` pour manipuler les
  interfaces réseau. Assurez-vous que votre utilisateur a
  les permissions nécessaires ou exécutez le script avec `sudo python3 app.py`.
- **Pare-feu** : Si un pare-feu local bloque les scans, désactivez-le temporairement pour tester (`sudo ufw disable` sur
  Ubuntu).
- **Tor/Proxy (optionnel)** : Pour plus de furtivité, installez `proxychains` et `tor` :
  ```bash
  sudo apt install proxychains tor -y
  service tor start
  ```

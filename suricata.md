# Setup

Voici un résumé complet de notre discussion, regroupé par produit, en incluant les fichiers de configuration à modifier, les commandes de debug et les étapes de
dépannage :

## 1. Suricata

### A. Installation et Configuration

- **Installation :**
  ```bash
  sudo apt update
  sudo apt install suricata
  ```
- **Fichier de configuration principal :**  
  `/etc/suricata/suricata.yaml`
    - **Section outputs :**
      ```yaml
      outputs:
        - fast:
            enabled: yes
            filename: fast.log
            append: yes
        - eve-log:
            enabled: yes
            filetype: json
            filename: /var/log/suricata/eve.json
      ```
    - **Interface de capture :**  
      Si l'interface par défaut est incorrecte (exemple : `eth0` n'existe pas), modifie la section (souvent sous `af-packet` ou autre) pour indiquer le nom exact de ton
      interface (par exemple, `ens33` ou `enp0s3`) :
      ```yaml
      af-packet:
        - interface: ens33
          threads: auto
      ```

### B. Vérifications et Debug

- **Vérifier le statut du service :**
  ```bash
  sudo systemctl status suricata
  ```
- **Consulter les logs :**
  ```bash
  sudo tail -f /var/log/suricata/suricata.log
  sudo tail -f /var/log/suricata/fast.log
  sudo tail -f /var/log/suricata/eve.json
  ```
- **Tester la configuration :**
  ```bash
  sudo suricata -T -c /etc/suricata/suricata.yaml
  ```

## 2. Elasticsearch

### A. Installation et Configuration

- **Installation via les paquets officiels :**
    1. Ajouter la clé GPG :
       ```bash
       wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
       ```
    2. Ajouter le dépôt (exemple pour la série 7.x) :
       ```bash
       sudo sh -c 'echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list'
       sudo apt-get update
       sudo apt-get install elasticsearch
       ```
- **Fichier de configuration principal :**  
  `/etc/elasticsearch/elasticsearch.yml`
    - Modifie ou ajoute ces lignes pour qu’Elasticsearch écoute sur toutes les interfaces :
      ```yaml
      network.host: 0.0.0.0
      http.port: 9200
      ```
- **Fichier de configuration de la JVM :**  
  `/etc/elasticsearch/jvm.options`
    - Ajoute ou modifie ces paramètres pour ajuster la mémoire (adapté à ton système) :
      ```
      -Xms1g
      -Xmx1g
      ```
  Si ces lignes ne sont pas présentes, ajoute-les manuellement en début de fichier.

### B. Vérifications et Debug

- **Vérifier le statut du service :**
  ```bash
  sudo systemctl status elasticsearch
  ```
- **Redémarrer Elasticsearch :**
  ```bash
  sudo systemctl restart elasticsearch
  ```
- **Consulter les logs :**
  ```bash
  sudo tail -f /var/log/elasticsearch/elasticsearch.log
  sudo journalctl -u elasticsearch --no-pager | tail -n 50
  ```
- **Tester avec curl (HTTP ou HTTPS selon ta config) :**
  ```bash
  curl -X GET "http://localhost:9200"
  ```
  (ou, en cas d’auto-signé SSL, utilisez `-k` pour ignorer la vérification)
  ```bash
  curl -k -X GET "https://localhost:9200"
  ```
- **Vérifier que les ports sont libres :**
  ```bash
  sudo ss -tulnp | grep 9200
  sudo netstat -tulnp | grep 9200
  ```
- **Vérifier l'utilisation mémoire et ressources système :**
  ```bash
  free -m
  swapon --show
  df -h
  ```

## 3. Kibana

### A. Installation et Configuration

- **Installation :**  
  Ajoute la clé GPG et le dépôt (similaire à Elasticsearch), puis :
  ```bash
  sudo apt-get install kibana
  ```
- **Fichier de configuration principal :**  
  `/etc/kibana/kibana.yml`
    - Pour que Kibana écoute sur toutes les interfaces :
      ```yaml
      server.host: "0.0.0.0"
      ```
    - Pour se connecter à Elasticsearch :
      ```yaml
      elasticsearch.hosts: ["http://localhost:9200"]
      ```
    - Si la sécurité est activée, renseigne :
      ```yaml
      elasticsearch.username: "kibana_system"  # ou ton utilisateur dédié
      elasticsearch.password: "TON_MOT_DE_PASSE"
      ```

### B. Vérifications et Debug

- **Vérifier le statut du service :**
  ```bash
  sudo systemctl status kibana
  ```
- **Redémarrer Kibana :**
  ```bash
  sudo systemctl restart kibana
  ```
- **Consulter les logs :**
  ```bash
  sudo journalctl -u kibana -f
  ```
- **Accéder à Kibana via le navigateur :**
  ```http
  http://<ton_IP>:5601
  ```

## 4. Filebeat

### A. Installation et Configuration

- **Installation :**
  ```bash
  wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.x-amd64.deb
  sudo dpkg -i filebeat-7.x-amd64.deb
  ```
- **Fichier de configuration principal :**  
  `/etc/filebeat/filebeat.yml`
    - **Entrée pour Suricata :**
      ```yaml
      filebeat.inputs:
        - type: log
          enabled: true
          paths:
            - /var/log/suricata/eve.json
      ```
    - **Sortie vers Elasticsearch :**
      ```yaml
      output.elasticsearch:
        hosts: ["http://localhost:9200"]
        username: "rvv"      # ou un autre utilisateur si nécessaire
        password: "TON_MOT_DE_PASSE"
      ```
    - **Configuration pour Kibana Setup (pour les dashboards) :**
      ```yaml
      setup.kibana:
        host: "http://localhost:5601"
        username: "rvv"
        password: "TON_MOT_DE_PASSE"
      ```

### B. Vérifications et Debug

- **Tester la sortie vers Elasticsearch :**
  ```bash
  sudo filebeat test output
  ```
- **Installer les dashboards :**
  ```bash
  sudo filebeat setup --dashboards
  ```
- **Redémarrer Filebeat :**
  ```bash
  sudo systemctl restart filebeat
  ```
- **Consulter les logs de Filebeat si besoin :**
  ```bash
  sudo journalctl -u filebeat -f
  ```

# Comment fonctionne Suricata ?

Suricata est un moteur open-source de détection d'intrusions (IDS), de prévention d'intrusions (IPS) et de surveillance de la sécurité réseau. Voici comment il
fonctionne :

### 1. Capture du trafic réseau

- **Interception du trafic :**  
  Suricata capte le trafic réseau en utilisant l'interface réseau configurée (via des méthodes comme *af-packet*, *pcap* ou *netmap*).
- **Multi-threading :**  
  Il exploite le multi-threading pour analyser simultanément plusieurs flux de données, optimisant ainsi la performance sur des réseaux à haut débit.

### 2. Analyse et traitement des paquets

- **Décodage des protocoles :**  
  Suricata analyse chaque paquet en décodant différents protocoles (TCP, UDP, HTTP, DNS, etc.).
- **Extraction des métadonnées :**  
  Il extrait des informations comme les adresses IP, les ports, les en-têtes et les contenus qui serviront à la détection d'anomalies ou d'intrusions.

### 3. Détection d'intrusions

- **Basée sur des règles/signatures :**  
  Suricata utilise un ensemble de règles (similaires à celles de Snort) pour détecter des comportements malveillants connus. Ces règles peuvent inclure des signatures
  pour détecter des scans de ports, des attaques par injection, des tentatives d'exploitation, etc.
- **Détection d'anomalies :**  
  Au-delà des règles statiques, il peut aussi identifier des comportements anormaux qui ne correspondent pas à des schémas normaux, permettant ainsi la détection de
  nouvelles menaces.

### 4. Sortie et journalisation

- **Logs structurés (EVE JSON) :**  
  Suricata peut exporter ses alertes et événements dans un format JSON (EVE JSON), facilitant ainsi l'intégration avec des outils de SIEM ou des dashboards (comme
  Kibana).
- **Alertes en temps réel :**  
  Il peut consigner les alertes sur un fichier (par exemple, *fast.log*) et/ou envoyer des événements via d'autres méthodes (syslog, Elasticsearch, etc.).

### 5. Modes de fonctionnement

- **IDS (Intrusion Detection System) :**  
  En mode IDS, Suricata analyse passivement le trafic réseau et génère des alertes en cas de détection d'activité suspecte.
- **IPS (Intrusion Prevention System) :**  
  En mode IPS, il peut être configuré pour bloquer activement certains paquets ou connexions lorsqu'une menace est détectée, en s'intégrant avec des systèmes de firewall
  ou d'autres mécanismes de blocage.

### Conclusion

Suricata fonctionne en interceptant le trafic réseau, en décodant et en analysant chaque paquet à l'aide de règles prédéfinies et de méthodes d'analyse heuristique. Grâce
à sa capacité à traiter plusieurs flux en parallèle et à générer des logs détaillés, il constitue un outil puissant pour surveiller et sécuriser les réseaux contre les
intrusions et les attaques malveillantes.

# Machine Learning

Oui, si tes logs (par exemple ceux de Suricata via Filebeat) arrivent dans Elasticsearch, tu peux exploiter ces données pour entraîner des modèles ou utiliser les
fonctionnalités d'anomalie de machine learning offertes par Elastic.

### Quelques points à retenir :

- **Centralisation des logs :**  
  Une fois que tes alertes et événements (par exemple, issus de Suricata) sont envoyés dans Elasticsearch, toutes ces informations sont indexées et disponibles pour
  analyse via Kibana.

- **Machine Learning intégré dans Elastic :**  
  Elastic propose des fonctionnalités de machine learning (ML) dans Kibana, permettant de détecter automatiquement des anomalies dans les données indexées. Cela
  fonctionne de manière non supervisée pour repérer des comportements inhabituels dans le trafic réseau ou dans les logs.

- **Entraînement de modèles personnalisés :**  
  Tu peux également exporter ces données et les utiliser pour entraîner des modèles personnalisés en dehors de l'écosystème Elastic (par exemple avec Python, scikit-learn
  ou TensorFlow) si tu souhaites faire des analyses plus spécifiques ou supervisées.

### Exemple d'utilisation dans Elastic ML :

1. **Activation de ML dans Kibana :**  
   Dans Kibana, dans la section Machine Learning, tu peux créer un job qui analysera un index particulier (comme `filebeat-*` ou un index dédié à Suricata) et détectera
   des anomalies sur la base de statistiques (nombre d'alertes, variations temporelles, etc.).

2. **Création de jobs ML :**  
   L'interface te guide pour sélectionner les champs à analyser (par exemple, le nombre d'événements par intervalle de temps, la répartition des types d'alertes, etc.) et
   crée un modèle d'anomalie pour repérer des comportements hors norme.

En résumé, oui, une fois que tes données arrivent dans Elasticsearch, tu as la possibilité d'exploiter ces informations pour entraîner un modèle, soit via les
fonctionnalités de ML d'Elastic, soit en exportant les données pour un traitement externe. Cela peut être très utile pour améliorer la détection d'intrusions ou
identifier des patterns inhabituels dans ton trafic réseau.

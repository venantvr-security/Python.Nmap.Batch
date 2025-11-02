# Exécuter Nmap et Scapy sans Privilèges Root

Ce guide explique comment configurer `nmap` et `scapy` pour utiliser des fonctionnalités nécessitant des privilèges élevés (comme l'envoi de paquets RAW) sans avoir à utiliser `sudo` à chaque exécution. Ces méthodes sont destinées à un usage légal sur des machines ou des réseaux que vous possédez ou pour lesquels vous avez une autorisation écrite.

> **Avertissement de Sécurité** : Scanner des réseaux sans autorisation explicite est illégal. N'utilisez ces techniques que dans un cadre autorisé.

## 1. Nmap : Exécution sans `sudo`

Par défaut, `nmap` nécessite les privilèges root pour effectuer des scans discrets et puissants comme le scan SYN (`-sS`). La solution la plus propre est d'utiliser les **capacités (capabilities) Linux**.

### Solution : Utiliser les Capacités Fichiers

Cette méthode accorde à l'exécutable `nmap` uniquement les droits nécessaires pour la manipulation de paquets RAW, sans donner tous les droits root au processus.

1.  **Attribuer les capacités (une seule fois) :**

    ```bash
    # En tant que root ou via sudo
    sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
    ```

2.  **Vérifier l'attribution :**

    ```bash
    getcap $(which nmap)
    # La sortie doit être : cap_net_raw,cap_net_admin,cap_net_bind_service+eip
    ```

3.  **Utilisation :**

    Vous pouvez maintenant lancer des scans privilégiés en tant qu'utilisateur normal.

    ```bash
    # Ce scan SYN fonctionne désormais sans sudo
    nmap -sS 192.168.1.1
    ```

*   **Avantages** : Plus sécurisé que d'utiliser `sudo`, car seul `nmap` obtient les privilèges. Pas besoin de taper le mot de passe à chaque fois.
*   **Note** : Si vous mettez à jour `nmap` via votre gestionnaire de paquets, vous devrez probablement ré-exécuter la commande `setcap`.

## 2. Scapy : Exécution sans `sudo`

Comme Nmap, Scapy a besoin de la capacité `CAP_NET_RAW` pour forger et envoyer des paquets personnalisés. Appliquer cette capacité directement à l'interpréteur Python (`/usr/bin/python3`) est **dangereux**, car cela donnerait ces droits à n'importe quel script Python.

### Solution Recommandée : Créer un Wrapper Binaire

1.  **Créer le script wrapper :**

    ```python
    # ~/scapy-wrapper.py
    #!/usr/bin/env python3
    from scapy.all import *
    import sys

    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        exec(open(sys.argv[1]).read())
    else:
        print("Usage: scapy-wrapper.py <script.py>")
    ```

2.  **Rendre le wrapper exécutable :**

    ```bash
    chmod +x ~/scapy-wrapper.py
    ```

3.  **Attribuer les capacités au wrapper :**

    ```bash
    sudo setcap cap_net_raw,cap_net_admin+eip ~/scapy-wrapper.py
    ```

4.  **Utiliser le wrapper pour lancer vos scripts Scapy :**

    ```bash
    # Exemple avec un script mon_script_scapy.py
    ~/scapy-wrapper.py mon_script_scapy.py
    ```

# Tester l'Évasion de Pare-feu avec Scapy et des PCAP

Cette section explique comment utiliser Scapy pour rejouer des fichiers `.pcap` afin de tester l'efficacité des pare-feu et des IDS, et surtout, comment interpréter les résultats.

## Le Principe : Scapy envoie, vous écoutez

Quand vous rejouez un `.pcap` avec `send()`, Scapy envoie les paquets et c'est tout. Il n'attend ni ne traite aucune réponse. C'est à vous de mettre en place une écoute pour voir ce qui se passe.

```python
from scapy.all import *

# Scapy lit les paquets et les envoie sur le réseau
pkts = rdpcap("mon_test_evasion.pcap")
send(pkts)
```

## Comment Capturer et Interpréter les Réponses

Pour savoir si votre évasion a fonctionné, vous devez observer la réaction du réseau et de la cible.

### Méthode 1 : `sniff()` en parallèle

C'est la méthode la plus fiable. Vous lancez une capture de paquets juste avant d'envoyer votre trafic de test.

```python
from scapy.all import *

# Définir la cible et le filtre
target_ip = "192.168.1.100"
sniff_filter = f"host {target_ip}"

# Lancer la capture en arrière-plan de manière asynchrone
print("Démarrage de la capture...")
# noinspection PyUnresolvedReferences
sniff_task = async_sniff(iface="eth0", filter=sniff_filter, timeout=15)

# Envoyer les paquets du PCAP
print("Envoi des paquets de test...")
pkts = rdpcap("evasion.pcap")
send(pkts, iface="eth0")

# Arrêter la capture et récupérer les paquets
responses = sniff_task.stop()
print(f"{len(responses)} réponses capturées.")

# Analyser les réponses
for pkt in responses:
    pkt.show()
```

### Méthode 2 : Utiliser `sr()` (Send and Receive)

Cette méthode est utile si vos paquets de test attendent une réponse directe (par exemple, un `SYN` qui attend un `SYN-ACK`).

```python
from scapy.all import *

pkts = rdpcap("test_syn.pcap")
answered, unanswered = sr(pkts, timeout=3, verbose=0)

print(f"Paquets ayant reçu une réponse : {len(answered)}")
print(f"Paquets sans réponse : {len(unanswered)}")

for sent, recv in answered:
    print(f"{sent.summary()}  ==>  {recv.summary()}")
```

## Tableau d'Interprétation des Résultats

| Réponse Observée                   | Signification Probable                                      | Conclusion sur l'Évasion                            |
|:-----------------------------------|:------------------------------------------------------------|:----------------------------------------------------|
| **SYN-ACK**                        | Le port est ouvert et le pare-feu a laissé passer.          | ✅ **Réussie**                                       |
| **RST / RST-ACK**                  | Le port est fermé ou le pare-feu a rejeté activement.       | ❌ **Échouée**                                       |
| **ICMP Unreachable**               | Une règle de pare-feu ou de routage bloque le trafic.       | ❌ **Échouée**                                       |
| **Aucune réponse**                 | Le paquet a été droppé silencieusement (firewall) ou perdu. | ⚠️ **Incertaine (mais probable échec)**             |
| **Alerte dans les logs IDS/IPS**   | Le trafic a été identifié comme suspect.                    | детеcтед **Détectée (même si le paquet est passé)** |
| **Paquet réassemblé différemment** | Le pare-feu a normalisé le trafic avant de le transmettre.  | 🛡️ **Contournée par le pare-feu**                  |

**Conclusion** : Pour valider un test d'évasion, il ne suffit pas d'envoyer des paquets. Il est impératif de **capturer le trafic en parallèle** et, idéalement, de **consulter les logs** du pare-feu ou de l'IDS pour avoir une image complète de la situation.

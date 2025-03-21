# Scapy - Manipulation avancée de paquets

## Présentation

Scapy est une bibliothèque Python pour créer, envoyer, et analyser des paquets réseau personnalisés. Elle est idéale
pour des scans furtifs et des tests avancés.

## Protocoles exploités

- **TCP** : Scans SYN, ACK, FIN, personnalisés via drapeaux.
- **UDP** : Envoi de datagrammes personnalisés.
- **ICMP** : Ping et autres types de requêtes.
- **IP** : Manipulation des en-têtes (TTL, fragmentation).

## Options principales (via code)

- `IP(dst=<ip>)` : Définit la destination.
- `TCP(sport=<port>, dport=<port>, flags="S")` : Crée un paquet TCP (ex. SYN).
- `sr1(packet, timeout=<sec>)` : Envoie un paquet et attend une réponse.
- `random.randint(1024, 65535)` : Port source aléatoire pour furtivité.

## Spécificités techniques

- **Personnalisation totale** : Contrôle des en-têtes IP/TCP (ex. taille de fenêtre, options TCP) pour imiter un trafic
  légitime.
- **Furtivité** : Délais aléatoires et ports sources variables réduisent la détectabilité.
- **Analyse fine** : Inspection des réponses (ex. flags SYN-ACK ou RST) pour déterminer l’état des ports.
- **Flexibilité** : Supporte ARP, IPv6, DNS, etc., avec des scripts personnalisés.

## Limites

- Nécessite des privilèges root pour envoyer des paquets bruts.
- Plus lent que Nmap ou Masscan sans parallélisation explicite.
- Courbe d’apprentissage pour créer des scans complexes.
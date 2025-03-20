# Nmap - Network Mapper

## Présentation

Nmap est un outil de scan réseau open-source conçu pour découvrir les hôtes, les services, et les vulnérabilités sur un réseau. Il est largement utilisé pour l’audit de
sécurité et l’analyse de réseau.

## Protocoles exploités

- **TCP** : Scans SYN (furtifs), Connect, FIN, Xmas, Null.
- **UDP** : Détection des ports ouverts via datagrammes UDP.
- **ICMP** : Utilisé pour la découverte d’hôtes (ping sweep).
- **SCTP** : Support pour les réseaux modernes (moins courant).

## Options principales

- `-sS` : Scan SYN (furtif, ne complète pas la connexion TCP).
- `-sU` : Scan UDP.
- `-O` : Détection du système d’exploitation basée sur les caractéristiques TCP/IP (TTL, fenêtre TCP, etc.).
- `-sV` : Détection de version des services via bannières et empreintes.
- `--script vuln` : Scripts NSE pour détecter les vulnérabilités (ex. CVE).
- `-p <ports>` : Spécifie les ports à scanner (ex. `-p 1-1000` ou `-p 80,443`).
- `-T<0-5>` : Timing (0=paranoïaque, 5=agressif).

## Spécificités techniques

- **Moteur NSE** : Scripting Engine pour des scans personnalisés (ex. détection de SSLv3 ou Heartbleed).
- **Empreintes TCP/IP** : Analyse des options TCP (window size, MSS) pour identifier l’OS.
- **Furtivité** : Le scan SYN envoie un paquet SYN sans établir de connexion complète, évitant souvent les logs de niveau applicatif.
- **Performance** : Parallélisation interne pour scanner rapidement de grandes plages IP.

## Limites

- Détectable par un IDS/IPS via signatures de paquets ou rythme élevé.
- Nécessite des privilèges root pour certaines options (ex. `-sS`).
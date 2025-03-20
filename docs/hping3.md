# Hping3 - Générateur de paquets personnalisés

## Présentation

Hping3 est un outil CLI pour générer et analyser des paquets TCP, UDP, et ICMP. Il est utilisé pour des tests de charge, de furtivité, ou d’analyse réseau.

## Protocoles exploités

- **TCP** : Scans SYN, ACK, FIN, personnalisés via drapeaux.
- **UDP** : Envoi de datagrammes.
- **ICMP** : Requêtes ping et autres types.

## Options principales

- `-S` : Scan SYN.
- `-p <port>` : Port cible (ex. `-p 443`).
- `-i u<µs>` : Intervalle entre paquets en microsecondes (ex. `-i u50000` pour 50ms).
- `-c <n>` : Nombre de paquets à envoyer (ex. `-c 10`).
- `--flood` : Mode inondation (non furtif).

## Spécificités techniques

- **Personnalisation** : Contrôle des drapeaux TCP et des données envoyées.
- **Furtivité** : Intervalles longs (ex. `-i u50000`) pour imiter un trafic légitime.
- **Analyse** : Retourne les réponses (ex. SYN-ACK pour ports ouverts) pour une analyse manuelle ou scriptée.
- **Flexibilité** : Supporte TCP, UDP, ICMP avec des options comme la fragmentation.

## Limites

- Pas de scan multi-ports natif (une invocation par port).
- Nécessite une analyse externe (ex. Wireshark) pour des résultats détaillés.
- Détectable si utilisé en mode agressif (`--flood`).
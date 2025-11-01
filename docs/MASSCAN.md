# Masscan - Scanner ultra-rapide

## Présentation

Masscan est un outil optimisé pour scanner rapidement de grandes plages IP. Il est conçu pour la performance brute,
souvent utilisé pour des audits à grande échelle.

## Protocoles exploités

- **TCP** : Scans SYN uniquement (pas de connexion complète).
- **IP** : Gestion des en-têtes pour la découverte d’hôtes.

## Options principales

- `-p <ports>` : Ports à scanner (ex. `-p 80,443`).
- `--rate <n>` : Vitesse en paquets/seconde (ex. `--rate 100` pour furtivité).
- `--wait <sec>` : Délai entre envois (ex. `--wait 2`).
- `--banners` : Récupère les bannières des services (limité).

## Spécificités techniques

- **Performance** : Utilise une pile réseau personnalisée pour envoyer des millions de paquets par seconde.
- **Furtivité ajustable** : Réduction de la vitesse (`--rate`) et ajout de délais (`--wait`) pour éviter les IDS.
- **SYN uniquement** : Envoie des paquets SYN sans établir de connexion, similaire à `nmap -sS`.
- **Randomisation** : Mélange aléatoire des IPs/ports pour réduire les motifs détectables.

## Limites

- Pas de détection d’OS ou de version par défaut.
- Moins de flexibilité que Nmap ou Scapy.
- Peut être bloqué par un IDS sensible aux scans SYN rapides.
# Netcat - Le "couteau suisse" des réseaux

## Présentation

Netcat (`nc`) est un utilitaire réseau simple et polyvalent pour établir des connexions TCP/UDP et tester les ports. Il
est léger et souvent utilisé pour des diagnostics
ou des scans manuels.

## Protocoles exploités

- **TCP** : Connexion directe pour tester les ports ouverts.
- **UDP** : Envoi de datagrammes pour détecter les réponses (moins fiable car sans connexion).

## Options principales

- `-z` : Mode scan (teste les ports sans envoyer de données).
- `-v` : Mode verbeux (affiche les résultats).
- `-w <sec>` : Timeout pour chaque tentative (ex. `-w 2`).
- `-p <port>` : Spécifie le port source (rarement utilisé dans notre cas).
- `-u` : Mode UDP.

## Spécificités techniques

- **Simplicité** : Envoie une requête TCP ou UDP brute et attend une réponse (SYN-ACK ou RST pour TCP, réponse ou
  timeout pour UDP).
- **Furtivité limitée** : Pas de contrôle fin sur les paquets, donc détectable par un IDS sensible aux connexions
  répétées.
- **Flexibilité** : Peut être combiné avec des scripts pour des tests personnalisés.
- **Performance** : Mono-thread par défaut, donc lent pour scanner plusieurs ports ou IPs sans script externe.

## Limites

- Pas de détection d’OS ou de version.
- Réponses UDP peu fiables (pas de handshake).
- Détectable par un IDS surveillant les tentatives de connexion.
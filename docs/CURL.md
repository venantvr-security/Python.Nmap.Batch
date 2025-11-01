# Curl - Client URL

## Présentation

`curl` est un outil en ligne de commande open-source utilisé pour transférer des données vers ou depuis un serveur via
divers protocoles, principalement HTTP/HTTPS. Il est idéal pour tester la disponibilité et les réponses des services
web, ainsi que pour effectuer des requêtes simples ou complexes.

## Protocoles exploités

- **HTTP** : Requêtes GET, HEAD, POST, etc., pour tester les serveurs web.
- **HTTPS** : Support des connexions sécurisées via TLS/SSL.
- **FTP** : Transfert de fichiers (moins utilisé dans ce contexte).
- **SMTP/POP3/IMAP** : Envoi et réception d’emails (optionnel, non pertinent ici).

## Options principales

- `-s` : Mode silencieux, supprime la barre de progression et les messages d’erreur non critiques.
- `-I` : Requête HEAD, récupère uniquement les en-têtes HTTP sans le corps de la réponse.
- `--connect-timeout <secondes>` : Limite le temps d’établissement de la connexion (ex. `--connect-timeout 2`).
- `-m <secondes>` : Timeout maximal pour l’ensemble de l’opération (ex. `-m 5`).
- `-v` : Mode verbeux, affiche des détails sur la connexion et les en-têtes.
- `-k` : Ignore la vérification du certificat SSL (utile pour tester des serveurs auto-signés).
- `-L` : Suit les redirections HTTP (ex. 301, 302).

## Spécificités techniques

- **Simplicité** : Effectue des requêtes HTTP/HTTPS directes sans nécessiter de configuration complexe.
- **Réponse HTTP** : Analyse les codes de statut (ex. 200 OK, 404 Not Found) pour déterminer si un service est actif.
- **Flexibilité** : Supporte des en-têtes personnalisés (ex. `-H "User-Agent: custom"`) et des méthodes HTTP variées.
- **Performance** : Rapide pour des tests ponctuels, car il n’envoie qu’une seule requête par exécution (pas de flood
  comme `hping3`).
- **TLS/SSL** : Gère les connexions sécurisées avec inspection des certificats par défaut.

## Limites

- **Portée limitée** : Teste uniquement les services HTTP/HTTPS, pas les ports bruts TCP/UDP comme Nmap ou Scapy.
- **Dépendance au service** : Nécessite un serveur web actif pour donner une réponse significative (ex. pas de détection
  si le port est ouvert mais sans service HTTP).
- **Pas de furtivité** : Les requêtes HTTP apparaissent dans les logs des serveurs web, contrairement à un scan SYN
  furtif.
- **Pas de parallélisation native** : Une seule cible à la fois par commande, moins adapté pour scanner de larges
  plages.

# Pcap2 Scanner

## Description

Pcap2 est un scanner spécialisé qui rejoue des paquets capturés depuis des fichiers PCAP. Il permet de reproduire des patterns de trafic réseau réels, issus d'attaques ou
de comportements légitimes, pour effectuer des scans furtifs.

## Fonctionnalités

- **Replay de PCAP** : Charge des paquets depuis des fichiers `.pcap` et les modifie dynamiquement
- **Modification dynamique** : Adapte les adresses IP, ports et checksums à la volée
- **Compatible avec tous les types de scan** : SYN, FIN, XMAS, NULL, ACK, Maimon
- **Support des techniques d'évasion** : Decoys, timing patterns, fragmentation
- **Templates pré-configurés** : Inclut des captures de malware (Squirrelwaffle)

## Templates PCAP disponibles

Le scanner inclut 3 templates basés sur la campagne Squirrelwaffle (septembre 2021) :

1. **2021-09-20-squirrelwaffle-1.pcap** - Premier vecteur d'attaque
2. **2021-09-20-squirrelwaffle-2.pcap** - Variante avec TTL différent
3. **2021-09-20-squirrelwaffle-3.pcap** - Pattern de reconnaissance

## Configuration des stratégies

Chaque stratégie dans `pcap-player-strategies.yaml` doit spécifier un `template_pcap` :

```yaml
strategies:
  squirrelwaffle_1:
    scan_type: syn
    ports: "<ports>"
    delay: 0.5
    timeout: 2
    ttl: 64
    send_rst: true
    template_pcap: "2021-09-20-squirrelwaffle-1.pcap"
```

## Paramètres

- **template_pcap** (requis) : Nom du fichier PCAP dans `pcap_templates/`
- **scan_type** : Type de scan (syn, fin, xmas, null, ack, maimon)
- **ports** : Liste ou plage de ports à scanner
- **delay** : Délai entre chaque paquet (secondes)
- **timeout** : Timeout de réponse (secondes)
- **ttl** : Time-To-Live des paquets
- **send_rst** : Envoyer RST après connexion réussie
- **decoys** : Nombre d'IP decoys à générer
- **timing_pattern** : Pattern de timing (fibonacci, sine, prime, exponential, random)
- **advanced_evasion** : Activer les techniques d'évasion avancées

## Fonctionnement interne

1. Charge le fichier PCAP depuis `pcap_templates/`
2. Extrait le premier paquet TCP/IP
3. Remplace l'IP destination par la cible
4. Remplace le port destination par le port scanné
5. Remplace le port source par un port aléatoire ou configuré
6. Recalcule les checksums IP et TCP
7. Envoie le paquet modifié
8. Interprète la réponse selon le type de scan

## Avantages

- **Furtivité maximale** : Reproduit du trafic réel capturé
- **Évite les signatures** : Les IDS/IPS ne reconnaissent pas les patterns synthétiques
- **Timing authentique** : Peut reproduire les délais du trafic original
- **Fingerprinting légitime** : Les paquets ressemblent à du trafic malware/légitime réel

## Limitations

- Nécessite des fichiers PCAP contenant au moins un paquet TCP
- Les templates doivent être placés dans `pcap_templates/`
- Ne supporte pas la fragmentation des templates (seulement scan standard)
- Les payloads applicatifs des PCAP ne sont pas modifiés

## Cas d'usage

1. **Tests de sécurité** : Reproduire des attaques réelles pour tester les défenses
2. **Red Team** : Mimétisme de malware connu pour éviter la détection
3. **Forensics** : Rejouer des captures d'incidents pour analyse
4. **Recherche** : Tester la détection de patterns spécifiques

## Ajout de templates personnalisés

1. Placer le fichier `.pcap` dans `pcap_templates/`
2. Ajouter une stratégie dans `strategies/pcap-player-strategies.yaml`
3. Spécifier le nom du fichier dans `template_pcap`
4. Le scanner détectera automatiquement le nouveau template

## Avertissement

L'utilisation de ce scanner pour reproduire du trafic malware doit se faire uniquement dans un cadre légal et autorisé (pentest, CTF, lab isolé). Ne pas utiliser sur des réseaux de production sans autorisation explicite.

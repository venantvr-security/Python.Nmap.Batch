# Sommaire des Stratégies d'Évasion

Ce document sert de point d'entrée pour comprendre les différentes stratégies d'évasion implémentées. Les stratégies sont classées de la plus générale à la plus
spécifique.

## Ordre Logique des Stratégies

1. **[Stratégies d'Évasion de Base (IA)](AI-EVASION-BASIC.MD)** : Le point de départ. Comprendre comment imiter les systèmes d'exploitation courants.

2. **[Stratégies par Type de Cible](TARGET-SPECIFIC.MD)** : Affiner l'approche en fonction de l'environnement (Entreprise, Cloud, IoT).

3. **[Stratégies pour Trafic Temps Réel](REAL-TIME-TRAFFIC.MD)** : Mimétisme de trafic hautement prioritaire (Jeu, VoIP, Navigateur).

4. **[Stratégies pour Trafic Mobile/5G](MOBILE-5G.MD)** : Se concentrer sur les profils uniques des appareils mobiles.

5. **[Stratégies Géo-Ciblées](GEO-TARGETED.MD)** : Techniques spécifiques pour contourner les pare-feu nationaux (Chine, Russie).

6. **[Stratégies Anti-Détection](ANTI-DETECTION.MD)** : Techniques pour déjouer les défenses actives comme les honeypots et les tarpits.

7. **[Stratégies Avancées contre le Machine Learning](ADVANCED-ML-EVASION.MD)** : Le niveau le plus complexe, conçu pour vaincre les classifieurs IA par la confusion et
   l'entropie.

## Annuaire par Mots-Clés

* **Adversarial Machine Learning** : Voir `ADVANCED-ML-EVASION.MD`
* **Android** : Voir `AI-EVASION-BASIC.MD`, `MOBILE-5G.MD`
* **Anti-Tarpit** : Voir `ANTI-DETECTION.MD`
* **Chine (GFW)** : Voir `GEO-TARGETED.MD`
* **Cloud (AWS, Azure, GCP)** : Voir `TARGET-SPECIFIC.MD`
* **Corporate / Entreprise** : Voir `TARGET-SPECIFIC.MD`
* **Deep Packet Inspection (DPI)** : Voir `GEO-TARGETED.MD`
* **Délais (Timing Patterns)** : Présent dans toutes les stratégies, expliqué dans `AI-EVASION-BASIC.MD`
* **Entropie** : Voir `ADVANCED-ML-EVASION.MD`
* **Fingerprinting (Empreinte OS)** : Le cœur de `AI-EVASION-BASIC.MD`
* **Fragmentation** : Voir `AI-EVASION-LINUX` (dans `AI-EVASION-BASIC.MD`), `GEO-TARGETED.MD`
* **Gaming (Jeu en ligne)** : Voir `REAL-TIME-TRAFFIC.MD`
* **Honeypot (Pot de miel)** : Voir `ANTI-DETECTION.MD`
* **iOS** : Voir `MOBILE-5G.MD`
* **IoT (Internet des Objets)** : Voir `TARGET-SPECIFIC.MD`
* **Linux** : Voir `AI-EVASION-BASIC.MD`
* **macOS** : Voir `AI-EVASION-BASIC.MD`
* **Mobile / 5G** : Voir `MOBILE-5G.MD`
* **Padding (Rembourrage)** : Voir `ADVANCED-ML-EVASION.MD`, `GEO-TARGETED.MD`
* **Protocol Mimicry (Mimétisme de protocole)** : Voir `REAL-TIME-TRAFFIC.MD`
* **Qualité de Service (QoS)** : Voir `REAL-TIME-TRAFFIC.MD`
* **Russie (SORM)** : Voir `GEO-TARGETED.MD`
* **SIP / VoIP** : Voir `REAL-TIME-TRAFFIC.MD`
* **Uptime (Fake Uptime)** : Présent dans la plupart des stratégies, expliqué dans `AI-EVASION-BASIC.MD`
* **Windows** : Voir `AI-EVASION-BASIC.MD`, `TARGET-SPECIFIC.MD`

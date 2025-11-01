# Sommaire des Stratégies d'Évasion

Ce document sert de point d'entrée pour comprendre les différentes stratégies d'évasion implémentées. Les stratégies sont classées de la plus générale à la plus
spécifique.

## Ordre Logique des Stratégies

1. **[Stratégies d'Évasion de Base (IA)](AI-EVASION-BASIC.md)** : Le point de départ. Comprendre comment imiter les systèmes d'exploitation courants.

2. **[Stratégies par Type de Cible](TARGET-SPECIFIC.md)** : Affiner l'approche en fonction de l'environnement (Entreprise, Cloud, IoT).

3. **[Stratégies pour Trafic Temps Réel](REAL-TIME-TRAFFIC.md)** : Mimétisme de trafic hautement prioritaire (Jeu, VoIP, Navigateur).

4. **[Stratégies pour Trafic Mobile/5G](MOBILE-5G.md)** : Se concentrer sur les profils uniques des appareils mobiles.

5. **[Stratégies Géo-Ciblées](GEO-TARGETED.md)** : Techniques spécifiques pour contourner les pare-feu nationaux (Chine, Russie).

6. **[Stratégies Anti-Détection](ANTI-DETECTION.md)** : Techniques pour déjouer les défenses actives comme les honeypots et les tarpits.

7. **[Stratégies Avancées contre le Machine Learning](ADVANCED-ML-EVASION.md)** : Le niveau le plus complexe, conçu pour vaincre les classifieurs IA par la confusion et
   l'entropie.

## Annuaire par Mots-Clés

* **Adversarial Machine Learning** : Voir `ADVANCED-ML-EVASION.md`
* **Android** : Voir `AI-EVASION-BASIC.md`, `MOBILE-5G.md`
* **Anti-Tarpit** : Voir `ANTI-DETECTION.md`
* **Chine (GFW)** : Voir `GEO-TARGETED.md`
* **Cloud (AWS, Azure, GCP)** : Voir `TARGET-SPECIFIC.md`
* **Corporate / Entreprise** : Voir `TARGET-SPECIFIC.md`
* **Deep Packet Inspection (DPI)** : Voir `GEO-TARGETED.md`
* **Délais (Timing Patterns)** : Présent dans toutes les stratégies, expliqué dans `AI-EVASION-BASIC.md`
* **Entropie** : Voir `ADVANCED-ML-EVASION.md`
* **Fingerprinting (Empreinte OS)** : Le cœur de `AI-EVASION-BASIC.md`
* **Fragmentation** : Voir `AI-EVASION-LINUX` (dans `AI-EVASION-BASIC.md`), `GEO-TARGETED.md`
* **Gaming (Jeu en ligne)** : Voir `REAL-TIME-TRAFFIC.md`
* **Honeypot (Pot de miel)** : Voir `ANTI-DETECTION.md`
* **iOS** : Voir `MOBILE-5G.md`
* **IoT (Internet des Objets)** : Voir `TARGET-SPECIFIC.md`
* **Linux** : Voir `AI-EVASION-BASIC.md`
* **macOS** : Voir `AI-EVASION-BASIC.md`
* **Mobile / 5G** : Voir `MOBILE-5G.md`
* **Padding (Rembourrage)** : Voir `ADVANCED-ML-EVASION.md`, `GEO-TARGETED.md`
* **Protocol Mimicry (Mimétisme de protocole)** : Voir `REAL-TIME-TRAFFIC.md`
* **Qualité de Service (QoS)** : Voir `REAL-TIME-TRAFFIC.md`
* **Russie (SORM)** : Voir `GEO-TARGETED.md`
* **SIP / VoIP** : Voir `REAL-TIME-TRAFFIC.md`
* **Uptime (Fake Uptime)** : Présent dans la plupart des stratégies, expliqué dans `AI-EVASION-BASIC.md`
* **Windows** : Voir `AI-EVASION-BASIC.md`, `TARGET-SPECIFIC.md`

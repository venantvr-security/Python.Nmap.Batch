# Stratégies d'Évasion Complètes - Scapy Scanner

Ce document répertorie les **51 stratégies d'évasion** disponibles dans le Scapy Scanner, organisées par catégorie et cas d'usage.

---

## 📊 Vue d'Ensemble

| Catégorie           | Nombre | Focus Principal                          |
|---------------------|--------|------------------------------------------|
| Basic AI Evasion    | 4      | OS fingerprinting réaliste               |
| Geo-Targeted        | 2      | DPI spécifique par pays                  |
| Target-Specific     | 3      | Types de cibles (corporate, cloud, IoT)  |
| Anti-Detection      | 2      | Éviter honeypots et tarpits              |
| Advanced ML Evasion | 3      | Contourner ML/AI avancés                 |
| Mobile/5G           | 2      | Profils mobiles réalistes                |
| Real-Time Traffic   | 3      | Mimétisme trafic temps-réel              |
| Behavioral          | 4      | Comportement humain/légitime             |
| Anti-Forensic       | 2      | Confusion forensique                     |
| Contextual          | 4      | Contextes spécifiques (Docker, IoT, TOR) |
| Emerging            | 4      | Technologies émergentes                  |
| Exotic              | 2      | Techniques exotiques                     |
| **TOTAL**           | **51** | **Couverture complète**                  |

---

## 🎯 Catégorie 1: Basic AI Evasion

### ai-evasion-windows10

- **OS:** Windows 10 mimicry complet
- **Timing:** Fibonacci (balanced)
- **Decoys:** 20
- **Uptime:** 45 jours
- **Use Case:** Scan général furtif imitant workstation Windows

### ai-evasion-linux

- **OS:** Linux avec fragmentation
- **Timing:** Sine wave (smooth)
- **Decoys:** 25
- **Uptime:** 120 jours
- **Features:** Fragmentation + padding 32B
- **Use Case:** Serveurs Linux, plus agressif

### ai-evasion-macos

- **OS:** macOS profile
- **Timing:** Prime numbers (irregular)
- **Decoys:** 15
- **Uptime:** 90 jours
- **Use Case:** Mimétisme Mac pour réseaux créatifs/design

### ai-evasion-android

- **OS:** Android mobile
- **Timing:** Exponential
- **Decoys:** 30
- **Uptime:** 15 jours (mobile reboot fréquent)
- **Features:** Fragmentation + padding 16B
- **Use Case:** Trafic mobile Android

---

## 🌍 Catégorie 2: Geo-Targeted

### chinese-great-firewall-evasion

- **OS:** Android (populaire en Chine)
- **Timing:** Random (imprévisible)
- **Decoys:** 50 (maximum)
- **Delay:** 5.0s (très lent, éviter DPI)
- **Features:** Fragmentation + padding 128B + ports WeChat/Alipay
- **Use Case:** Contourner Great Firewall chinois

### russian-dpi-bypass

- **OS:** Windows 10
- **Timing:** Sine wave
- **Decoys:** 30
- **Features:** Fragmentation + padding 64B + ports Telegram/VK
- **Use Case:** DPI russe (SORM, Roskomnadzor)

---

## 🎯 Catégorie 3: Target-Specific

### corporate-firewall-bypass

- **OS:** Windows 11 (corporate standard)
- **Timing:** Exponential
- **Decoys:** 15
- **Uptime:** 30 jours (workstation)
- **Ports:** 443, 3389 (RDP), 1194/1723 (VPN), O365
- **Use Case:** Firewalls entreprise avec DPI

### cloud-provider-scan

- **OS:** Linux (VMs cloud)
- **Timing:** Fibonacci
- **Decoys:** 20
- **Uptime:** 365 jours (serveur long-running)
- **Ports:** 443, 8080, 8443, 9090
- **Use Case:** AWS, GCP, Azure avec WAF

### iot-device-scan

- **OS:** Linux embedded
- **Timing:** Random
- **Decoys:** 5 (peu de connexions)
- **Window:** 512 (petit buffer)
- **TTL:** 32 (local)
- **Use Case:** Devices IoT, embedded systems

---

## 🕵️ Catégorie 4: Anti-Detection

### honeypot-aware-scan

- **OS:** macOS
- **Timing:** Prime numbers
- **Delay:** 10.0s (ultra-lent)
- **Decoys:** 0 (pas de signature honeypot detection)
- **Uptime:** 180 jours
- **Features:** RST cleanup immédiat
- **Use Case:** Éviter honeypots avec détection comportementale

### anti-tarpit-scan

- **OS:** Windows 10
- **Timeout:** 1s (court, éviter tarpit)
- **Decoys:** 25 (saturer tarpit)
- **Use Case:** Contourner tarpits comme LaBrea

---

## 🤖 Catégorie 5: Advanced ML Evasion

### adaptive-learning-evasion

- **Scan Type:** FIN (furtif)
- **OS:** Linux
- **Timing:** Fibonacci
- **Decoys:** 35
- **Features:** Fragmentation + padding 48B + multi-techniques
- **Uptime:** 150 jours
- **Use Case:** ML adaptatif (auto-learning firewalls)

### ml-classifier-confusion

- **OS:** Android
- **Timing:** Random (max entropy)
- **Decoys:** 45 (maximum)
- **Features:** Padding 96B + fragmentation
- **Uptime:** 25 jours (variable)
- **Use Case:** Confusion ML/AI classifiers via entropy maximale

### ultra-stealth-ai-evasion

- **Scan Type:** FIN
- **OS:** Linux
- **Timing:** Random
- **Decoys:** 40
- **Features:** Padding 64B + fragmentation + TTL randomization
- **Uptime:** 200 jours
- **Use Case:** Évasion maximale contre AI/ML avancés

---

## 📱 Catégorie 6: Mobile/5G

### mobile-5g-profile

- **OS:** Android
- **Timing:** Exponential
- **Decoys:** 10
- **Uptime:** 3 jours (reboot fréquent)
- **Ports:** 443, 8443, 9000 (apps mobiles)
- **TTL:** 64 randomized
- **Use Case:** Trafic mobile 5G

### ios-device-profile

- **OS:** iOS
- **Timing:** Fibonacci
- **Decoys:** 12
- **Uptime:** 7 jours
- **Use Case:** iPhone/iPad traffic

---

## ⚡ Catégorie 7: Real-Time Traffic

### gaming-traffic-mimicry

- **OS:** Windows 11
- **Timing:** Exponential (burst pattern)
- **Delay:** 0.3s (très rapide)
- **Decoys:** 8
- **Ports:** 27015 (Steam), 3074 (Xbox), 5222 (Riot)
- **Use Case:** QoS gaming traffic prioritaire

### voip-sip-mimicry

- **OS:** Linux (Asterisk servers)
- **Timing:** Sine wave (flux vocal constant)
- **Delay:** 0.5s
- **Ports:** 5060/5061 (SIP)
- **Window:** 8192 (VoIP buffer)
- **Decoys:** 5
- **Use Case:** VoIP/téléphonie IP prioritaire

### legitimate-browser-scan

- **OS:** Windows 11
- **Timing:** Exponential
- **Decoys:** 10
- **Uptime:** 7 jours
- **Features:** Protocol mimicry (HTTP/TLS)
- **Use Case:** Navigation web standard

---

## 🧠 Catégorie 8: Behavioral

### human-browsing-pattern

- **OS:** Windows 11
- **Timing:** Fibonacci (humain naturel)
- **Delay:** 2.5s (pauses humaines)
- **Decoys:** 3 (peu de connexions simultanées)
- **Uptime:** 14 jours
- **Ports:** 443, 8080, 3000, 5173 (web + AJAX)
- **Use Case:** Mimétisme comportement humain contre ML

### timing-steganography

- **OS:** Linux
- **Timing:** Prime (covert channel)
- **Delay:** 3.0s
- **Decoys:** 0 (pas de bruit)
- **Features:** Fragmentation + padding 32B
- **Use Case:** Canal caché temporel (stéganographie)

### cdn-edge-server

- **OS:** Linux
- **Timing:** Exponential (burst CDN)
- **Delay:** 0.2s (très rapide)
- **Decoys:** 40
- **Uptime:** 500 jours (serveur CDN)
- **TTL:** 56 (~8 hops edge)
- **Ports:** 443, 8443, 2052-2096 (Cloudflare/Akamai)
- **Use Case:** Mimétisme CDN edge nodes

### bitcoin-node-sync

- **OS:** Linux
- **Timing:** Random (block propagation)
- **Delay:** 1.8s
- **Decoys:** 20 (peer connections)
- **Uptime:** 400 jours
- **Ports:** 8333, 8332, 18333, 18332 (Bitcoin)
- **Window:** 65535 (full)
- **Use Case:** Blockchain node traffic

---

## 🔬 Catégorie 9: Anti-Forensic

### forensic-confusion

- **OS:** Windows 10
- **Timing:** Random
- **Delay:** 4.0s
- **Decoys:** 30
- **Features:** Fragmentation + padding 77B (nombre premier)
- **Use Case:** Confusion analyse forensique

### protocol-polymorphism

- **OS:** Android
- **Timing:** Random
- **Delay:** 2.5s
- **Decoys:** 35
- **Features:** Protocol mimicry variable + fragmentation + padding 64B
- **Use Case:** Polymorphisme anti-signature

---

## 🏭 Catégorie 10: Contextual

### container-orchestration

- **OS:** Linux
- **Timing:** Exponential (microservices)
- **Delay:** 0.6s
- **Decoys:** 15 (multi-pod)
- **Uptime:** 2 jours (containers courts)
- **Ports:** 443, 6443, 8080, 2375/2376 (Docker), 10250-10252 (K8s)
- **Use Case:** Docker/Kubernetes traffic

### industrial-iot

- **OS:** Linux
- **Timing:** Sine (polling SCADA périodique)
- **Delay:** 5.0s
- **Decoys:** 2 (peu de devices ICS)
- **Uptime:** 1000 jours (systèmes critiques)
- **TTL:** 32 (LAN industriel)
- **Ports:** 502 (Modbus), 4840 (OPC-UA), 44818, 102
- **Window:** 8192
- **Use Case:** ICS/SCADA industriel

### smart-home-device

- **OS:** Linux embedded
- **Timing:** Sine (heartbeat périodique)
- **Delay:** 3.0s
- **Decoys:** 0 (device unique)
- **Uptime:** 4 jours
- **TTL:** 1 (local)
- **Ports:** 1883/8883 (MQTT), 5683 (CoAP)
- **Window:** 1024 (petit buffer IoT)
- **Use Case:** Smart home (Zigbee, MQTT)

### tor-exit-node

- **OS:** Linux
- **Timing:** Random (multi-hop latency)
- **Delay:** 4.0s
- **Decoys:** 50 (exit traffic)
- **Uptime:** 200 jours
- **TTL:** 52 randomized (multi-hop)
- **Ports:** 9001, 9030, 443, 80
- **Use Case:** TOR exit node mimicry

---

## 🚀 Catégorie 11: Emerging

### satellite-internet

- **OS:** Linux
- **Timing:** Sine
- **Delay:** 8.0s (latence satellite)
- **Timeout:** 10s
- **Decoys:** 5
- **TTL:** 48 randomized (orbite)
- **Window:** 65535 (compenser latency)
- **Use Case:** Starlink/satellite internet

### ml-training-cluster

- **OS:** Linux
- **Timing:** Exponential (burst epochs)
- **Delay:** 0.1s (très rapide)
- **Decoys:** 8 (distributed training)
- **Uptime:** 90 jours (training job)
- **Ports:** 6006 (TensorBoard), 5000 (MLflow), 8080 (Wandb)
- **Window:** 65535
- **Use Case:** GPU clusters ML/AI

### webrtc-p2p

- **OS:** Windows 11
- **Timing:** Random (P2P)
- **Delay:** 0.4s
- **Decoys:** 6 (peers)
- **Uptime:** 1 jour (browser session)
- **Ports:** 3478, 19302 (STUN/TURN), 49152/49153
- **Use Case:** WebRTC peer-to-peer

### video-streaming

- **OS:** Android
- **Timing:** Exponential (buffer filling)
- **Delay:** 0.8s
- **Decoys:** 4
- **Uptime:** 10 jours
- **Ports:** 443, 8443 (HTTPS streaming)
- **Window:** 65535 (large buffer)
- **Use Case:** Netflix/YouTube/streaming

---

## 🔮 Catégorie 12: Exotic

### time-oracle-scan

- **OS:** Linux
- **Timing:** Random
- **Delay:** 60.0s (1 MINUTE entre paquets!)
- **Timeout:** 30s
- **Decoys:** 0 (silence total)
- **Use Case:** Ultra-furtif, éviter corrélation temporelle, time-based blind scan

### quantum-entropy

- **OS:** Linux
- **Timing:** Random (maximum entropy)
- **Delay:** 2.0s
- **Decoys:** 25
- **Features:** TTL + IPID randomization maximale (random mode)
- **IPID Mode:** random (0-65535 full range)
- **Use Case:** Entropie maximale, éviter corrélation IPID, future QRNG support

---

## 📋 Guide de Sélection Rapide

| Situation                 | Stratégie Recommandée                                   |
|---------------------------|---------------------------------------------------------|
| **Scan général furtif**   | `ai-evasion-windows10` ou `ai-evasion-linux`            |
| **Chine (GFW)**           | `chinese-great-firewall-evasion`                        |
| **Russie (DPI)**          | `russian-dpi-bypass`                                    |
| **Entreprise**            | `corporate-firewall-bypass`                             |
| **Cloud (AWS/GCP/Azure)** | `cloud-provider-scan`                                   |
| **Honeypot possible**     | `honeypot-aware-scan`                                   |
| **ML/AI avancé**          | `ml-classifier-confusion` ou `ultra-stealth-ai-evasion` |
| **Mobile**                | `mobile-5g-profile` ou `ios-device-profile`             |
| **Ressemble à humain**    | `human-browsing-pattern`                                |
| **CDN mimicry**           | `cdn-edge-server`                                       |
| **Bitcoin tolerated**     | `bitcoin-node-sync`                                     |
| **Docker/K8s**            | `container-orchestration`                               |
| **SCADA/ICS**             | `industrial-iot`                                        |
| **Ultra-furtif**          | `time-oracle-scan`                                      |
| **Maximum entropy**       | `quantum-entropy`                                       |

---

## 🛠️ Paramètres Clés

### Timing Patterns

- **fibonacci:** Balanced, naturel (1, 1, 2, 3, 5, 8, 13...)
- **sine:** Smooth wave, organique
- **prime:** Irregular (2, 3, 5, 7, 11, 13, 17...)
- **exponential:** Escalating (1.5^n)
- **random:** Chaotic, imprévisible

### IPID Modes

- **random:** Full range 0-65535 (maximum entropy, évite corrélation)
- **incremental:** Sequential 1000-10000 (mimics classic OS behavior)
- **zero:** IPID=0 (modern OS like recent Linux kernels)
- **odd:** Only odd numbers (BSD-style behavior)

### Decoys

- **0:** Canal caché, timing stego
- **3-8:** Comportement humain/simple
- **10-25:** Standard furtif
- **30-50:** Maximum (DPI/GFW)

### Delay

- **< 1s:** Temps-réel (gaming, streaming)
- **1-5s:** Standard
- **5-10s:** Lent (ICS, honeypot-aware)
- **60s:** Ultra-furtif (time-oracle)

### Uptime

- **1-7j:** Mobile, browser, containers
- **30-90j:** Workstations
- **365-1000j:** Serveurs, ICS

---

## 📖 Notes d'Utilisation

1. **Toutes les stratégies** supportent `advanced_evasion: true` pour activer:
    - TCP options réalistes par OS
    - Window size réaliste
    - TTL réaliste
    - SEQ number timestamp-based
    - Protocol mimicry (HTTP/TLS/DNS)
    - IPID manipulation (4 modes disponibles)

2. **Overlapping fragments** implémenté dans `AdvancedEvasion.create_overlapping_fragments()`

3. **Port randomization** via `src_ports` pour contourner firewall rules

4. **RST cleanup** (`send_rst: true`) ferme proprement connexions SYN-ACK

5. **Fragmentation** disponible pour toutes stratégies (`fragment: true`)

6. **IPID manipulation** (`ipid_mode: random|incremental|zero|odd`) évite corrélation temporelle et fingerprinting

---

## 🎓 Utilisation Éducative

Ce scanner est conçu pour la **recherche académique sur les firewalls IA**. Toutes les stratégies visent à:

- Comprendre détection comportementale ML/AI
- Tester robustesse des pare-feu modernes
- Étudier patterns de trafic légitimes
- Analyser corrélation temporelle

**Usage autorisé:** CTF, labs, pentesting avec autorisation, recherche sécurité.

---

**Total: 51 stratégies d'évasion couvrant tous les cas d'usage modernes.**

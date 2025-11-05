# Tests des Scanners Réseau

## 📋 Vue d'ensemble

Ce répertoire contient les tests unitaires pour tous les scanners réseau. Les tests utilisent des **fixtures intelligibles** qui simulent des comportements réseau réalistes (firewalls, ports ouverts/fermés/filtrés, timeouts).

## 🎯 Objectifs des tests

### 1. **Vérifier l'interprétation correcte des états de ports**
   - Port **ouvert** : Service répond correctement
   - Port **fermé** : Service refuse la connexion (RST)
   - Port **filtré** : Firewall bloque (aucune réponse, timeout)

### 2. **Valider le parsing des sorties**
   - Bannières de services (HTTP, SSH, etc.)
   - Flags TCP (SYN-ACK, RST, etc.)
   - Métadonnées (versions, OS, MAC)

### 3. **Tester les comportements mixtes**
   - Scan multi-ports avec états différents
   - Scénarios réalistes (firewall stealth, serveur web, etc.)

## 🔬 Fixtures Intelligibles

### Comportements Firewall (`conftest.py`)

```python
firewall_blocks_everything
```
→ Firewall strict : tout est bloqué (scénario haute sécurité)

```python
firewall_allows_web_server
```
→ Firewall classique : HTTP/HTTPS ouverts, SSH bloqué

```python
firewall_allows_ssh_only
```
→ Serveur de gestion : seul SSH accessible

```python
firewall_stealth_mode
```
→ IDS/IPS actif : aucune réponse (mode furtif)

```python
firewall_open_relay
```
→ Serveur mal configuré : tous les ports ouverts (compromis)

```python
network_unreachable
```
→ Réseau inaccessible : timeout sur tout (câble débranché)

### Réponses Mockées

```python
curl_response_open_port
```
→ Serveur HTTP répond avec bannière (200 OK)

```python
curl_response_connection_refused
```
→ Port fermé (errno 7 - connection refused)

```python
scapy_syn_ack_response
```
→ Paquet TCP avec flags SYN-ACK (port ouvert)

```python
scapy_rst_response
```
→ Paquet TCP avec flags RST (port fermé)

```python
scapy_no_response
```
→ Timeout (port filtré par firewall)

## 🚀 Lancer les tests

### Installation des dépendances

```bash
pip install pytest pytest-cov pytest-mock
```

### Exécuter tous les tests

```bash
pytest tests/
```

### Exécuter un scanner spécifique

```bash
pytest tests/test_curl_scanner.py -v
pytest tests/test_scapy_scanner.py -v
pytest tests/test_nmap_scanner.py -v
pytest tests/test_netcat_scanner.py -v
pytest tests/test_hping3_scanner.py -v
pytest tests/test_masscan_scanner.py -v
pytest tests/test_pcap2_scanner.py -v
```

### Avec couverture de code

```bash
pytest tests/ --cov=scanners --cov-report=html
```

### Mode verbeux (détails complets)

```bash
pytest tests/ -vv
```

### Exécuter un test spécifique

```bash
pytest tests/test_curl_scanner.py::TestCurlScannerPortInterpretation::test_port_ouvert_http_avec_banniere -v
```

## 📊 Scénarios de test par scanner

### CurlScanner (`test_curl_scanner.py`)

| Test | Scénario | Résultat attendu |
|------|----------|------------------|
| `test_port_ouvert_http_avec_banniere` | Serveur HTTP répond | Port 80 ouvert + bannière capturée |
| `test_port_ferme_connection_refused` | Port fermé | Port 80 absent de la liste |
| `test_port_filtre_timeout` | Firewall DROP | Port 443 absent (timeout) |
| `test_multi_ports_comportements_mixtes` | 80 ouvert, 8080 fermé, 443 filtré | Seul port 80 détecté |

### ScapyScanner (`test_scapy_scanner.py`)

| Test | Scénario | Flags TCP | Résultat attendu |
|------|----------|-----------|------------------|
| `test_syn_scan_port_ouvert_syn_ack` | Port ouvert | SYN-ACK (0x12) | status="open" |
| `test_syn_scan_port_ferme_rst_ack` | Port fermé | RST-ACK (0x14) | status="closed" |
| `test_syn_scan_port_filtre_no_response` | Firewall DROP | (aucune) | status="filtered" |
| `test_fin_scan_port_ouvert_no_response` | FIN scan ouvert | (aucune) | status="open\|filtered" |
| `test_fin_scan_port_ferme_rst` | FIN scan fermé | RST (0x14) | status="closed" |

### NmapScanner (`test_nmap_scanner.py`)

| Test | Scénario | Résultat attendu |
|------|----------|------------------|
| `test_parse_ports_ouverts` | Nmap détecte 22, 80 | Ports 22, 80 extraits |
| `test_parse_versions_services` | Nmap -sV | Versions dans `details["versions"]` |
| `test_parse_os_detection` | Nmap -O | OS dans `details["os"]` |
| `test_parse_mac_address` | Scan local | MAC dans `extra["mac_address"]` |

### NetcatScanner (`test_netcat_scanner.py`)

| Test | Scénario | Résultat attendu |
|------|----------|------------------|
| `test_port_ouvert_avec_banniere` | Port 22 SSH avec bannière | Port 22 ouvert + bannière SSH capturée |
| `test_port_ferme_connection_refused` | Port fermé | Port absent de la liste |
| `test_port_filtre_timeout` | Firewall DROP | Port absent (timeout) |
| `test_multi_ports_comportements_mixtes` | 22 ouvert, 80 fermé, 443 filtré | Seul port 22 détecté |

### Hping3Scanner (`test_hping3_scanner.py`)

| Test | Scénario | Flags TCP | Résultat attendu |
|------|----------|-----------|------------------|
| `test_syn_scan_port_ouvert_syn_ack` | Port ouvert | SA (SYN-ACK) | Port 80 détecté |
| `test_syn_scan_port_ferme_rst_ack` | Port fermé | RA (RST-ACK) | Port 80 absent |
| `test_syn_scan_port_filtre_no_response` | Firewall DROP | (aucune) | Port 443 absent |
| `test_multi_ports_comportements_mixtes` | 22 ouvert, 80 fermé, 443 filtré | Mixte | Seul port 22 détecté |
| `test_fin_scan_port_ouvert_no_response` | FIN scan ouvert | (aucune) | Comportement validé |

### MasscanScanner (`test_masscan_scanner.py`)

| Test | Scénario | Résultat attendu |
|------|----------|------------------|
| `test_parse_ports_ouverts` | Masscan détecte 22, 80, 443 | Ports 22, 80, 443 extraits |
| `test_parse_aucun_port_ouvert` | Firewall bloque tout | Liste de ports vide |
| `test_parse_format_alternatif` | Format output varié | Parsing robuste |
| `test_scan_avec_stop_flag` | Scan interrompu | success = False |
| `test_timeout_handling` | Process.wait() timeout | Processus tué proprement |

### Pcap2 (`test_pcap2_scanner.py`)

| Test | Scénario | Résultat attendu |
|------|----------|------------------|
| `test_load_and_replay_packets` | Replay de 3 paquets PCAP | send() appelé 3 fois |
| `test_modify_destination_ip` | IP destination modifiée | IP cible utilisée |
| `test_empty_pcap_file` | PCAP vide | success = False |
| `test_missing_pcap_file` | Fichier inexistant | Erreur fichier introuvable |
| `test_repeat_functionality` | repeat=3 (2 paquets) | 6 appels à send() (2×3) |
| `test_stop_flag_interruption` | Replay interrompu | success = False |

## 🧪 Écrire de nouveaux tests

### Template de test avec fixture claire

```python
def test_scenario_intelligible(
    ip_target,                    # IP fictive
    thread_id,                    # ID thread
    event_queue,                  # Queue événements
    stop_flag_never,              # Scan complet
    process_manager_mock,         # Mock process manager
    firewall_allows_web_server    # Comportement firewall
):
    """
    Scénario : Description claire du cas de test.

    Comportement attendu :
    - Assertion 1
    - Assertion 2
    """
    scanner = MyScanner(...)

    # Setup mocks selon fixture
    with patch(...):
        result = scanner.scan(...)

    # Assertions claires
    assert result["ports"] == [80, 443]
    assert "nginx" in result["banners"][80]
```

## 🛠️ Structure des fixtures

```
conftest.py
├── Fixtures générales
│   ├── ip_target : "192.168.1.100"
│   ├── thread_id : "test-thread-12345"
│   ├── event_queue : Queue()
│   └── stop_flag_never : lambda: False
│
├── Fixtures firewall (FirewallBehavior)
│   ├── firewall_blocks_everything
│   ├── firewall_allows_web_server
│   ├── firewall_allows_ssh_only
│   ├── firewall_stealth_mode
│   ├── firewall_open_relay
│   └── network_unreachable
│
├── Fixtures subprocess (CurlScanner, etc.)
│   ├── curl_response_open_port
│   ├── curl_response_connection_refused
│   └── curl_response_timeout
│
└── Fixtures Scapy (ScapyScanner, Pcap2)
    ├── scapy_syn_ack_response
    ├── scapy_rst_response
    └── scapy_no_response
```

## 📈 Couverture de code cible

- **CurlScanner** : 90%+
- **ScapyScanner** : 85%+
- **NmapScanner** : 80%+
- **NetcatScanner** : 85%+
- **Hping3Scanner** : 85%+
- **MasscanScanner** : 80%+
- **Pcap2** : 80%+
- **BaseSubprocessScanner** : 90%+

## 🐛 Debugging des tests

### Afficher les logs pendant les tests

```bash
pytest tests/ -v -s
```

### Stopper au premier échec

```bash
pytest tests/ -x
```

### Relancer uniquement les tests échoués

```bash
pytest tests/ --lf
```

### Mode debug interactif

```bash
pytest tests/ --pdb
```

## 📝 Conventions de nommage

- **Fixtures** : `firewall_<comportement>` ou `<scanner>_response_<état>`
- **Tests** : `test_<scenario_descriptif>`
- **Classes** : `Test<Scanner>Name<Aspect>`

Exemple : `TestScapyScannerTCPFlags::test_syn_scan_port_ouvert_syn_ack`

## ✅ Checklist avant commit

- [ ] Tous les tests passent (`pytest tests/`)
- [ ] Couverture > 80% (`pytest tests/ --cov`)
- [ ] Fixtures avec noms explicites
- [ ] Docstrings décrivant le scénario
- [ ] Assertions avec messages clairs

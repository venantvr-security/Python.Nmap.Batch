# Rapport d'analyse PCAP - Compatibilité Pcap2

**Répertoire analysé**: `pcap_templates/packets`
**Fichiers analysés**: 75

## 📊 Statistiques globales

- ✅ **Compatibles avec Pcap2**: 48/75
- ⭐ **Qualité excellente** (>80% TCP): 43
- 👍 **Bonne qualité** (>50% TCP): 3

## 🎯 Fichiers recommandés pour Pcap2

| Fichier                                   | Paquets TCP | % TCP  | Qualité   | Échantillon SYN    |
|-------------------------------------------|-------------|--------|-----------|--------------------|
| `aurora.pcapng`                           | 39          | 100.0% | excellent | TTL=128, Win=64240 |
| `cryptowall4_c2.pcapng`                   | 162         | 100.0% | excellent | TTL=128, Win=8192  |
| `dns_axfr.pcapng`                         | 11          | 100.0% | excellent | TTL=128, Win=64240 |
| `download-fast.pcapng`                    | 89942       | 100.0% | excellent | TTL=128, Win=8192  |
| `download-slow.pcapng`                    | 10728       | 100.0% | excellent | TTL=128, Win=8192  |
| `ek_to_cryptowall4.pcapng`                | 653         | 100.0% | excellent | TTL=128, Win=8192  |
| `http_dvwa_clearlogin.pcapng`             | 54          | 100.0% | excellent | TTL=64, Win=65535  |
| `http_dvwa_sqlinjection.pcapng`           | 35          | 100.0% | excellent | TTL=64, Win=65535  |
| `http_dvwa_sqlinjection_passwords.pcapng` | 12          | 100.0% | excellent | TTL=64, Win=65535  |
| `http_google.pcapng`                      | 12          | 100.0% | excellent | TTL=128, Win=8192  |

## 📋 Analyse détaillée

### ✅ `aurora.pcapng` ⭐⭐⭐

- **Total paquets**: 39
- **TCP**: 39 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `192.168.100.206:1031` → `192.168.100.202:80` | TTL=128, Window=64240
2. `192.168.100.206:1032` → `192.168.100.202:4321` | TTL=128, Window=64240

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `192.168.100.206:1031` → `192.168.100.202:80` flags=S
- `192.168.100.202:80` → `192.168.100.206:1031` flags=SA
- `192.168.100.206:1031` → `192.168.100.202:80` flags=A
- `192.168.100.206:1031` → `192.168.100.202:80` flags=PA
- `192.168.100.202:80` → `192.168.100.206:1031` flags=A

</details>

### ✅ `cryptowall4_c2.pcapng` ⭐⭐⭐

- **Total paquets**: 162
- **TCP**: 162 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `192.168.122.145:49357` → `184.170.149.44:80` | TTL=128, Window=8192
2. `192.168.122.145:49359` → `184.170.149.44:80` | TTL=128, Window=8192
3. `192.168.122.145:49361` → `184.170.149.44:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `192.168.122.145:49357` → `184.170.149.44:80` flags=S
- `184.170.149.44:80` → `192.168.122.145:49357` flags=SA
- `192.168.122.145:49357` → `184.170.149.44:80` flags=A
- `192.168.122.145:49357` → `184.170.149.44:80` flags=PA
- `192.168.122.145:49357` → `184.170.149.44:80` flags=PA

</details>

### ✅ `dns_axfr.pcapng` ⭐⭐⭐

- **Total paquets**: 11
- **TCP**: 11 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.164:1108` → `172.16.16.139:53` | TTL=128, Window=64240

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.164:1108` → `172.16.16.139:53` flags=S
- `172.16.16.139:53` → `172.16.16.164:1108` flags=SA
- `172.16.16.164:1108` → `172.16.16.139:53` flags=A
- `172.16.16.164:1108` → `172.16.16.139:53` flags=PA
- `172.16.16.139:53` → `172.16.16.164:1108` flags=A

</details>

### ✅ `download-fast.pcapng` ⭐⭐⭐

- **Total paquets**: 89942
- **TCP**: 89942 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:3218` → `72.4.123.180:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:3218` → `72.4.123.180:80` flags=S
- `72.4.123.180:80` → `172.16.16.128:3218` flags=SA
- `172.16.16.128:3218` → `72.4.123.180:80` flags=A
- `172.16.16.128:3218` → `72.4.123.180:80` flags=PA
- `72.4.123.180:80` → `172.16.16.128:3218` flags=A

</details>

### ✅ `download-slow.pcapng` ⭐⭐⭐

- **Total paquets**: 10728
- **TCP**: 10728 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:3202` → `193.136.195.36:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:3202` → `193.136.195.36:80` flags=S
- `193.136.195.36:80` → `172.16.16.128:3202` flags=SA
- `172.16.16.128:3202` → `193.136.195.36:80` flags=A
- `172.16.16.128:3202` → `193.136.195.36:80` flags=PA
- `193.136.195.36:80` → `172.16.16.128:3202` flags=A

</details>

### ✅ `ek_to_cryptowall4.pcapng` ⭐⭐⭐

- **Total paquets**: 653
- **TCP**: 653 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `192.168.122.145:49314` → `113.20.11.49:80` | TTL=128, Window=8192
2. `192.168.122.145:49328` → `45.32.238.202:80` | TTL=128, Window=8192
3. `192.168.122.145:49329` → `45.32.238.202:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `192.168.122.145:49314` → `113.20.11.49:80` flags=S
- `113.20.11.49:80` → `192.168.122.145:49314` flags=SA
- `192.168.122.145:49314` → `113.20.11.49:80` flags=A
- `192.168.122.145:49314` → `113.20.11.49:80` flags=PA
- `113.20.11.49:80` → `192.168.122.145:49314` flags=A

</details>

### ✅ `http_dvwa_clearlogin.pcapng` ⭐⭐⭐

- **Total paquets**: 54
- **TCP**: 54 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `10.2.2.101:58783` → `10.2.2.104:80` | TTL=64, Window=65535
2. `10.2.2.101:58785` → `10.2.2.104:80` | TTL=64, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `10.2.2.101:58783` → `10.2.2.104:80` flags=S
- `10.2.2.104:80` → `10.2.2.101:58783` flags=SA
- `10.2.2.101:58783` → `10.2.2.104:80` flags=A
- `10.2.2.101:58783` → `10.2.2.104:80` flags=PA
- `10.2.2.104:80` → `10.2.2.101:58783` flags=A

</details>

### ✅ `http_dvwa_directorytraversal.pcapng` ⭐⭐⭐

- **Total paquets**: 10
- **TCP**: 10 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `10.2.2.101:58806` → `10.2.2.104:80` | TTL=64, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `10.2.2.101:58806` → `10.2.2.104:80` flags=S
- `10.2.2.104:80` → `10.2.2.101:58806` flags=SA
- `10.2.2.101:58806` → `10.2.2.104:80` flags=A
- `10.2.2.101:58806` → `10.2.2.104:80` flags=PA
- `10.2.2.104:80` → `10.2.2.101:58806` flags=A

</details>

### ✅ `http_dvwa_sqlinjection.pcapng` ⭐⭐⭐

- **Total paquets**: 35
- **TCP**: 35 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `10.2.2.101:58856` → `10.2.2.104:80` | TTL=64, Window=65535
2. `10.2.2.101:58866` → `10.2.2.104:80` | TTL=64, Window=65535
3. `10.2.2.101:58868` → `10.2.2.104:80` | TTL=64, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `10.2.2.101:58856` → `10.2.2.104:80` flags=S
- `10.2.2.104:80` → `10.2.2.101:58856` flags=SA
- `10.2.2.101:58856` → `10.2.2.104:80` flags=A
- `10.2.2.101:58856` → `10.2.2.104:80` flags=PA
- `10.2.2.104:80` → `10.2.2.101:58856` flags=A

</details>

### ✅ `http_dvwa_sqlinjection_passwords.pcapng` ⭐⭐⭐

- **Total paquets**: 12
- **TCP**: 12 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `10.2.2.101:58904` → `10.2.2.104:80` | TTL=64, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `10.2.2.101:58904` → `10.2.2.104:80` flags=S
- `10.2.2.104:80` → `10.2.2.101:58904` flags=SA
- `10.2.2.101:58904` → `10.2.2.104:80` flags=A
- `10.2.2.101:58904` → `10.2.2.104:80` flags=PA
- `10.2.2.104:80` → `10.2.2.101:58904` flags=A

</details>

### ✅ `http_google.pcapng` ⭐⭐⭐

- **Total paquets**: 12
- **TCP**: 12 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:1606` → `74.125.95.104:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:1606` → `74.125.95.104:80` flags=S
- `74.125.95.104:80` → `172.16.16.128:1606` flags=SA
- `172.16.16.128:1606` → `74.125.95.104:80` flags=A
- `172.16.16.128:1606` → `74.125.95.104:80` flags=PA
- `74.125.95.104:80` → `172.16.16.128:1606` flags=A

</details>

### ✅ `http_post.pcapng` ⭐⭐⭐

- **Total paquets**: 21
- **TCP**: 21 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:1989` → `69.163.176.56:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:1989` → `69.163.176.56:80` flags=S
- `69.163.176.56:80` → `172.16.16.128:1989` flags=SA
- `172.16.16.128:1989` → `69.163.176.56:80` flags=A
- `172.16.16.128:1989` → `69.163.176.56:80` flags=PA
- `69.163.176.56:80` → `172.16.16.128:1989` flags=A

</details>

### ✅ `inconsistent_printer.pcapng` ⭐⭐⭐

- **Total paquets**: 122
- **TCP**: 122 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.0.8:3527` → `172.16.0.253:9100` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.0.8:3527` → `172.16.0.253:9100` flags=S
- `172.16.0.253:9100` → `172.16.0.8:3527` flags=SA
- `172.16.0.8:3527` → `172.16.0.253:9100` flags=A
- `172.16.0.8:3527` → `172.16.0.253:9100` flags=A
- `172.16.0.8:3527` → `172.16.0.253:9100` flags=A

</details>

### ✅ `latency1.pcapng` ⭐⭐⭐

- **Total paquets**: 6
- **TCP**: 6 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:1606` → `74.125.95.104:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:1606` → `74.125.95.104:80` flags=S
- `74.125.95.104:80` → `172.16.16.128:1606` flags=SA
- `172.16.16.128:1606` → `74.125.95.104:80` flags=A
- `172.16.16.128:1606` → `74.125.95.104:80` flags=PA
- `74.125.95.104:80` → `172.16.16.128:1606` flags=A

</details>

### ✅ `latency2.pcapng` ⭐⭐⭐

- **Total paquets**: 6
- **TCP**: 6 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:1606` → `74.125.95.104:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:1606` → `74.125.95.104:80` flags=S
- `74.125.95.104:80` → `172.16.16.128:1606` flags=SA
- `172.16.16.128:1606` → `74.125.95.104:80` flags=A
- `172.16.16.128:1606` → `74.125.95.104:80` flags=PA
- `74.125.95.104:80` → `172.16.16.128:1606` flags=A

</details>

### ✅ `latency3.pcapng` ⭐⭐⭐

- **Total paquets**: 6
- **TCP**: 6 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:1606` → `74.125.95.104:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:1606` → `74.125.95.104:80` flags=S
- `74.125.95.104:80` → `172.16.16.128:1606` flags=SA
- `172.16.16.128:1606` → `74.125.95.104:80` flags=A
- `172.16.16.128:1606` → `74.125.95.104:80` flags=PA
- `74.125.95.104:80` → `172.16.16.128:1606` flags=A

</details>

### ✅ `latency4.pcapng` ⭐⭐⭐

- **Total paquets**: 6
- **TCP**: 6 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:1606` → `74.125.95.104:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:1606` → `74.125.95.104:80` flags=S
- `74.125.95.104:80` → `172.16.16.128:1606` flags=SA
- `172.16.16.128:1606` → `74.125.95.104:80` flags=A
- `172.16.16.128:1606` → `74.125.95.104:80` flags=PA
- `74.125.95.104:80` → `172.16.16.128:1606` flags=A

</details>

### ✅ `mail_receiver_server_3.pcapng` ⭐⭐⭐

- **Total paquets**: 54
- **TCP**: 54 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.221:56694` → `172.16.16.231:25` | TTL=64, Window=29200
2. `172.16.16.235:51147` → `172.16.16.231:143` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.221:56694` → `172.16.16.231:25` flags=S
- `172.16.16.231:25` → `172.16.16.221:56694` flags=SA
- `172.16.16.221:56694` → `172.16.16.231:25` flags=A
- `172.16.16.231:25` → `172.16.16.221:56694` flags=PA
- `172.16.16.221:56694` → `172.16.16.231:25` flags=A

</details>

### ✅ `mail_sender_attachment.pcapng` ⭐⭐⭐

- **Total paquets**: 58
- **TCP**: 58 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.225:50593` → `172.16.16.221:25` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.225:50593` → `172.16.16.221:25` flags=S
- `172.16.16.221:25` → `172.16.16.225:50593` flags=SA
- `172.16.16.225:50593` → `172.16.16.221:25` flags=A
- `172.16.16.221:25` → `172.16.16.225:50593` flags=PA
- `172.16.16.225:50593` → `172.16.16.221:25` flags=PA

</details>

### ✅ `mail_sender_client_1.pcapng` ⭐⭐⭐

- **Total paquets**: 23
- **TCP**: 23 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.225:49313` → `172.16.16.221:25` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.225:49313` → `172.16.16.221:25` flags=S
- `172.16.16.221:25` → `172.16.16.225:49313` flags=SA
- `172.16.16.225:49313` → `172.16.16.221:25` flags=A
- `172.16.16.221:25` → `172.16.16.225:49313` flags=PA
- `172.16.16.225:49313` → `172.16.16.221:25` flags=PA

</details>

### ✅ `mail_sender_server_2.pcapng` ⭐⭐⭐

- **Total paquets**: 38
- **TCP**: 38 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.225:49313` → `172.16.16.221:25` | TTL=128, Window=8192
2. `172.16.16.221:56694` → `172.16.16.231:25` | TTL=64, Window=29200

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.225:49313` → `172.16.16.221:25` flags=S
- `172.16.16.221:25` → `172.16.16.225:49313` flags=SA
- `172.16.16.225:49313` → `172.16.16.221:25` flags=A
- `172.16.16.221:25` → `172.16.16.225:49313` flags=PA
- `172.16.16.225:49313` → `172.16.16.221:25` flags=PA

</details>

### ✅ `passiveosfingerprinting.pcapng` ⭐⭐⭐

- **Total paquets**: 2
- **TCP**: 2 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.134:1176` → `168.143.162.100:80` | TTL=128, Window=64240
2. `172.16.16.134:1176` → `168.143.162.100:80` | TTL=64, Window=2920

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.134:1176` → `168.143.162.100:80` flags=S
- `172.16.16.134:1176` → `168.143.162.100:80` flags=S

</details>

### ✅ `ratinfected.pcapng` ⭐⭐⭐

- **Total paquets**: 779
- **TCP**: 779 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.0.114:6641` → `172.16.0.111:4433` | TTL=128, Window=64240
2. `172.16.0.114:6642` → `172.16.0.111:4433` | TTL=128, Window=64240
3. `172.16.0.114:6643` → `172.16.0.111:4433` | TTL=128, Window=64240

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.0.114:6641` → `172.16.0.111:4433` flags=S
- `172.16.0.111:4433` → `172.16.0.114:6641` flags=SA
- `172.16.0.114:6641` → `172.16.0.111:4433` flags=A
- `172.16.0.111:4433` → `172.16.0.114:6641` flags=PA
- `172.16.0.114:6641` → `172.16.0.111:4433` flags=PA

</details>

### ✅ `synscan.pcapng` ⭐⭐⭐

- **Total paquets**: 2011
- **TCP**: 2011 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.0.8:36050` → `64.13.134.52:443` | TTL=54, Window=3072
2. `172.16.0.8:36050` → `64.13.134.52:143` | TTL=46, Window=3072
3. `172.16.0.8:36050` → `64.13.134.52:3306` | TTL=45, Window=2048

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.0.8:36050` → `64.13.134.52:443` flags=S
- `172.16.0.8:36050` → `64.13.134.52:143` flags=S
- `172.16.0.8:36050` → `64.13.134.52:3306` flags=S
- `172.16.0.8:36050` → `64.13.134.52:199` flags=S
- `172.16.0.8:36050` → `64.13.134.52:111` flags=S

</details>

### ✅ `tcp_dupack.pcapng` ⭐⭐⭐

- **Total paquets**: 9
- **TCP**: 9 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.31.136.85:38760` → `195.81.202.68:80` flags=A
- `195.81.202.68:80` → `172.31.136.85:38760` flags=A
- `172.31.136.85:38760` → `195.81.202.68:80` flags=A
- `195.81.202.68:80` → `172.31.136.85:38760` flags=A
- `172.31.136.85:38760` → `195.81.202.68:80` flags=A

</details>

### ✅ `tcp_handshake.pcapng` ⭐⭐⭐

- **Total paquets**: 3
- **TCP**: 3 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:2826` → `212.58.226.142:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:2826` → `212.58.226.142:80` flags=S
- `212.58.226.142:80` → `172.16.16.128:2826` flags=SA
- `172.16.16.128:2826` → `212.58.226.142:80` flags=A

</details>

### ✅ `tcp_ports.pcapng` ⭐⭐⭐

- **Total paquets**: 505
- **TCP**: 505 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:2826` → `212.58.226.142:80` | TTL=128, Window=8192
2. `172.16.16.128:2827` → `67.228.110.120:80` | TTL=128, Window=8192
3. `172.16.16.128:2828` → `67.228.110.120:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:2826` → `212.58.226.142:80` flags=S
- `212.58.226.142:80` → `172.16.16.128:2826` flags=SA
- `172.16.16.128:2826` → `212.58.226.142:80` flags=A
- `172.16.16.128:2826` → `212.58.226.142:80` flags=PA
- `212.58.226.142:80` → `172.16.16.128:2826` flags=A

</details>

### ✅ `tcp_refuseconnection.pcapng` ⭐⭐⭐

- **Total paquets**: 2
- **TCP**: 2 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `192.168.100.138:3372` → `192.168.100.1:80` | TTL=128, Window=8760

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `192.168.100.138:3372` → `192.168.100.1:80` flags=S
- `192.168.100.1:80` → `192.168.100.138:3372` flags=RA

</details>

### ✅ `tcp_retransmissions.pcapng` ⭐⭐⭐

- **Total paquets**: 6
- **TCP**: 6 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `10.3.30.1:1048` → `10.3.71.7:1043` flags=PA
- `10.3.30.1:1048` → `10.3.71.7:1043` flags=PA
- `10.3.30.1:1048` → `10.3.71.7:1043` flags=PA
- `10.3.30.1:1048` → `10.3.71.7:1043` flags=PA
- `10.3.30.1:1048` → `10.3.71.7:1043` flags=PA

</details>

### ✅ `tcp_teardown.pcapng` ⭐⭐⭐

- **Total paquets**: 4
- **TCP**: 4 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `67.228.110.120:80` → `172.16.16.128:3363` flags=FA
- `172.16.16.128:3363` → `67.228.110.120:80` flags=A
- `172.16.16.128:3363` → `67.228.110.120:80` flags=FA
- `67.228.110.120:80` → `172.16.16.128:3363` flags=A

</details>

### ✅ `tcp_zerowindowdead.pcapng` ⭐⭐⭐

- **Total paquets**: 8
- **TCP**: 8 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `195.81.202.68:80` → `172.31.136.85:38760` flags=PA
- `172.31.136.85:38760` → `195.81.202.68:80` flags=A
- `195.81.202.68:80` → `172.31.136.85:38760` flags=A
- `172.31.136.85:38760` → `195.81.202.68:80` flags=A
- `195.81.202.68:80` → `172.31.136.85:38760` flags=A

</details>

### ✅ `tcp_zerowindowrecovery.pcapng` ⭐⭐⭐

- **Total paquets**: 7
- **TCP**: 7 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `192.168.0.20:2235` → `192.168.0.30:1720` flags=A
- `192.168.0.20:2235` → `192.168.0.30:1720` flags=A
- `192.168.0.20:2235` → `192.168.0.30:1720` flags=A
- `192.168.0.20:2235` → `192.168.0.30:1720` flags=A
- `192.168.0.20:2235` → `192.168.0.30:1720` flags=A

</details>

### ✅ `tickedoffdeveloper.pcapng` ⭐⭐⭐

- **Total paquets**: 93
- **TCP**: 93 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:2555` → `172.16.16.121:21` | TTL=128, Window=8192
2. `172.16.16.128:2559` → `172.16.16.121:49166` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:2555` → `172.16.16.121:21` flags=S
- `172.16.16.121:21` → `172.16.16.128:2555` flags=SA
- `172.16.16.128:2555` → `172.16.16.121:21` flags=A
- `172.16.16.121:21` → `172.16.16.128:2555` flags=PA
- `172.16.16.128:2555` → `172.16.16.121:21` flags=PA

</details>

### ✅ `weather_broken.pcapng` ⭐⭐⭐

- **Total paquets**: 9
- **TCP**: 9 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.154:53904` → `38.102.136.125:80` | TTL=64, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.154:53904` → `38.102.136.125:80` flags=S
- `38.102.136.125:80` → `172.16.16.154:53904` flags=SA
- `172.16.16.154:53904` → `38.102.136.125:80` flags=A
- `172.16.16.154:53904` → `38.102.136.125:80` flags=PA
- `38.102.136.125:80` → `172.16.16.154:53904` flags=PA

</details>

### ✅ `weather_working.pcapng` ⭐⭐⭐

- **Total paquets**: 7
- **TCP**: 7 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.123:24267` → `38.102.136.125:80` | TTL=255, Window=5840

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.123:24267` → `38.102.136.125:80` flags=S
- `38.102.136.125:80` → `172.16.16.123:24267` flags=SA
- `172.16.16.123:24267` → `38.102.136.125:80` flags=A
- `172.16.16.123:24267` → `38.102.136.125:80` flags=PA
- `38.102.136.125:80` → `172.16.16.123:24267` flags=FA

</details>

### ✅ `wrongdissector.pcapng` ⭐⭐⭐

- **Total paquets**: 52
- **TCP**: 52 (100.0%)
- **UDP**: 0
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `192.168.0.82:1492` → `192.168.0.53:443` | TTL=128, Window=8192
2. `192.168.0.82:1493` → `192.168.0.53:1101` | TTL=128, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `192.168.0.82:1492` → `192.168.0.53:443` flags=S
- `192.168.0.53:443` → `192.168.0.82:1492` flags=SA
- `192.168.0.82:1492` → `192.168.0.53:443` flags=A
- `192.168.0.53:443` → `192.168.0.82:1492` flags=PA
- `192.168.0.53:443` → `192.168.0.82:1492` flags=PA

</details>

### ✅ `sessionhijacking.pcapng` ⭐⭐⭐

- **Total paquets**: 134
- **TCP**: 133 (99.3%)
- **UDP**: 0
- **Autres**: 1
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.164:60432` → `172.16.16.181:80` | TTL=64, Window=65535
2. `172.16.16.164:60433` → `172.16.16.181:80` | TTL=64, Window=65535
3. `172.16.16.164:60434` → `172.16.16.181:80` | TTL=64, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.164:60428` → `172.16.16.181:80` flags=FA
- `172.16.16.181:80` → `172.16.16.164:60428` flags=A
- `172.16.16.164:60432` → `172.16.16.181:80` flags=S
- `172.16.16.181:80` → `172.16.16.164:60432` flags=SA
- `172.16.16.164:60433` → `172.16.16.181:80` flags=S

</details>

### ✅ `lotsofweb.pcapng` ⭐⭐⭐

- **Total paquets**: 12899
- **TCP**: 12645 (98.0%)
- **UDP**: 214
- **Autres**: 40
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:2918` → `157.166.226.25:80` | TTL=128, Window=8192
2. `172.16.16.128:2919` → `204.160.104.126:80` | TTL=128, Window=8192
3. `172.16.16.128:2920` → `204.160.104.126:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:2905` → `205.203.140.65:80` flags=A
- `172.16.16.128:2905` → `205.203.140.65:80` flags=A
- `172.16.16.128:2905` → `205.203.140.65:80` flags=PA
- `205.203.140.65:80` → `172.16.16.128:2905` flags=A
- `205.203.140.65:80` → `172.16.16.128:2905` flags=A

</details>

### ✅ `http_espn_fail.pcapng` ⭐⭐⭐

- **Total paquets**: 569
- **TCP**: 555 (97.5%)
- **UDP**: 14
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.154:64859` → `68.71.212.158:80` | TTL=64, Window=65535
2. `172.16.16.154:64861` → `199.181.133.61:80` | TTL=64, Window=65535
3. `172.16.16.154:64862` → `203.0.113.94:80` | TTL=64, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.154:64859` → `68.71.212.158:80` flags=S
- `68.71.212.158:80` → `172.16.16.154:64859` flags=SA
- `172.16.16.154:64859` → `68.71.212.158:80` flags=A
- `172.16.16.154:64859` → `68.71.212.158:80` flags=PA
- `68.71.212.158:80` → `172.16.16.154:64859` flags=A

</details>

### ✅ `http_espn.pcapng` ⭐⭐⭐

- **Total paquets**: 956
- **TCP**: 928 (97.1%)
- **UDP**: 28
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.0.122:52166` → `199.181.132.250:80` | TTL=64, Window=5840
2. `172.16.0.122:44955` → `68.71.208.11:80` | TTL=64, Window=5840
3. `172.16.0.122:41834` → `205.234.218.129:80` | TTL=64, Window=5840

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.0.122:52166` → `199.181.132.250:80` flags=S
- `199.181.132.250:80` → `172.16.0.122:52166` flags=SA
- `172.16.0.122:52166` → `199.181.132.250:80` flags=A
- `172.16.0.122:52166` → `199.181.132.250:80` flags=PA
- `199.181.132.250:80` → `172.16.0.122:52166` flags=PA

</details>

### ✅ `dns_isp_hijack.pcapng` ⭐⭐⭐

- **Total paquets**: 123
- **TCP**: 119 (96.7%)
- **UDP**: 4
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.170:64255` → `104.239.213.7:80` | TTL=64, Window=65535
2. `172.16.16.170:64256` → `104.239.213.7:80` | TTL=64, Window=65535
3. `172.16.16.170:64257` → `38.29.168.232:80` | TTL=64, Window=65535

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.170:64255` → `104.239.213.7:80` flags=S
- `172.16.16.170:64256` → `104.239.213.7:80` flags=S
- `104.239.213.7:80` → `172.16.16.170:64256` flags=SA
- `172.16.16.170:64256` → `104.239.213.7:80` flags=A
- `104.239.213.7:80` → `172.16.16.170:64255` flags=SA

</details>

### ✅ `dns_tcp.pcapng` ⭐⭐⭐

- **Total paquets**: 14
- **TCP**: 12 (85.7%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `192.168.11.62:45818` → `192.168.11.1:53` | TTL=64, Window=5840

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `192.168.11.62:45818` → `192.168.11.1:53` flags=S
- `192.168.11.1:53` → `192.168.11.62:45818` flags=SA
- `192.168.11.62:45818` → `192.168.11.1:53` flags=A
- `192.168.11.62:45818` → `192.168.11.1:53` flags=PA
- `192.168.11.1:53` → `192.168.11.62:45818` flags=A

</details>

### ✅ `activeosfingerprinting.pcapng` ⭐⭐⭐

- **Total paquets**: 48
- **TCP**: 40 (83.3%)
- **UDP**: 4
- **Autres**: 4
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.128:53936` → `172.16.16.150:135` | TTL=44, Window=1
2. `172.16.16.128:53937` → `172.16.16.150:135` | TTL=47, Window=63
3. `172.16.16.128:53938` → `172.16.16.150:135` | TTL=39, Window=4

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.128:53936` → `172.16.16.150:135` flags=S
- `172.16.16.150:135` → `172.16.16.128:53936` flags=SA
- `172.16.16.128:53937` → `172.16.16.150:135` flags=S
- `172.16.16.150:135` → `172.16.16.128:53937` flags=SA
- `172.16.16.128:53938` → `172.16.16.150:135` flags=S

</details>

### ✅ `nowebaccess2.pcapng` ⭐⭐

- **Total paquets**: 8
- **TCP**: 6 (75.0%)
- **UDP**: 0
- **Autres**: 2
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.0.8:1074` → `172.16.0.102:80` | TTL=128, Window=8192
2. `172.16.0.8:1074` → `172.16.0.102:80` | TTL=128, Window=8192
3. `172.16.0.8:1074` → `172.16.0.102:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.0.8:1074` → `172.16.0.102:80` flags=S
- `172.16.0.102:80` → `172.16.0.8:1074` flags=RA
- `172.16.0.8:1074` → `172.16.0.102:80` flags=S
- `172.16.0.102:80` → `172.16.0.8:1074` flags=RA
- `172.16.0.8:1074` → `172.16.0.102:80` flags=S

</details>

### ✅ `arppoison.pcapng` ⭐⭐

- **Total paquets**: 165
- **TCP**: 107 (64.8%)
- **UDP**: 54
- **Autres**: 4
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.0.107:45691` → `74.125.95.147:80` | TTL=64, Window=5840
2. `172.16.0.107:45692` → `74.125.95.147:80` | TTL=64, Window=5840

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.0.107:45691` → `74.125.95.147:80` flags=S
- `74.125.95.147:80` → `172.16.0.107:45691` flags=SA
- `172.16.0.107:45691` → `74.125.95.147:80` flags=A
- `172.16.0.107:45691` → `74.125.95.147:80` flags=PA
- `74.125.95.147:80` → `172.16.0.107:45691` flags=A

</details>

### ✅ `nowebaccess3.pcapng` ⭐⭐

- **Total paquets**: 5
- **TCP**: 3 (60.0%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.0.8:1251` → `74.125.95.105:80` | TTL=128, Window=8192
2. `172.16.0.8:1251` → `74.125.95.105:80` | TTL=128, Window=8192
3. `172.16.0.8:1251` → `74.125.95.105:80` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.0.8:1251` → `74.125.95.105:80` flags=S
- `172.16.0.8:1251` → `74.125.95.105:80` flags=S
- `172.16.0.8:1251` → `74.125.95.105:80` flags=S

</details>

### ✅ `http_ip4and6.pcapng` ⭐

- **Total paquets**: 20
- **TCP**: 10 (50.0%)
- **UDP**: 0
- **Autres**: 10
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.140:53350` → `172.16.16.139:80` | TTL=64, Window=29200

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.140:53350` → `172.16.16.139:80` flags=S
- `172.16.16.139:80` → `172.16.16.140:53350` flags=SA
- `172.16.16.140:53350` → `172.16.16.139:80` flags=A
- `172.16.16.140:53350` → `172.16.16.139:80` flags=PA
- `172.16.16.139:80` → `172.16.16.140:53350` flags=A

</details>

### ✅ `stranded_branchdns.pcapng` ⭐

- **Total paquets**: 3
- **TCP**: 1 (33.3%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Oui

**Échantillons SYN** (pour scan patterns):

1. `172.16.16.251:49160` → `172.16.16.250:53` | TTL=128, Window=8192

<details>
<summary>Échantillons TCP (cliquer pour développer)</summary>

- `172.16.16.251:49160` → `172.16.16.250:53` flags=S

</details>

### ❌ `3e80211_wepauth.pcapng` ❌

- **Total paquets**: 8
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 8
- **Compatible Pcap2**: Non

### ❌ `3e80211_wepauthfail.pcapng` ❌

- **Total paquets**: 5
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 5
- **Compatible Pcap2**: Non

### ❌ `3e80211_wpaauth.pcapng` ❌

- **Total paquets**: 12
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 12
- **Compatible Pcap2**: Non

### ❌ `3e80211_wpaauthfail.pcapng` ❌

- **Total paquets**: 16
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 16
- **Compatible Pcap2**: Non

### ❌ `80211beacon.pcapng` ❌

- **Total paquets**: 1
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 1
- **Compatible Pcap2**: Non

### ❌ `arp_gratuitous.pcapng` ❌

- **Total paquets**: 1
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 1
- **Compatible Pcap2**: Non

### ❌ `arp_resolution.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 2
- **Compatible Pcap2**: Non

### ❌ `dhcp6_outlease_acquisition.pcapng` ❌

- **Total paquets**: 4
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 4
- **Compatible Pcap2**: Non

### ❌ `dhcp_inlease_renewal.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `dhcp_nolease_initialization.pcapng` ❌

- **Total paquets**: 4
- **TCP**: 0 (0.0%)
- **UDP**: 4
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `dns.pcap` ❌

- **Total paquets**: 7
- **TCP**: 0 (0.0%)
- **UDP**: 7
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `dns_lab.pcapng` ❌

- **Total paquets**: 22
- **TCP**: 0 (0.0%)
- **UDP**: 22
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `dns_query_nonexistent.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `dns_query_response.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `dns_recursivequery_client.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `dns_recursivequery_server.pcapng` ❌

- **Total paquets**: 4
- **TCP**: 0 (0.0%)
- **UDP**: 4
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `dns_reverse_lookup.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `icmp_echo.pcapng` ❌

- **Total paquets**: 8
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 8
- **Compatible Pcap2**: Non

### ❌ `icmp_traceroute.pcapng` ❌

- **Total paquets**: 54
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 54
- **Compatible Pcap2**: Non

### ❌ `icmpv6_neighbor_solicitation.pcapng` ❌

- **Total paquets**: 7
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 7
- **Compatible Pcap2**: Non

### ❌ `ip_frag_source.pcapng` ❌

- **Total paquets**: 6
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 6
- **Compatible Pcap2**: Non

### ❌ `ip_ttl_dest.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 2
- **Compatible Pcap2**: Non

### ❌ `ip_ttl_source.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 2
- **Compatible Pcap2**: Non

### ❌ `ipv6_fragments.pcapng` ❌

- **Total paquets**: 22
- **TCP**: 0 (0.0%)
- **UDP**: 0
- **Autres**: 22
- **Compatible Pcap2**: Non

### ❌ `nowebaccess1.pcapng` ❌

- **Total paquets**: 9
- **TCP**: 0 (0.0%)
- **UDP**: 7
- **Autres**: 2
- **Compatible Pcap2**: Non

### ❌ `stranded_clientside.pcapng` ❌

- **Total paquets**: 2
- **TCP**: 0 (0.0%)
- **UDP**: 2
- **Autres**: 0
- **Compatible Pcap2**: Non

### ❌ `udp_dnsrequest.pcapng` ❌

- **Total paquets**: 1
- **TCP**: 0 (0.0%)
- **UDP**: 1
- **Autres**: 0
- **Compatible Pcap2**: Non

## 💡 Recommandations

### Pour utiliser avec Pcap2:

1. Choisir des fichiers avec >80% TCP (qualité excellente)
2. Vérifier présence de paquets SYN (flags=S)
3. Privilégier trafic HTTP/HTTPS (ports 80/443)
4. Éviter PCAP WiFi (802.11) ou purement UDP

### Ajout à `pcap2-strategies.yaml`:

```yaml
  aurorang:
    scan_type: syn
    ports: "<ports>"
    delay: 0.5
    timeout: 2
    ttl: 64
    send_rst: true
    template_pcap: "packets/aurora.pcapng"
```

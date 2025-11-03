#!/usr/bin/env python3
"""
Analyseur de fichiers PCAP/PCAPNG pour compatibilité avec Pcap2.
Génère un rapport détaillé des paquets TCP/IP disponibles.
"""

import os
import sys
from typing import Dict

from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import rdpcap

PCAP_DIR = "pcap_templates/packets"


def analyze_pcap(filepath: str) -> Dict:
    """Analyse un fichier PCAP et retourne les statistiques."""
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {
            "error": str(e),
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "other": 0,
            "compatible": False
        }

    total = len(packets)
    tcp_count = 0
    udp_count = 0
    other_count = 0
    syn_packets = []
    tcp_samples = []

    for pkt in packets:
        if pkt.haslayer(IP):
            if pkt.haslayer(TCP):
                tcp_count += 1
                tcp_layer = pkt[TCP]
                ip_layer = pkt[IP]

                # Collecter échantillons SYN
                if tcp_layer.flags == 'S' and len(syn_packets) < 3:
                    syn_packets.append({
                        "src": f"{ip_layer.src}:{tcp_layer.sport}",
                        "dst": f"{ip_layer.dst}:{tcp_layer.dport}",
                        "ttl": ip_layer.ttl,
                        "window": tcp_layer.window,
                        "flags": str(tcp_layer.flags)
                    })

                # Collecter échantillons TCP variés
                if len(tcp_samples) < 5:
                    tcp_samples.append({
                        "src": f"{ip_layer.src}:{tcp_layer.sport}",
                        "dst": f"{ip_layer.dst}:{tcp_layer.dport}",
                        "flags": str(tcp_layer.flags)
                    })

            elif pkt.haslayer(UDP):
                udp_count += 1
            else:
                other_count += 1
        else:
            other_count += 1

    # Déterminer compatibilité
    compatible = tcp_count > 0
    tcp_percentage = (tcp_count / total * 100) if total > 0 else 0

    return {
        "total": total,
        "tcp": tcp_count,
        "udp": udp_count,
        "other": other_count,
        "tcp_percentage": tcp_percentage,
        "compatible": compatible,
        "syn_packets": syn_packets,
        "tcp_samples": tcp_samples,
        "quality": "excellent" if tcp_percentage > 80 else "good" if tcp_percentage > 50 else "poor" if tcp_count > 0 else "incompatible"
    }


def generate_report(results: Dict[str, Dict]) -> str:
    """Génère un rapport markdown."""

    # Statistiques globales
    compatible_count = sum(1 for r in results.values() if r.get("compatible", False))
    excellent_count = sum(1 for r in results.values() if r.get("quality") == "excellent")
    good_count = sum(1 for r in results.values() if r.get("quality") == "good")

    report = ["# Rapport d'analyse PCAP - Compatibilité Pcap2", "", f"**Répertoire analysé**: `{PCAP_DIR}`", f"**Fichiers analysés**: {len(results)}", "",
              "## 📊 Statistiques globales", "", f"- ✅ **Compatibles avec Pcap2**: {compatible_count}/{len(results)}",
              f"- ⭐ **Qualité excellente** (>80% TCP): {excellent_count}", f"- 👍 **Bonne qualité** (>50% TCP): {good_count}", "", "## 🎯 Fichiers recommandés pour Pcap2",
              ""]

    # Fichiers recommandés
    recommended = [(name, data) for name, data in results.items()
                   if data.get("quality") in ["excellent", "good"] and data.get("tcp", 0) > 10]
    recommended.sort(key=lambda x: x[1].get("tcp_percentage", 0), reverse=True)

    if recommended:
        report.append("| Fichier | Paquets TCP | % TCP | Qualité | Échantillon SYN |")
        report.append("|---------|-------------|-------|---------|-----------------|")
        for name, data in recommended[:10]:
            syn_info = "N/A"
            if data.get("syn_packets"):
                syn = data["syn_packets"][0]
                syn_info = f"TTL={syn['ttl']}, Win={syn['window']}"
            report.append(f"| `{name}` | {data['tcp']} | {data['tcp_percentage']:.1f}% | {data['quality']} | {syn_info} |")
    else:
        report.append("*Aucun fichier recommandé trouvé.*")
    report.append("")

    # Détails par fichier
    report.append("## 📋 Analyse détaillée")
    report.append("")

    sorted_results = sorted(results.items(), key=lambda x: x[1].get("tcp_percentage", 0), reverse=True)

    for filename, data in sorted_results:
        if "error" in data:
            report.append(f"### ❌ `{filename}`")
            report.append(f"**Erreur**: {data['error']}")
            report.append("")
            continue

        icon = "✅" if data["compatible"] else "❌"
        quality_icon = {"excellent": "⭐⭐⭐", "good": "⭐⭐", "poor": "⭐", "incompatible": "❌"}
        report.append(f"### {icon} `{filename}` {quality_icon.get(data['quality'], '')}")
        report.append("")
        report.append(f"- **Total paquets**: {data['total']}")
        report.append(f"- **TCP**: {data['tcp']} ({data['tcp_percentage']:.1f}%)")
        report.append(f"- **UDP**: {data['udp']}")
        report.append(f"- **Autres**: {data['other']}")
        report.append(f"- **Compatible Pcap2**: {'Oui' if data['compatible'] else 'Non'}")
        report.append("")

        if data.get("syn_packets"):
            report.append("**Échantillons SYN** (pour scan patterns):")
            for i, syn in enumerate(data["syn_packets"], 1):
                report.append(f"{i}. `{syn['src']}` → `{syn['dst']}` | TTL={syn['ttl']}, Window={syn['window']}")
            report.append("")

        if data.get("tcp_samples") and len(data["tcp_samples"]) > 0:
            report.append("<details>")
            report.append("<summary>Échantillons TCP (cliquer pour développer)</summary>")
            report.append("")
            for sample in data["tcp_samples"][:5]:
                report.append(f"- `{sample['src']}` → `{sample['dst']}` flags={sample['flags']}")
            report.append("")
            report.append("</details>")
            report.append("")

    # Recommandations
    report.append("## 💡 Recommandations")
    report.append("")
    report.append("### Pour utiliser avec Pcap2:")
    report.append("1. Choisir des fichiers avec >80% TCP (qualité excellente)")
    report.append("2. Vérifier présence de paquets SYN (flags=S)")
    report.append("3. Privilégier trafic HTTP/HTTPS (ports 80/443)")
    report.append("4. Éviter PCAP WiFi (802.11) ou purement UDP")
    report.append("")
    report.append("### Ajout à `pcap2-strategies.yaml`:")
    report.append("```yaml")
    if recommended:
        best = recommended[0]
        clean_name = best[0].replace('.pcap', '').replace('.pcapng', '').replace('-', '_').replace('.', '_')
        report.append(f"  {clean_name}:")
        report.append(f"    scan_type: syn")
        report.append(f"    ports: \"<ports>\"")
        report.append(f"    delay: 0.5")
        report.append(f"    timeout: 2")
        report.append(f"    ttl: 64")
        report.append(f"    send_rst: true")
        report.append(f"    template_pcap: \"packets/{best[0]}\"")
    report.append("```")
    report.append("")

    return "\n".join(report)


def main():
    if not os.path.exists(PCAP_DIR):
        print(f"❌ Répertoire {PCAP_DIR} introuvable")
        sys.exit(1)

    files = [f for f in os.listdir(PCAP_DIR) if f.endswith(('.pcap', '.pcapng'))]

    if not files:
        print(f"❌ Aucun fichier PCAP trouvé dans {PCAP_DIR}")
        sys.exit(1)

    print(f"🔍 Analyse de {len(files)} fichiers PCAP...")
    print()

    results = {}
    for i, filename in enumerate(sorted(files), 1):
        filepath = os.path.join(PCAP_DIR, filename)
        print(f"[{i}/{len(files)}] {filename}...", end=" ")
        data = analyze_pcap(filepath)
        results[filename] = data

        if "error" in data:
            print(f"❌ Erreur")
        elif data["compatible"]:
            print(f"✅ {data['tcp']} TCP ({data['tcp_percentage']:.1f}%)")
        else:
            print(f"❌ Incompatible (0 TCP)")

    print()
    print("📝 Génération du rapport...")
    report = generate_report(results)

    output_file = "docs/PCAP-ANALYSIS-REPORT.md"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"✅ Rapport généré: {output_file}")
    print()
    print("=" * 60)
    print(report[:500] + "...")


if __name__ == "__main__":
    main()

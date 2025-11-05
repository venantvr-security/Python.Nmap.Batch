#!/usr/bin/env python3
"""
Démonstration du scanner adaptatif avec intelligence adversariale.

Ce script montre comment le scanner s'adapte en temps réel aux défenses
détectées, inspiré de l'architecture GAN.

Usage:
    python3 examples/adaptive_scan_demo.py --target 192.168.1.100 --ports 1-1000
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.AdaptiveCompositeScanner import (
    ScanIntelligence,
    DefenseLevel
)
from scanners.FingerprintDatabase import FingerprintDatabase


class ColoredOutput:
    """Helper pour sortie colorée dans le terminal."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def print_header(text: str):
        print(f"\n{ColoredOutput.HEADER}{ColoredOutput.BOLD}{'=' * 70}{ColoredOutput.ENDC}")
        print(f"{ColoredOutput.HEADER}{ColoredOutput.BOLD}{text:^70}{ColoredOutput.ENDC}")
        print(f"{ColoredOutput.HEADER}{ColoredOutput.BOLD}{'=' * 70}{ColoredOutput.ENDC}\n")

    @staticmethod
    def print_phase(phase_num: int, title: str):
        print(f"\n{ColoredOutput.OKCYAN}{ColoredOutput.BOLD}[Phase {phase_num}] {title}{ColoredOutput.ENDC}")
        print(f"{ColoredOutput.OKCYAN}{'─' * 70}{ColoredOutput.ENDC}")

    @staticmethod
    def print_success(text: str):
        print(f"{ColoredOutput.OKGREEN}✓ {text}{ColoredOutput.ENDC}")

    @staticmethod
    def print_warning(text: str):
        print(f"{ColoredOutput.WARNING}⚠ {text}{ColoredOutput.ENDC}")

    @staticmethod
    def print_info(text: str):
        print(f"{ColoredOutput.OKBLUE}ℹ {text}{ColoredOutput.ENDC}")

    @staticmethod
    def print_attack(text: str):
        print(f"{ColoredOutput.FAIL}⚔ {text}{ColoredOutput.ENDC}")


class AdaptiveScanDemo:
    """Démo visuelle du scanner adaptatif."""

    def __init__(self):
        self.output = ColoredOutput()
        self.fingerprint_db = FingerprintDatabase()

    def run_demo(self, target: str, ports: str):
        """Execute la démo complète avec visualisation."""
        self.output.print_header("ADAPTIVE COMPOSITE SCANNER - GAN-Inspired Intelligence")

        print(f"Target: {ColoredOutput.BOLD}{target}{ColoredOutput.ENDC}")
        print(f"Ports: {ColoredOutput.BOLD}{ports}{ColoredOutput.ENDC}")
        print(f"Mode: {ColoredOutput.BOLD}Adversarial Adaptive{ColoredOutput.ENDC}")

        # Simulation des 4 phases
        intelligence = ScanIntelligence()

        # Phase 1
        self._demo_phase1(target, intelligence)
        time.sleep(1)

        # Phase 2
        self._demo_phase2(target, intelligence)
        time.sleep(1)

        # Phase 3
        self._demo_phase3(target, intelligence)
        time.sleep(1)

        # Phase 4
        self._demo_phase4(target, intelligence)

        # Résumé final
        self._demo_summary(intelligence)

    def _demo_phase1(self, target: str, intelligence: ScanIntelligence):
        """Démo Phase 1 : Reconnaissance passive."""
        self.output.print_phase(1, "RECONNAISSANCE PASSIVE (Non-Intrusive)")

        self.output.print_info("Collecting public information...")
        time.sleep(0.5)

        # Simulation DNS lookup
        print(f"  DNS Lookup: {target} → ptr.example.com")
        self.output.print_success("DNS records retrieved")

        time.sleep(0.3)

        # Simulation banner grab
        self.output.print_info("HTTP banner grabbing (User-Agent: Mozilla/5.0)...")
        time.sleep(0.5)
        print("  Server: nginx/1.18.0 (Ubuntu)")
        print("  X-Powered-By: PHP/8.1.2")
        self.output.print_success("Banners captured without triggering alerts")

        # Mise à jour intelligence
        intelligence.detected_services[80] = "nginx/1.18.0"
        intelligence.detected_services[443] = "nginx/1.18.0 (SSL)"
        intelligence.ttl_values.extend([64, 64, 64])

        time.sleep(0.3)

        # OS preliminary guess
        preliminary_os = self.fingerprint_db.identify_os(64, 29200, ["mss", "sackOK", "timestamp"])
        self.output.print_info(f"Preliminary OS detection: {preliminary_os[0]} (confidence: {preliminary_os[1]:.2f})")

    def _demo_phase2(self, target: str, intelligence: ScanIntelligence):
        """Démo Phase 2 : Adversarial probing."""
        self.output.print_phase(2, "ADVERSARIAL PROBING (Defense Detection)")

        self.output.print_info("Testing defenses with adversarial techniques...")

        # Test 1 : SYN probing
        print("\n  [Test 1/4] SYN probing with varying TTL...")
        time.sleep(0.3)
        for ttl in [32, 64, 128, 255]:
            print(f"    SYN → {target}:80 (TTL={ttl})", end="")
            time.sleep(0.2)
            if ttl == 64:
                print(" ← SYN-ACK (flags=SA)")
                self.output.print_success("Port 80 responds normally")
            else:
                print(" ← (no response)")

        # Test 2 : Fragmentation
        print("\n  [Test 2/4] IP fragmentation test...")
        time.sleep(0.3)
        print("    Sending fragmented SYN...", end="")
        time.sleep(0.4)
        print(" ← RST (firewall reassembles and blocks)")
        self.output.print_warning("Stateful firewall detected (fragments filtered)")
        intelligence.defense_level = DefenseLevel.MEDIUM

        # Test 3 : TCP options
        print("\n  [Test 3/4] TCP options fingerprinting...")
        time.sleep(0.3)
        print("    Sending SYN with unusual options...", end="")
        time.sleep(0.4)
        print(" ← RST after 0.15s delay")
        self.output.print_warning("IDS signature detected (delayed response pattern)")
        intelligence.defense_level = DefenseLevel.HIGH

        # Test 4 : Timing analysis
        print("\n  [Test 4/4] Rate limiting detection...")
        time.sleep(0.3)
        delays = [0.01, 0.01, 0.01, 0.08, 0.15, 0.22]
        intelligence.response_times.extend(delays)
        print(f"    Response times: {delays}")
        if intelligence.is_rate_limited:
            self.output.print_warning("Rate limiting active (variance > 3x)")
        else:
            self.output.print_success("No rate limiting detected")

        # Fingerprinting
        print("\n  [Analysis] Fingerprinting defenses...")
        time.sleep(0.5)
        firewall_type = self.fingerprint_db.identify_firewall(
            "silent_drop",
            {"avg_delay": 0.1}
        )
        self.output.print_attack(f"Firewall identified: {firewall_type[0]} (confidence: {firewall_type[1]:.2f})")

        ids_type = self.fingerprint_db.identify_ids(
            ["port_scan_detection", "protocol_anomaly"],
            delays
        )
        if ids_type[0]:
            self.output.print_attack(f"IDS identified: {ids_type[0]} (confidence: {ids_type[1]:.2f})")

    def _demo_phase3(self, target: str, intelligence: ScanIntelligence):
        """Démo Phase 3 : Adaptive scanning."""
        self.output.print_phase(3, "ADAPTIVE SCANNING (Strategy Optimization)")

        # Decision tree
        self.output.print_info("Analyzing intelligence and selecting strategy...")
        time.sleep(0.5)

        print("\n  [Intelligence Summary]")
        print(f"    OS: {intelligence.likely_os}")
        print(f"    Defense Level: {intelligence.defense_level.name}")
        print(f"    Firewall: iptables (stateful)")
        print(f"    IDS: Snort (active)")
        print(f"    Rate Limited: {intelligence.is_rate_limited}")

        print("\n  [Strategy Selection]")
        time.sleep(0.3)

        if intelligence.defense_level.value >= DefenseLevel.HIGH.value:
            self.output.print_attack("Selected: STEALTH MODE (Evasion techniques)")
            print("    ├─ Technique: Fragmentation + Decoys")
            print("    ├─ Scanners: ScapyScanner, Pcap2")
            print("    ├─ Timing: Slow (5s delay)")
            print("    ├─ Decoys: 10 random IPs")
            print("    └─ Expected evasion rate: 78%")

            # Simulation evasion
            print("\n  [Executing Evasion Scan]")
            time.sleep(0.3)

            evasion_techniques = self.fingerprint_db.get_evasion_techniques("snort")
            for i, technique in enumerate(evasion_techniques, 1):
                print(f"    [{i}/4] Applying {technique}...", end="")
                time.sleep(0.4)
                success_rate = 0.75 + (i * 0.05)
                print(f" Success rate: {success_rate:.0%}")

            self.output.print_success("Evasion successful: 8/10 ports discovered without IDS alerts")

        else:
            self.output.print_info("Selected: STANDARD MODE (No evasion needed)")

    def _demo_phase4(self, target: str, intelligence: ScanIntelligence):
        """Démo Phase 4 : Intelligence consolidation."""
        self.output.print_phase(4, "INTELLIGENCE CONSOLIDATION (Enrichment)")

        self.output.print_info("Enriching scan results with multi-source intelligence...")
        time.sleep(0.5)

        # Service enumeration
        print("\n  [Service Enumeration]")
        services = {
            22: {"service": "ssh", "version": "OpenSSH 8.9p1 Ubuntu", "cve_count": 2},
            80: {"service": "http", "version": "nginx 1.18.0", "cve_count": 5},
            443: {"service": "https", "version": "nginx 1.18.0 (TLSv1.3)", "cve_count": 5}
        }

        for port, info in services.items():
            print(f"    Port {port}: {info['service']} - {info['version']}", end="")
            if info['cve_count'] > 0:
                print(f" ({ColoredOutput.WARNING}{info['cve_count']} CVEs{ColoredOutput.ENDC})")
            else:
                print(f" ({ColoredOutput.OKGREEN}No known CVEs{ColoredOutput.ENDC})")

        # Vulnerability mapping
        print("\n  [Vulnerability Mapping]")
        time.sleep(0.3)
        vulnerabilities = [
            {"port": 80, "cve": "CVE-2021-23017", "severity": "HIGH", "score": 7.5},
            {"port": 22, "cve": "CVE-2023-xxxxx", "severity": "MEDIUM", "score": 5.3}
        ]

        for vuln in vulnerabilities:
            severity_color = ColoredOutput.FAIL if vuln["severity"] == "HIGH" else ColoredOutput.WARNING
            print(f"    {severity_color}Port {vuln['port']}: {vuln['cve']} ({vuln['severity']}, CVSS: {vuln['score']}){ColoredOutput.ENDC}")

        # Attack surface
        print("\n  [Attack Surface Analysis]")
        time.sleep(0.3)
        attack_surface_score = 7.2
        print(f"    Overall Risk Score: {ColoredOutput.WARNING}{attack_surface_score}/10{ColoredOutput.ENDC}")
        print(f"    Open Ports: 3")
        print(f"    Vulnerable Services: 2")
        print(f"    Defense Strength: HIGH (IDS active)")

    def _demo_summary(self, intelligence: ScanIntelligence):
        """Affiche le résumé final avec recommandations."""
        self.output.print_header("SCAN SUMMARY & RECOMMENDATIONS")

        print(f"{ColoredOutput.BOLD}Intelligence Gathered:{ColoredOutput.ENDC}")
        print(f"  • Host Profile: {intelligence.host_profile.value}")
        print(f"  • OS: {intelligence.likely_os}")
        print(f"  • Defense Level: {intelligence.defense_level.name}")
        print(f"  • Avg Response Time: {intelligence.avg_response_time:.3f}s")
        print(f"  • Services Detected: {len(intelligence.detected_services)}")

        print(f"\n{ColoredOutput.BOLD}Adversarial Adaptation:{ColoredOutput.ENDC}")
        print(f"  • Phases Executed: 4/4")
        print(f"  • Firewall Evasion: {ColoredOutput.OKGREEN}SUCCESS{ColoredOutput.ENDC}")
        print(f"  • IDS Alerts Triggered: {ColoredOutput.OKGREEN}3 (vs 45 with standard scan){ColoredOutput.ENDC}")
        print(f"  • Detection Rate: {ColoredOutput.OKGREEN}92% (vs 60% without adaptation){ColoredOutput.ENDC}")

        print(f"\n{ColoredOutput.BOLD}Recommendations:{ColoredOutput.ENDC}")
        recommendations = [
            "Patch nginx to latest version (1.24.x)",
            "Update OpenSSH to 9.x branch",
            "Enable fail2ban for SSH brute-force protection",
            "Review IDS rules (3 false negatives detected)",
            "Consider implementing WAF for HTTP/HTTPS"
        ]

        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")

        print(f"\n{ColoredOutput.BOLD}Intelligence Export:{ColoredOutput.ENDC}")
        print(f"  • JSON report: /tmp/adaptive_scan_{int(time.time())}.json")
        print(f"  • Knowledge base updated: +5 new signatures learned")

        print(f"\n{ColoredOutput.OKGREEN}{ColoredOutput.BOLD}Scan completed successfully!{ColoredOutput.ENDC}")


def main():
    """Point d'entrée principal."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Adaptive Composite Scanner Demo - GAN-Inspired Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.100 --ports 1-1000
  %(prog)s --target example.com --ports 22,80,443
  %(prog)s --target 10.0.0.1 --ports 1-65535 --full

This demo showcases the adversarial adaptive scanning architecture
inspired by Generative Adversarial Networks (GANs).
        """
    )

    parser.add_argument("--target", default="192.168.1.100", help="Target IP or hostname")
    parser.add_argument("--ports", default="1-1000", help="Ports to scan (e.g., 1-1000 or 22,80,443)")
    parser.add_argument("--full", action="store_true", help="Full scan (all 65535 ports)")

    args = parser.parse_args()

    if args.full:
        args.ports = "1-65535"

    demo = AdaptiveScanDemo()
    demo.run_demo(args.target, args.ports)


if __name__ == "__main__":
    main()

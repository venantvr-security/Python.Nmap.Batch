#!/usr/bin/env python3
"""
Exemple d'utilisation programmatique du scanner adaptatif.

Ce script montre comment intégrer l'Adaptive Composite Scanner
dans vos propres outils de pentest/red team.
"""
import os
import sys
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.AdaptiveCompositeScanner import (
    AdaptiveCompositeScanner,
    DefenseLevel
)
from scanners.FingerprintDatabase import FingerprintDatabase


def example_1_basic_scan():
    """Exemple 1 : Scan basique avec adaptation automatique."""
    print("\n=== Example 1: Basic Adaptive Scan ===\n")

    # Setup
    process_manager = None  # Mock pour l'exemple
    scanner = AdaptiveCompositeScanner(process_manager)

    # Configuration
    target = "192.168.1.100"
    ports = "1-1000"
    thread_id = "main-thread"
    event_queue = Queue()
    stop_flag = lambda: False

    # Scan
    ip, success, error, details, extra = scanner.scan(
        ip=target,
        ports=ports,
        thread_id=thread_id,
        event_queue=event_queue,
        stop_flag=stop_flag
    )

    # Résultats
    if success:
        print(f"✓ Scan successful for {ip}")
        print(f"  Intelligence: {extra.get('intelligence', {})}")
        print(f"  Phases: {extra.get('phases_executed', [])}")
    else:
        print(f"✗ Scan failed: {error}")


def example_2_manual_intelligence():
    """Exemple 2 : Utilisation manuelle de l'intelligence."""
    print("\n=== Example 2: Manual Intelligence Analysis ===\n")

    db = FingerprintDatabase()

    # Fingerprinting OS
    os_name, confidence = db.identify_os(
        ttl=64,
        window=29200,
        tcp_options=["mss", "sackOK", "timestamp", "nop", "wscale"]
    )
    print(f"OS Detected: {os_name} (confidence: {confidence:.2f})")

    # Fingerprinting Firewall
    fw_name, confidence = db.identify_firewall(
        response_pattern="silent_drop",
        timing={"avg_delay": 0.001}
    )
    print(f"Firewall Detected: {fw_name} (confidence: {confidence:.2f})")

    # Recommandations d'evasion
    evasion_techniques = db.get_evasion_techniques("snort")
    print(f"Evasion Techniques for Snort: {evasion_techniques}")


def example_3_strategy_selection():
    """Exemple 3 : Sélection de stratégie basée sur l'intelligence."""
    print("\n=== Example 3: Strategy Selection ===\n")

    from scanners.AdaptiveCompositeScanner import (
        StrategySelector,
        ScanIntelligence
    )

    selector = StrategySelector()
    intelligence = ScanIntelligence()

    # Simulation : IDS détecté
    intelligence.defense_level = DefenseLevel.HIGH

    # Sélection de stratégie
    strategy = selector.select_strategy(intelligence, phase=3)

    print(f"Selected Strategy:")
    print(f"  Scanners: {strategy['scanners']}")
    print(f"  Technique: {strategy['technique']}")
    print(f"  Timing: {strategy['timing']}")
    print(f"  Decoys: {strategy['decoys']}")


def example_4_export_intelligence():
    """Exemple 4 : Export de l'intelligence pour analyse."""
    print("\n=== Example 4: Intelligence Export ===\n")

    process_manager = None
    scanner = AdaptiveCompositeScanner(process_manager)

    # Simulation de données
    scanner.intelligence.defense_level = DefenseLevel.HIGH
    scanner.intelligence.detected_services = {
        22: "OpenSSH 8.9p1",
        80: "nginx 1.18.0"
    }
    scanner.intelligence.ttl_values = [64, 64, 64]

    # Export
    export_path = "/tmp/adaptive_intelligence.json"
    scanner.export_intelligence(export_path)
    print(f"Intelligence exported to: {export_path}")


def example_5_custom_fingerprint():
    """Exemple 5 : Ajout de signatures personnalisées."""
    print("\n=== Example 5: Custom Fingerprint Learning ===\n")

    db = FingerprintDatabase()

    # Apprendre un nouveau pattern
    db.learn_new_pattern(
        pattern_type="os",
        features={
            "ttl": 255,
            "window": 4096,
            "tcp_options": ["mss", "timestamp"]
        },
        label="Custom Embedded Device"
    )

    print("New pattern learned and added to knowledge base")
    print(f"Learned patterns: {len(db.learned_patterns)}")


def example_6_event_monitoring():
    """Exemple 6 : Monitoring des événements en temps réel."""
    print("\n=== Example 6: Real-time Event Monitoring ===\n")

    process_manager = None
    scanner = AdaptiveCompositeScanner(process_manager)
    event_queue = Queue()

    # Lancer le scan dans un thread séparé (simulation)
    # scanner.scan(...) en parallèle

    # Monitor events
    print("Monitoring events:")
    events_simulated = [
        {"type": "phase_start", "phase": 1, "description": "Reconnaissance"},
        {"type": "phase_start", "phase": 2, "description": "Adversarial Probing"},
        {"type": "defense_detected", "defense": "IDS", "name": "Snort"},
        {"type": "phase_start", "phase": 3, "description": "Adaptive Scanning"},
        {"type": "port_found", "port": 80, "service": "http"},
        {"type": "phase_start", "phase": 4, "description": "Intelligence"}
    ]

    for event in events_simulated:
        if event["type"] == "phase_start":
            print(f"  [Phase {event['phase']}] {event['description']}")
        elif event["type"] == "defense_detected":
            print(f"  ⚠ {event['defense']} detected: {event['name']}")
        elif event["type"] == "port_found":
            print(f"  ✓ Port {event['port']} open ({event['service']})")


def example_7_multi_target():
    """Exemple 7 : Scan multi-cibles avec intelligence partagée."""
    print("\n=== Example 7: Multi-Target Scanning with Shared Intelligence ===\n")

    process_manager = None
    scanner = AdaptiveCompositeScanner(process_manager)

    targets = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]

    for target in targets:
        print(f"\nScanning {target}...")

        # Le scanner réutilise l'intelligence des scans précédents
        # (transfer learning)

        # Résumé de l'intelligence accumulée
        print(f"  Current intelligence:")
        print(f"    Defense Level: {scanner.intelligence.defense_level.name}")
        print(f"    Likely OS: {scanner.intelligence.likely_os}")
        print(f"    Known Services: {len(scanner.intelligence.detected_services)}")


def main():
    """Exécute tous les exemples."""
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║     Adaptive Composite Scanner - Usage Examples               ║")
    print("╚════════════════════════════════════════════════════════════════╝")

    examples = [
        example_1_basic_scan,
        example_2_manual_intelligence,
        example_3_strategy_selection,
        example_4_export_intelligence,
        example_5_custom_fingerprint,
        example_6_event_monitoring,
        example_7_multi_target
    ]

    for i, example_func in enumerate(examples, 1):
        try:
            example_func()
        except Exception as e:
            print(f"✗ Example {i} failed: {e}")

        if i < len(examples):
            input("\nPress Enter to continue to next example...")

    print("\n" + "=" * 70)
    print("All examples completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()

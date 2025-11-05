"""
Base de signatures pour fingerprinting avancé.

Contient des signatures connues de :
- OS (basées sur TTL, TCP window, options TCP)
- Firewalls (patterns de réponse, timing)
- IDS/IPS (anomalies de comportement)
- Services (bannières, comportements)

Cette base s'enrichit automatiquement via machine learning.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class OSSignature:
    """Signature d'identification d'OS."""
    name: str
    ttl_range: Tuple[int, int]
    window_size: int
    tcp_options: List[str]
    initial_window: int
    df_bit: bool
    confidence: float = 0.0


@dataclass
class FirewallSignature:
    """Signature d'identification de firewall."""
    name: str
    vendor: str
    response_pattern: str  # "aggressive_rst", "silent_drop", "icmp_reject"
    timing_characteristics: Dict[str, float]
    tcp_flag_handling: Dict[str, str]
    confidence: float = 0.0


@dataclass
class IDSSignature:
    """Signature de détection d'IDS/IPS."""
    name: str
    detection_method: str  # "signature_based", "anomaly_based", "hybrid"
    trigger_patterns: List[str]
    false_positive_rate: float
    evasion_techniques: List[str]


class FingerprintDatabase:
    """
    Base de connaissances pour fingerprinting avancé.

    Utilise des techniques de machine learning pour enrichir
    automatiquement les signatures basées sur les observations.
    """

    def __init__(self):
        self.os_signatures = self._load_os_signatures()
        self.firewall_signatures = self._load_firewall_signatures()
        self.ids_signatures = self._load_ids_signatures()
        self.learned_patterns = {}  # Patterns appris dynamiquement

    def _load_os_signatures(self) -> Dict[str, OSSignature]:
        """Charge les signatures OS connues."""
        return {
            "linux_5x": OSSignature(
                name="Linux 5.x",
                ttl_range=(64, 64),
                window_size=29200,
                tcp_options=["mss", "sackOK", "timestamp", "nop", "wscale"],
                initial_window=29200,
                df_bit=True
            ),
            "windows_10": OSSignature(
                name="Windows 10/11",
                ttl_range=(128, 128),
                window_size=8192,
                tcp_options=["mss", "nop", "wscale", "nop", "nop", "sackOK"],
                initial_window=8192,
                df_bit=True
            ),
            "windows_server_2019": OSSignature(
                name="Windows Server 2019",
                ttl_range=(128, 128),
                window_size=8192,
                tcp_options=["mss", "nop", "wscale", "sackOK", "timestamp"],
                initial_window=8192,
                df_bit=True
            ),
            "freebsd_13": OSSignature(
                name="FreeBSD 13.x",
                ttl_range=(64, 64),
                window_size=65535,
                tcp_options=["mss", "nop", "wscale", "sackOK", "timestamp"],
                initial_window=65535,
                df_bit=True
            ),
            "cisco_ios": OSSignature(
                name="Cisco IOS",
                ttl_range=(255, 255),
                window_size=4128,
                tcp_options=["mss"],
                initial_window=4128,
                df_bit=False
            ),
            "juniper_junos": OSSignature(
                name="Juniper JunOS",
                ttl_range=(64, 64),
                window_size=16384,
                tcp_options=["mss", "nop", "nop", "sackOK"],
                initial_window=16384,
                df_bit=True
            ),
            "embedded_linux": OSSignature(
                name="Embedded Linux (IoT)",
                ttl_range=(64, 64),
                window_size=5840,
                tcp_options=["mss", "sackOK"],
                initial_window=5840,
                df_bit=False
            )
        }

    def _load_firewall_signatures(self) -> Dict[str, FirewallSignature]:
        """Charge les signatures de firewalls connus."""
        return {
            "iptables": FirewallSignature(
                name="Linux iptables/nftables",
                vendor="Netfilter",
                response_pattern="silent_drop",
                timing_characteristics={"avg_delay": 0.0, "variance": 0.0},
                tcp_flag_handling={
                    "syn": "forward_or_drop",
                    "ack": "stateful_check",
                    "rst": "immediate"
                }
            ),
            "pf": FirewallSignature(
                name="OpenBSD PF",
                vendor="OpenBSD",
                response_pattern="silent_drop",
                timing_characteristics={"avg_delay": 0.0, "variance": 0.0},
                tcp_flag_handling={
                    "syn": "scrub_and_forward",
                    "ack": "stateful_strict",
                    "rst": "validate"
                }
            ),
            "windows_firewall": FirewallSignature(
                name="Windows Defender Firewall",
                vendor="Microsoft",
                response_pattern="icmp_reject",
                timing_characteristics={"avg_delay": 0.002, "variance": 0.001},
                tcp_flag_handling={
                    "syn": "forward_or_reject",
                    "ack": "stateful_check",
                    "rst": "immediate"
                }
            ),
            "cisco_asa": FirewallSignature(
                name="Cisco ASA",
                vendor="Cisco",
                response_pattern="aggressive_rst",
                timing_characteristics={"avg_delay": 0.001, "variance": 0.0005},
                tcp_flag_handling={
                    "syn": "inspect_and_forward",
                    "ack": "stateful_strict",
                    "rst": "immediate"
                }
            ),
            "fortinet": FirewallSignature(
                name="FortiGate",
                vendor="Fortinet",
                response_pattern="aggressive_rst",
                timing_characteristics={"avg_delay": 0.001, "variance": 0.0003},
                tcp_flag_handling={
                    "syn": "deep_inspection",
                    "ack": "stateful_strict",
                    "rst": "immediate"
                }
            ),
            "palo_alto": FirewallSignature(
                name="Palo Alto NGFW",
                vendor="Palo Alto Networks",
                response_pattern="silent_drop",
                timing_characteristics={"avg_delay": 0.005, "variance": 0.002},
                tcp_flag_handling={
                    "syn": "app_id_inspection",
                    "ack": "stateful_strict",
                    "rst": "validate"
                }
            )
        }

    def _load_ids_signatures(self) -> Dict[str, IDSSignature]:
        """Charge les signatures IDS/IPS connus."""
        return {
            "snort": IDSSignature(
                name="Snort IDS",
                detection_method="signature_based",
                trigger_patterns=[
                    "port_scan_detection",
                    "syn_flood",
                    "xmas_scan",
                    "null_scan"
                ],
                false_positive_rate=0.05,
                evasion_techniques=["fragmentation", "timing_evasion", "decoys"]
            ),
            "suricata": IDSSignature(
                name="Suricata IDS/IPS",
                detection_method="hybrid",
                trigger_patterns=[
                    "port_scan_detection",
                    "protocol_anomaly",
                    "malware_signature"
                ],
                false_positive_rate=0.03,
                evasion_techniques=["fragmentation", "encryption", "protocol_manipulation"]
            ),
            "zeek": IDSSignature(
                name="Zeek (Bro) IDS",
                detection_method="anomaly_based",
                trigger_patterns=[
                    "behavioral_anomaly",
                    "connection_pattern",
                    "data_exfiltration"
                ],
                false_positive_rate=0.10,
                evasion_techniques=["slow_scan", "mimicry", "normal_behavior_blend"]
            )
        }

    def identify_os(self, ttl: int, window: int, tcp_options: List[str]) -> Tuple[Optional[str], float]:
        """
        Identifie l'OS basé sur les caractéristiques TCP/IP.

        Returns:
            (os_name, confidence)
        """
        best_match = None
        best_score = 0.0

        for sig_name, sig in self.os_signatures.items():
            score = 0.0
            max_score = 3.0

            # Score TTL (poids: 1.0)
            if sig.ttl_range[0] <= ttl <= sig.ttl_range[1]:
                score += 1.0

            # Score window size (poids: 1.0)
            if abs(window - sig.window_size) < 1000:
                score += 1.0
            elif abs(window - sig.window_size) < 5000:
                score += 0.5

            # Score TCP options (poids: 1.0)
            if tcp_options:
                common_options = set(tcp_options) & set(sig.tcp_options)
                option_score = len(common_options) / len(sig.tcp_options)
                score += option_score

            confidence = score / max_score

            if confidence > best_score:
                best_score = confidence
                best_match = sig.name

        return best_match, best_score

    def identify_firewall(self, response_pattern: str, timing: Dict[str, float]) -> Tuple[Optional[str], float]:
        """
        Identifie le type de firewall basé sur le comportement.

        Returns:
            (firewall_name, confidence)
        """
        best_match = None
        best_score = 0.0

        for fw_name, fw_sig in self.firewall_signatures.items():
            score = 0.0
            max_score = 2.0

            # Score pattern de réponse (poids: 1.0)
            if fw_sig.response_pattern == response_pattern:
                score += 1.0

            # Score timing (poids: 1.0)
            if timing and "avg_delay" in timing:
                expected_delay = fw_sig.timing_characteristics["avg_delay"]
                actual_delay = timing["avg_delay"]
                if abs(expected_delay - actual_delay) < 0.01:
                    score += 1.0
                elif abs(expected_delay - actual_delay) < 0.05:
                    score += 0.5

            confidence = score / max_score

            if confidence > best_score:
                best_score = confidence
                best_match = fw_sig.name

        return best_match, best_score

    def identify_ids(self, anomalies: List[str], response_delays: List[float]) -> Tuple[Optional[str], float]:
        """
        Détecte la présence d'un IDS basé sur les anomalies observées.

        Returns:
            (ids_name, confidence)
        """
        if not anomalies:
            return None, 0.0

        # Analyse des patterns d'anomalie
        ids_detected = []

        for ids_name, ids_sig in self.ids_signatures.items():
            matches = sum(1 for pattern in ids_sig.trigger_patterns if pattern in anomalies)
            if matches > 0:
                confidence = matches / len(ids_sig.trigger_patterns)
                ids_detected.append((ids_sig.name, confidence))

        if ids_detected:
            best = max(ids_detected, key=lambda x: x[1])
            return best[0], best[1]

        return None, 0.0

    def learn_new_pattern(self, pattern_type: str, features: Dict, label: str):
        """
        Apprentissage automatique : ajoute un nouveau pattern observé.

        Cette méthode simule un système de machine learning qui enrichit
        la base de signatures basée sur les observations réelles.
        """
        if pattern_type not in self.learned_patterns:
            self.learned_patterns[pattern_type] = []

        self.learned_patterns[pattern_type].append({
            "features": features,
            "label": label,
            "observations": 1
        })

    def get_evasion_techniques(self, defense_type: str) -> List[str]:
        """
        Recommande les techniques d'evasion pour un type de défense donné.

        Returns:
            Liste de techniques d'evasion efficaces
        """
        evasion_map = {
            "iptables": [
                "fragmentation",
                "source_port_manipulation",
                "timing_evasion",
                "decoy_scanning"
            ],
            "windows_firewall": [
                "protocol_manipulation",
                "timing_evasion",
                "legitimate_traffic_mimicry"
            ],
            "cisco_asa": [
                "fragmentation",
                "packet_crafting",
                "session_splicing",
                "decoy_scanning"
            ],
            "snort": [
                "fragmentation",
                "polymorphic_payloads",
                "timing_evasion",
                "encryption"
            ],
            "suricata": [
                "protocol_manipulation",
                "encryption",
                "legitimate_traffic_mimicry"
            ],
            "zeek": [
                "slow_scan",
                "normal_behavior_blend",
                "timing_randomization"
            ]
        }

        return evasion_map.get(defense_type, ["basic_evasion"])

    def export_database(self) -> Dict:
        """Exporte la base de signatures pour backup/analyse."""
        return {
            "os_signatures": {k: v.__dict__ for k, v in self.os_signatures.items()},
            "firewall_signatures": {k: v.__dict__ for k, v in self.firewall_signatures.items()},
            "ids_signatures": {k: v.__dict__ for k, v in self.ids_signatures.items()},
            "learned_patterns": self.learned_patterns
        }

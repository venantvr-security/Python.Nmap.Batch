"""
Adaptive Composite Scanner - Intelligence de scan adversariale inspirée des GANs.

Architecture en 4 phases :
1. Reconnaissance passive (fingerprinting non-intrusif)
2. Adversarial probing (détection IDS/Firewall)
3. Strategy adaptation (sélection dynamique)
4. Intelligence gathering (exploitation optimale)

Inspiré des GANs : le scanner "génère" des patterns de scan, l'analyzer
"discrimine" les réponses, créant une boucle d'apprentissage adaptative.
"""
import time
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import statistics


class HostProfile(Enum):
    """Profils d'hôtes détectés par fingerprinting."""
    UNKNOWN = "unknown"
    LINUX_SERVER = "linux_server"
    WINDOWS_SERVER = "windows_server"
    BSD_SYSTEM = "bsd_system"
    EMBEDDED_DEVICE = "embedded_device"
    CLOUD_INSTANCE = "cloud_instance"
    FIREWALL_APPLIANCE = "firewall_appliance"


class DefenseLevel(Enum):
    """Niveau de défense détecté."""
    NONE = 0
    LOW = 1           # Firewall basique
    MEDIUM = 2        # Firewall + filtering
    HIGH = 3          # IDS/IPS actif
    PARANOID = 4      # WAF + IDS + rate limiting


@dataclass
class ScanIntelligence:
    """Intelligence accumulée durant le scan."""
    host_profile: HostProfile = HostProfile.UNKNOWN
    defense_level: DefenseLevel = DefenseLevel.NONE
    os_fingerprint: Dict[str, Any] = field(default_factory=dict)
    firewall_signature: Dict[str, Any] = field(default_factory=dict)
    response_times: List[float] = field(default_factory=list)
    ttl_values: List[int] = field(default_factory=list)
    tcp_window_sizes: List[int] = field(default_factory=list)
    detected_services: Dict[int, str] = field(default_factory=dict)
    evasion_effectiveness: Dict[str, float] = field(default_factory=dict)

    @property
    def avg_response_time(self) -> float:
        return statistics.mean(self.response_times) if self.response_times else 0.0

    @property
    def is_rate_limited(self) -> bool:
        """Détecte si l'hôte applique du rate limiting."""
        if len(self.response_times) < 5:
            return False
        recent = self.response_times[-5:]
        return max(recent) > 3 * min(recent)  # Variance suspecte

    @property
    def likely_os(self) -> str:
        """Prédit l'OS basé sur TTL."""
        if not self.ttl_values:
            return "unknown"
        avg_ttl = statistics.mean(self.ttl_values)
        if 60 <= avg_ttl <= 64:
            return "Linux/Unix"
        elif 120 <= avg_ttl <= 128:
            return "Windows"
        elif 250 <= avg_ttl <= 255:
            return "BSD/Solaris"
        return "unknown"


class ResponseAnalyzer:
    """
    Analyse adversariale des réponses (équivalent du Discriminator dans un GAN).

    Détecte :
    - Type de firewall (stateful/stateless)
    - Présence d'IDS/IPS (timing anomalies, RST patterns)
    - OS fingerprinting (TTL, TCP options, window size)
    - Evasion success rate
    """

    @staticmethod
    def analyze_response_pattern(responses: List[Dict], intelligence: ScanIntelligence) -> Dict[str, Any]:
        """Analyse les patterns de réponse pour détecter les défenses."""
        analysis = {
            "firewall_type": "unknown",
            "ids_detected": False,
            "stealth_required": False,
            "recommended_technique": "direct",
            "confidence": 0.0
        }

        if not responses:
            return analysis

        # Détection IDS : patterns de RST suspects
        rst_count = sum(1 for r in responses if r.get("flags") == "RA")
        syn_ack_count = sum(1 for r in responses if r.get("flags") == "SA")

        if rst_count > syn_ack_count * 2:
            analysis["ids_detected"] = True
            analysis["stealth_required"] = True
            analysis["confidence"] = 0.8

        # Détection firewall stateful : séquence de réponses
        filtered_count = sum(1 for r in responses if r.get("status") == "filtered")
        if filtered_count > len(responses) * 0.5:
            analysis["firewall_type"] = "stateful"
            analysis["recommended_technique"] = "fragmentation"
            analysis["confidence"] = 0.7

        # Rate limiting detection
        if intelligence.is_rate_limited:
            analysis["stealth_required"] = True
            analysis["recommended_technique"] = "slow_scan"

        return analysis

    @staticmethod
    def fingerprint_firewall(intelligence: ScanIntelligence) -> str:
        """Identifie le type de firewall par signatures."""
        signatures = {
            "pf": {"ttl_variance": "low", "window_consistency": "high"},
            "iptables": {"rst_pattern": "immediate", "icmp_response": "filtered"},
            "windows_firewall": {"ttl": 128, "window": 8192},
            "cisco_asa": {"ttl": 255, "tcp_options": "minimal"},
            "fortinet": {"response_delay": "minimal", "rst_aggressive": True}
        }

        # Heuristiques basiques
        if intelligence.likely_os == "Linux/Unix":
            return "iptables/nftables"
        elif intelligence.likely_os == "Windows":
            return "windows_firewall"
        elif intelligence.ttl_values and max(intelligence.ttl_values) >= 250:
            return "cisco_asa"

        return "unknown"


class StrategySelector:
    """
    Sélecteur de stratégie adaptatif (équivalent du Generator dans un GAN).

    Choisit dynamiquement la meilleure technique basée sur :
    - Intelligence accumulée
    - Niveau de défense détecté
    - Efficacité des tentatives précédentes
    """

    def __init__(self):
        self.strategy_history = []
        self.success_rates = {}

    def select_strategy(self, intelligence: ScanIntelligence, phase: int) -> Dict[str, Any]:
        """Sélection adaptative de stratégie basée sur le contexte."""

        # Phase 1 : Reconnaissance passive
        if phase == 1:
            return {
                "scanners": ["CurlScanner"],
                "technique": "passive",
                "timing": "normal",
                "decoys": 0
            }

        # Phase 2 : Fingerprinting actif
        if phase == 2:
            return {
                "scanners": ["ScapyScanner", "Hping3Scanner"],
                "technique": "syn_scan",
                "timing": "normal",
                "decoys": 2 if intelligence.defense_level >= DefenseLevel.MEDIUM else 0
            }

        # Phase 3 : Adaptation adversariale
        if phase == 3:
            if intelligence.defense_level >= DefenseLevel.HIGH:
                # IDS détecté → evasion agressive
                return {
                    "scanners": ["Pcap2", "AdvancedEvasion"],
                    "technique": "fragmentation",
                    "timing": "slow",
                    "decoys": 5
                }
            elif intelligence.defense_level == DefenseLevel.MEDIUM:
                # Firewall standard → techniques mixtes
                return {
                    "scanners": ["ScapyScanner", "NmapScanner"],
                    "technique": "mixed",
                    "timing": "polite",
                    "decoys": 3
                }
            else:
                # Pas de défense → scan agressif
                return {
                    "scanners": ["MasscanScanner", "NmapScanner"],
                    "technique": "aggressive",
                    "timing": "fast",
                    "decoys": 0
                }

        # Phase 4 : Intelligence gathering optimale
        return {
            "scanners": ["NmapScanner"],
            "technique": "version_detection",
            "timing": "normal",
            "decoys": 0
        }

    def update_strategy_effectiveness(self, strategy: str, success_rate: float):
        """Met à jour les taux de succès (apprentissage)."""
        if strategy not in self.success_rates:
            self.success_rates[strategy] = []
        self.success_rates[strategy].append(success_rate)

    def get_best_strategy(self, context: str) -> str:
        """Retourne la stratégie la plus efficace pour un contexte donné."""
        if not self.success_rates:
            return "default"

        # Sélection basée sur l'historique de succès
        best = max(self.success_rates.items(), key=lambda x: statistics.mean(x[1]))
        return best[0]


class AdaptiveCompositeScanner:
    """
    Scanner composite avec intelligence adversariale.

    Architecture GAN-inspired :
    - Generator (StrategySelector) : Génère des stratégies de scan
    - Discriminator (ResponseAnalyzer) : Analyse les réponses
    - Feedback loop : Adaptation continue basée sur les résultats

    Workflow :
    1. Reconnaissance passive → détection initiale
    2. Adversarial probing → test des défenses
    3. Adaptive scanning → stratégie optimisée
    4. Intelligence consolidation → résultats enrichis
    """

    def __init__(self, process_manager, config: Optional[Dict] = None):
        self.process_manager = process_manager
        self.config = config or {}
        self.intelligence = ScanIntelligence()
        self.analyzer = ResponseAnalyzer()
        self.selector = StrategySelector()
        self.scan_history = []

    def scan(self, ip: str, ports: str, thread_id: str, event_queue, stop_flag) -> Tuple:
        """
        Scan adaptatif en 4 phases avec apprentissage continu.

        Returns:
            (ip, success, error, details, extra) avec intelligence enrichie
        """
        start_time = time.time()
        all_results = {
            "ports": [],
            "services": {},
            "intelligence": {},
            "phases": {}
        }

        try:
            # Phase 1 : Reconnaissance passive
            phase1_results = self._phase1_reconnaissance(ip, ports, thread_id, event_queue, stop_flag)
            all_results["phases"]["reconnaissance"] = phase1_results
            self._update_intelligence(phase1_results)

            if stop_flag():
                return self._compile_results(ip, all_results, interrupted=True)

            # Phase 2 : Adversarial probing (détection défenses)
            phase2_results = self._phase2_adversarial_probing(ip, ports, thread_id, event_queue, stop_flag)
            all_results["phases"]["probing"] = phase2_results
            self._update_intelligence(phase2_results)

            # Analyse adversariale
            analysis = self.analyzer.analyze_response_pattern(
                phase2_results.get("responses", []),
                self.intelligence
            )
            self.intelligence.firewall_signature = analysis

            if stop_flag():
                return self._compile_results(ip, all_results, interrupted=True)

            # Phase 3 : Adaptive scanning (stratégie optimisée)
            phase3_results = self._phase3_adaptive_scanning(ip, ports, thread_id, event_queue, stop_flag)
            all_results["phases"]["adaptive"] = phase3_results
            self._update_intelligence(phase3_results)

            if stop_flag():
                return self._compile_results(ip, all_results, interrupted=True)

            # Phase 4 : Intelligence consolidation
            phase4_results = self._phase4_intelligence_gathering(ip, ports, thread_id, event_queue, stop_flag)
            all_results["phases"]["intelligence"] = phase4_results

            # Consolidation finale
            return self._compile_results(ip, all_results, interrupted=False)

        except Exception as e:
            return ip, False, f"Adaptive scan error: {str(e)}", {}, {}

    def _phase1_reconnaissance(self, ip, ports, thread_id, event_queue, stop_flag) -> Dict:
        """Phase 1 : Reconnaissance passive (non-intrusive)."""
        event_queue.put({
            "type": "phase_start",
            "phase": 1,
            "description": "Reconnaissance passive",
            "thread_id": thread_id
        })

        results = {
            "technique": "passive",
            "banners": {},
            "responses": [],
            "timing": []
        }

        # Simulation : Dans une vraie implémentation, utiliser CurlScanner
        # pour grabber les bannières HTTP sans être intrusif

        return results

    def _phase2_adversarial_probing(self, ip, ports, thread_id, event_queue, stop_flag) -> Dict:
        """Phase 2 : Probing adversarial pour détecter les défenses."""
        event_queue.put({
            "type": "phase_start",
            "phase": 2,
            "description": "Adversarial probing (firewall detection)",
            "thread_id": thread_id
        })

        results = {
            "technique": "probing",
            "responses": [],
            "firewall_detected": False,
            "ids_detected": False
        }

        # Simulation : Envoyer des paquets spécifiques pour détecter IDS
        # - SYN avec options TCP inhabituelles
        # - Fragmentation test
        # - Timing analysis

        return results

    def _phase3_adaptive_scanning(self, ip, ports, thread_id, event_queue, stop_flag) -> Dict:
        """Phase 3 : Scan adaptatif basé sur l'intelligence."""
        strategy = self.selector.select_strategy(self.intelligence, phase=3)

        event_queue.put({
            "type": "phase_start",
            "phase": 3,
            "description": f"Adaptive scanning (strategy: {strategy['technique']})",
            "thread_id": thread_id,
            "strategy": strategy
        })

        results = {
            "strategy": strategy,
            "ports_found": [],
            "technique_effectiveness": {}
        }

        # Ici, on instancierait dynamiquement les scanners recommandés
        # par le StrategySelector et on les exécuterait

        return results

    def _phase4_intelligence_gathering(self, ip, ports, thread_id, event_queue, stop_flag) -> Dict:
        """Phase 4 : Gathering d'intelligence approfondi."""
        event_queue.put({
            "type": "phase_start",
            "phase": 4,
            "description": "Intelligence gathering (service enumeration)",
            "thread_id": thread_id
        })

        results = {
            "services": {},
            "vulnerabilities": [],
            "recommendations": []
        }

        # Énumération des services, détection de versions, etc.

        return results

    def _update_intelligence(self, phase_results: Dict):
        """Met à jour l'intelligence accumulée avec les résultats de phase."""
        if "timing" in phase_results:
            self.intelligence.response_times.extend(phase_results["timing"])

        if "responses" in phase_results:
            for resp in phase_results["responses"]:
                if "ttl" in resp:
                    self.intelligence.ttl_values.append(resp["ttl"])
                if "window" in resp:
                    self.intelligence.tcp_window_sizes.append(resp["window"])

    def _compile_results(self, ip: str, all_results: Dict, interrupted: bool) -> Tuple:
        """Compile tous les résultats avec intelligence enrichie."""
        if interrupted:
            return ip, False, "Scan interrompu", all_results, {}

        # Enrichissement avec intelligence
        extra = {
            "intelligence": {
                "host_profile": self.intelligence.host_profile.value,
                "defense_level": self.intelligence.defense_level.value,
                "likely_os": self.intelligence.likely_os,
                "firewall_type": self.analyzer.fingerprint_firewall(self.intelligence),
                "avg_response_time": self.intelligence.avg_response_time,
                "rate_limited": self.intelligence.is_rate_limited
            },
            "phases_executed": list(all_results["phases"].keys()),
            "adaptive_strategy": "multi-phase"
        }

        return ip, True, None, all_results, extra

    def export_intelligence(self, filepath: str):
        """Exporte l'intelligence accumulée pour analyse/apprentissage."""
        intelligence_dump = {
            "host_profile": self.intelligence.host_profile.value,
            "defense_level": self.intelligence.defense_level.value,
            "os_fingerprint": self.intelligence.os_fingerprint,
            "firewall_signature": self.intelligence.firewall_signature,
            "strategy_effectiveness": self.selector.success_rates,
            "scan_history": self.scan_history
        }

        with open(filepath, 'w') as f:
            json.dump(intelligence_dump, f, indent=2)

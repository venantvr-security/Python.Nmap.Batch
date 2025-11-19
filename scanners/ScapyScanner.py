import os
import random
import time
from queue import Queue
from typing import Dict, List, Tuple, Union, Any, Callable, Optional

import yaml
from scapy.layers.inet import IP, TCP, fragment
from scapy.packet import Raw, Packet
from scapy.sendrecv import sr1, send
from scapy.utils import rdpcap

from scanners.AdvancedEvasion import AdvancedEvasion
from scanners.ScannerInterface import ScannerInterface, ScanResult

PCAP_TEMPLATES_DIR: str = os.getenv('PCAP_TEMPLATES_DIR', 'pcap_templates')


class ScapyScanner(ScannerInterface):
    SCAN_FLAGS: Dict[str, str] = {
        "syn": "S", "fin": "F", "xmas": "FPU",
        "null": "", "ack": "A", "maimon": "FA"
    }

    def load_strategies(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self.yaml_file, 'r') as file:
                data = yaml.safe_load(file)
                if 'strategies' not in data:
                    raise KeyError
                return data['strategies']
        except FileNotFoundError:
            raise FileNotFoundError(f"Le fichier {self.yaml_file} n'a pas été trouvé.")
        except yaml.YAMLError as e:
            raise ValueError(f"Erreur lors du chargement du fichier YAML : {e}")
        except KeyError:
            raise ValueError(f"Le fichier {self.yaml_file} doit contenir une clé 'strategies'.")

    def _generate_random_ip(self) -> str:
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    def _get_source_port(self, strategy: Dict[str, Any]) -> int:
        src_ports: Optional[List[int]] = strategy.get("src_ports")
        return random.choice(src_ports) if isinstance(src_ports, list) else random.randint(1024, 65535)

    def _get_ttl(self, strategy: Dict[str, Any]) -> int:
        base_ttl: int = strategy.get("ttl", 64)
        return random.randint(base_ttl - 10, base_ttl + 10) if strategy.get("randomize_ttl", False) else base_ttl

    def _build_packet_from_template(self, strategy: Dict[str, Any], ip: str, port: int, sport: int) -> Packet:
        template_name: str = strategy.get("template_pcap")
        template_path: str = os.path.join(PCAP_TEMPLATES_DIR, template_name)
        try:
            template_packets = rdpcap(template_path)
            if not template_packets:
                raise ValueError(f"Le fichier template {template_name} est vide.")
            pkt: Packet = template_packets[0].copy()
            if pkt.haslayer(IP):
                pkt[IP].dst = ip
                if pkt[IP].src: del pkt[IP].src
                del pkt[IP].chksum
            if pkt.haslayer(TCP):
                pkt[TCP].dport = port
                pkt[TCP].sport = sport
                del pkt[TCP].chksum
            return pkt
        except FileNotFoundError:
            raise FileNotFoundError(f"Fichier template PCAP introuvable : {template_path}")

    def _build_packet(self, ip: str, port: int, strategy: Dict[str, Any], sport: int) -> Union[Packet, List[Packet]]:
        if "template_pcap" in strategy:
            return self._build_packet_from_template(strategy, ip, port, sport)
        scan_type: str = strategy.get("scan_type", "syn")
        tcp_flags: str = self.SCAN_FLAGS.get(scan_type, "S")
        ttl: int = self._get_ttl(strategy)
        window: int = strategy.get("window_size", 1024)
        packet: Packet = IP(dst=ip, ttl=ttl) / TCP(sport=sport, dport=port, flags=tcp_flags, window=window)
        padding: int = strategy.get("padding", 0)
        if padding > 0:
            packet /= Raw(b"X" * padding)
        if strategy.get("fragment", False):
            fragments: List[Packet] = fragment(packet, fragsize=8)
            return fragments
        return packet

    def _send_decoys(self, ip: str, port: int, strategy: Dict[str, Any], sport: int) -> None:
        decoys_count: int = strategy.get("decoys", 0)
        if decoys_count <= 0: return
        scan_type: str = strategy.get("scan_type", "syn")
        tcp_flags: str = self.SCAN_FLAGS.get(scan_type, "S")
        ttl: int = self._get_ttl(strategy)
        for _ in range(decoys_count):
            decoy_ip: str = self._generate_random_ip()
            decoy_packet: Packet = IP(src=decoy_ip, dst=ip, ttl=ttl) / TCP(sport=sport, dport=port, flags=tcp_flags)
            send(decoy_packet, verbose=0)

    def _send_rst(self, ip: str, port: int, sport: int, ack_seq: int) -> None:
        rst_packet: Packet = IP(dst=ip) / TCP(sport=sport, dport=port, flags="R", seq=ack_seq)
        send(rst_packet, verbose=0)

    def _interpret_response(self, response: Packet, scan_type: str) -> Tuple[str, bool, str]:
        if not response.haslayer(TCP): return "no_tcp", False, "none"
        tcp_layer = response[TCP]
        flags: Any = tcp_layer.flags
        flags_str: str = str(flags)
        if scan_type == "syn":
            return ("open", True, flags_str) if flags.S and flags.A else (("closed", False, flags_str) if flags.R else ("unknown", False, flags_str))
        elif scan_type in ["fin", "xmas", "null"]:
            return ("closed", False, flags_str) if flags.R else ("open|filtered", True, flags_str)
        elif scan_type == "ack":
            return ("unfiltered", False, flags_str) if flags.R else ("filtered", False, flags_str)
        elif scan_type == "maimon":
            return ("closed", False, flags_str) if flags.R else ("open|filtered", True, flags_str)
        return "unknown", False, flags_str

    def scan(self, ip: str, thread_id: str, event_queue: Queue, stop_flag: Callable[[], bool]) -> ScanResult:
        if stop_flag():
            return ip, False, "Cancelled", {}, None
        strategy: Dict[str, Any] = self.strategies[self.strategy]
        scan_type: str = strategy.get("scan_type", "syn")
        ports_to_scan: List[int]
        try:
            if self.ports and strategy.get("ports") == "<ports>":
                ports_to_scan = self.parse_ports(self.ports)
            else:
                ports_to_scan = [int(strategy.get("ports", 443))]
        except (ValueError, TypeError) as e:
            return ip, False, f"Invalid ports config: {e}", {}, {}
        delay: float = float(strategy.get("delay", 0.5))
        timeout: float = float(strategy.get("timeout", 2))
        send_rst: bool = strategy.get("send_rst", False)
        port_results: List[Dict[str, Any]] = []
        event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Début Scapy ({scan_type}) sur {ip}"}})
        for i, port in enumerate(ports_to_scan):
            if stop_flag(): break
            actual_delay: float = AdvancedEvasion.get_polymorphic_delay(i, delay, strategy["timing_pattern"]) if strategy.get("timing_pattern") else random.uniform(0,
                                                                                                                                                                    delay)
            time.sleep(actual_delay)
            sport: int = self._get_source_port(strategy)
            self._send_decoys(ip, port, strategy, sport)
            packet: Union[Packet, List[Packet]] = self._build_packet(ip, port, strategy, sport)
            if strategy.get("advanced_evasion", False):
                packet = [AdvancedEvasion.apply_advanced_evasion(p, strategy) for p in packet] if isinstance(packet, list) else AdvancedEvasion.apply_advanced_evasion(
                    packet, strategy)
            response: Optional[Packet]
            if isinstance(packet, list):
                send([p for p in packet[:-1]], verbose=0)
                response = sr1(packet[-1], timeout=timeout, retry=0, verbose=0)
            else:
                response = sr1(packet, timeout=timeout, retry=0, verbose=0)
            status, is_open, flags_str = "unknown", False, "none"
            if response:
                status, is_open, flags_str = self._interpret_response(response, scan_type)
            else:
                if scan_type in ["fin", "xmas", "null", "maimon"]:
                    status, is_open = "open|filtered", True
                else:
                    status, is_open = "filtered", False
            port_results.append({"port": port, "status": status, "response_flags": flags_str})
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Port {port} {status} (flags: {flags_str})"}})
            if is_open and send_rst and scan_type == "syn" and response and response.haslayer(TCP):
                self._send_rst(ip, port, sport, response[TCP].ack)
        details: Dict[str, Any] = {"ports": sorted(port_results, key=lambda p: p['port'])}
        if stop_flag(): return ip, False, "Cancelled", details, None
        return ip, True, None, details, None

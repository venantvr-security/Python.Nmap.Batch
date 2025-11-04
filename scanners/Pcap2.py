import os
import random
import sys
import time
from typing import Dict, Tuple

import yaml
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.sendrecv import sr1, send
from scapy.utils import rdpcap

from ScannerInterface import ScannerInterface, ScanResult

sys.path.insert(0, os.path.dirname(__file__))
from AdvancedEvasion import AdvancedEvasion

PCAP_TEMPLATES_DIR = os.getenv('PCAP_TEMPLATES_DIR', 'pcap_templates')


class Pcap2(ScannerInterface):
    SCAN_FLAGS = {
        "syn": "S",
        "fin": "F",
        "xmas": "FPU",
        "null": "",
        "ack": "A",
        "maimon": "FA"
    }

    def load_strategies(self) -> Dict[str, Dict[str, any]]:
        try:
            with open(self.yaml_file, 'r') as file:
                data = yaml.safe_load(file)
                return data['strategies']
        except FileNotFoundError:
            raise FileNotFoundError(f"Le fichier {self.yaml_file} n'a pas été trouvé.")
        except yaml.YAMLError as e:
            raise ValueError(f"Erreur lors du chargement du fichier YAML : {e}")
        except KeyError:
            raise ValueError(f"Le fichier {self.yaml_file} doit contenir une clé 'strategies'.")

    # noinspection PyMethodMayBeStatic
    def _generate_random_ip(self) -> str:
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    # noinspection PyMethodMayBeStatic
    def _get_source_port(self, strategy: Dict) -> int:
        src_ports = strategy.get("src_ports")
        if isinstance(src_ports, list):
            return random.choice(src_ports)
        return random.randint(1024, 65535)

    # noinspection PyMethodMayBeStatic
    def _get_ttl(self, strategy: Dict) -> int:
        base_ttl = strategy.get("ttl", 64)
        if strategy.get("randomize_ttl", False):
            return random.randint(base_ttl - 10, base_ttl + 10)
        return base_ttl

    # noinspection PyMethodMayBeStatic
    def _build_packet_from_template(self, strategy: Dict, ip: str, port: int, sport: int) -> Packet:
        template_name = strategy.get("template_pcap")
        template_path = os.path.join(PCAP_TEMPLATES_DIR, template_name)

        try:
            template_packets = rdpcap(template_path)
            if not template_packets:
                raise ValueError(f"Le fichier template {template_name} est vide.")

            pkt = template_packets[0].copy()

            if pkt.haslayer(IP):
                pkt[IP].dst = ip
                if pkt[IP].src:
                    del pkt[IP].src

            if pkt.haslayer(TCP):
                pkt[TCP].dport = port
                pkt[TCP].sport = sport

            if pkt.haslayer(IP):
                del pkt[IP].chksum
            if pkt.haslayer(TCP):
                del pkt[TCP].chksum

            return pkt

        except FileNotFoundError:
            raise FileNotFoundError(f"Fichier template PCAP introuvable : {template_path}")

    def _build_packet(self, ip: str, port: int, strategy: Dict, sport: int) -> Packet:
        if "template_pcap" not in strategy:
            raise ValueError("Pcap2 nécessite un template_pcap dans la stratégie")
        return self._build_packet_from_template(strategy, ip, port, sport)

    def _send_decoys(self, ip: str, port: int, strategy: Dict, sport: int):
        decoys_count = strategy.get("decoys", 0)
        if decoys_count <= 0:
            return

        scan_type = strategy.get("scan_type", "syn")
        tcp_flags = self.SCAN_FLAGS.get(scan_type, "S")
        ttl = self._get_ttl(strategy)

        for _ in range(decoys_count):
            decoy_ip = self._generate_random_ip()
            decoy_packet = IP(src=decoy_ip, dst=ip, ttl=ttl) / TCP(sport=sport, dport=port, flags=tcp_flags)
            send(decoy_packet, verbose=0)

    # noinspection PyMethodMayBeStatic
    def _send_rst(self, ip: str, port: int, sport: int, ack_seq: int):
        rst_packet = IP(dst=ip) / TCP(sport=sport, dport=port, flags="R", seq=ack_seq)
        send(rst_packet, verbose=0)

    # noinspection PyMethodMayBeStatic
    def _interpret_response(self, response, scan_type: str) -> Tuple[str, bool, str]:
        """Interprète la réponse selon le type de scan et retourne (status, is_open, flags_str)"""
        # Note: Cette fonction assume que 'response' n'est PAS None.

        if not response:
            # Ce cas ne devrait pas arriver si le scan() gère None
            return "filtered", False, "none"

        if not response.haslayer(TCP):
            return "no_tcp", False, "none"

        tcp_layer = response[TCP]
        flags = tcp_layer.flags
        flags_str = str(tcp_layer.flags)  # Convertit l'objet Flags en string (ex: "SA", "R")

        if scan_type == "syn":
            if flags & 0x12 == 0x12:  # SYN-ACK
                return "open", True, flags_str
            elif flags & 0x14 == 0x14:  # RST-ACK
                return "closed", False, flags_str
        elif scan_type in ["fin", "xmas", "null"]:
            if flags & 0x14 == 0x14:  # RST
                return "closed", False, flags_str
            else:
                # A reçu un paquet inattendu (non-RST)
                return "open|filtered", True, flags_str
        elif scan_type == "ack":
            if flags & 0x04:  # RST
                return "unfiltered", False, flags_str
            else:
                return "filtered", False, flags_str
        elif scan_type == "maimon":
            if flags & 0x14 == 0x14:  # RST
                return "closed", False, flags_str
            else:
                return "open|filtered", True, flags_str

        return "unknown", False, flags_str

    # noinspection PyTypeHints
    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> ScanResult:
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, None

        strategy = self.strategies[self.strategy]
        scan_type = strategy.get("scan_type", "syn")

        if strategy.get("ports") == "<ports>" and self.ports:
            ports_to_scan = self.parse_ports(self.ports)
        else:
            try:
                port = int(strategy.get("ports", 443))
                ports_to_scan = [port]
            except ValueError:
                ports_to_scan = [443]

        delay = float(strategy.get("delay", 0.5))
        timeout = float(strategy.get("timeout", 2))
        send_rst = strategy.get("send_rst", False)

        port_results = []

        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id,
                                  'message': f"[{time.ctime()}] Début du scan Pcap2 ({scan_type}) de {ip} avec {len(ports_to_scan)} ports"}})

        for port in ports_to_scan:
            if stop_flag():
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
                break  # Sortir de la boucle

            if strategy.get("timing_pattern"):
                actual_delay = AdvancedEvasion.get_polymorphic_delay(
                    ports_to_scan.index(port), delay, strategy["timing_pattern"]
                )
            else:
                actual_delay = random.uniform(0, delay)
            time.sleep(actual_delay)

            sport = self._get_source_port(strategy)
            self._send_decoys(ip, port, strategy, sport)

            try:
                packet = self._build_packet(ip, port, strategy, sport)
            except Exception as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur build packet: {e}"}})
                continue  # Passe au port suivant

            if strategy.get("advanced_evasion", False):
                packet = AdvancedEvasion.apply_advanced_evasion(packet, strategy)

            response = sr1(packet, timeout=timeout, verbose=0)

            status, is_open, flags_str = "unknown", False, "none"

            if response:
                # Une réponse a été reçue
                status, is_open, flags_str = self._interpret_response(response, scan_type)
            else:
                # Aucune réponse (Timeout)
                if scan_type in ["fin", "xmas", "null", "maimon"]:
                    status, is_open = "open|filtered", True
                else:  # SYN, ACK
                    status, is_open = "filtered", False
                flags_str = "none"

            # Stocker le résultat
            port_data = {"port": port, "status": status, "response_flags": flags_str}

            if is_open:
                port_results.append(port_data)  # Ajouter le dictionnaire
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Port {port} {status} (flags: {flags_str})"}})

                if send_rst and scan_type == "syn" and response and response.haslayer(TCP):
                    self._send_rst(ip, port, sport, response[TCP].ack)
            else:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Port {port} {status} (flags: {flags_str})"}})

        sorted_results = sorted(port_results, key=lambda p: p['port'])
        details = {"ports": sorted_results}

        if port_results:
            open_ports_list = [p['port'] for p in port_results]
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} actif (ports: {open_ports_list})"}})
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} n'a pas de ports ouverts"}})

        # Gérer le cas "Cancelled"
        if stop_flag():
            return ip, False, "Cancelled", details, None

        return ip, True, None, details, None

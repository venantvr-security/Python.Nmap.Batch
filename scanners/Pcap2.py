import os
import random
import sys
import time
from typing import Dict, List

import yaml
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.sendrecv import send
from scapy.utils import rdpcap

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
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
    def _load_and_modify_packets(self, strategy: Dict, ip: str, port: int, sport: int):
        """Charge tous les paquets d'un fichier PCAP et les modifie pour la cible."""
        template_name = strategy.get("template_pcap")
        template_path = os.path.join(PCAP_TEMPLATES_DIR, template_name)

        try:
            template_packets = rdpcap(template_path)
            if not template_packets:
                raise ValueError(f"Le fichier template {template_name} est vide.")

            modified_packets = []
            for pkt in template_packets:
                pkt_copy = pkt.copy()

                # Modifier l'IP de destination
                if pkt_copy.haslayer(IP):
                    pkt_copy[IP].dst = ip
                    # Supprimer l'IP source pour utiliser celle de la machine
                    if pkt_copy[IP].src:
                        del pkt_copy[IP].src
                    del pkt_copy[IP].chksum

                # Modifier le port de destination si TCP
                if pkt_copy.haslayer(TCP):
                    pkt_copy[TCP].dport = port
                    pkt_copy[TCP].sport = sport
                    del pkt_copy[TCP].chksum

                modified_packets.append(pkt_copy)

            return modified_packets

        except FileNotFoundError:
            raise FileNotFoundError(f"Fichier template PCAP introuvable : {template_path}")

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


    # noinspection PyTypeHints
    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> ScanResult:
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, None

        strategy = self.strategies[self.strategy]
        scan_type = strategy.get("scan_type", "syn")

        if strategy.get("ports") == "<ports>" and self.ports:
            try:
                ports_to_scan = self.parse_ports(self.ports)
            except ValueError as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur parsing ports: {str(e)}"}})
                return ip, False, f"Invalid ports: {str(e)}", {}, None
        else:
            try:
                port = int(strategy.get("ports", 443))
                ports_to_scan = [port]
            except ValueError:
                ports_to_scan = [443]

        delay = float(strategy.get("delay", 0.5))
        inter_packet_delay = float(strategy.get("inter_packet_delay", 0.001))  # Délai entre paquets

        port_results = []

        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id,
                                  'message': f"[{time.ctime()}] Début du scan Pcap2 ({scan_type}) de {ip} avec {len(ports_to_scan)} ports"}})

        for port_index, port in enumerate(ports_to_scan):
            if stop_flag():
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
                break  # Sortir de la boucle

            if strategy.get("timing_pattern"):
                actual_delay = AdvancedEvasion.get_polymorphic_delay(
                    port_index, delay, strategy["timing_pattern"]
                )
            else:
                actual_delay = random.uniform(0, delay)
            time.sleep(actual_delay)

            sport = self._get_source_port(strategy)
            self._send_decoys(ip, port, strategy, sport)

            try:
                # Charger et modifier TOUS les paquets du fichier PCAP
                packets = self._load_and_modify_packets(strategy, ip, port, sport)

                # Validation : vérifier que des paquets ont été chargés
                if not packets:
                    event_queue.put({'event': 'thread_update',
                                     'data': {'thread_id': thread_id,
                                              'message': f"[{time.ctime()}] Aucun paquet dans le template PCAP pour {ip}:{port}"}})
                    continue

                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Envoi de {len(packets)} paquets vers {ip}:{port}"}})

                # Envoyer tous les paquets sans attendre de réponse (mode replay)
                for pkt in packets:
                    if stop_flag():
                        break

                    if strategy.get("advanced_evasion", False):
                        pkt = AdvancedEvasion.apply_advanced_evasion(pkt, strategy)

                    send(pkt, verbose=0)
                    time.sleep(inter_packet_delay)

                # Marquer le port comme "sent" (pas de détection d'ouverture)
                port_data = {"port": port, "status": "sent", "response_flags": "none", "packets_sent": len(packets)}
                port_results.append(port_data)

                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Port {port} - {len(packets)} paquets envoyés"}})

            except Exception as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur envoi packets: {e}"}})
                continue
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

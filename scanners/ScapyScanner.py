import os
import random
# Import local
import sys
import time
from typing import Dict, List, Tuple, Union

import yaml
from scapy.layers.inet import IP, TCP, fragment
from scapy.packet import Raw, Packet
from scapy.sendrecv import sr1, send

from ScannerInterface import ScannerInterface, ScanResult

sys.path.insert(0, os.path.dirname(__file__))
from AdvancedEvasion import AdvancedEvasion


class ScapyScanner(ScannerInterface):
    # Mapping des types de scan vers flags TCP
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
        """Génère une IP aléatoire pour decoys"""
        return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    # noinspection PyMethodMayBeStatic
    def _get_source_port(self, strategy: Dict) -> int:
        """Détermine le port source selon la stratégie"""
        src_ports = strategy.get("src_ports")
        if isinstance(src_ports, list):
            return random.choice(src_ports)
        return random.randint(1024, 65535)

    # noinspection PyMethodMayBeStatic
    def _get_ttl(self, strategy: Dict) -> int:
        """Détermine le TTL selon la stratégie"""
        base_ttl = strategy.get("ttl", 64)
        if strategy.get("randomize_ttl", False):
            return random.randint(base_ttl - 10, base_ttl + 10)
        return base_ttl

    def _build_packet(self, ip: str, port: int, strategy: Dict, sport: int) -> Union[Packet, List[Packet]]:
        """Construit le paquet IP/TCP selon la stratégie"""
        scan_type = strategy.get("scan_type", "syn")
        tcp_flags = self.SCAN_FLAGS.get(scan_type, "S")
        ttl = self._get_ttl(strategy)
        window = strategy.get("window_size", 1024)

        # Construction paquet de base
        ip_layer = IP(dst=ip, ttl=ttl)
        tcp_layer = TCP(sport=sport, dport=port, flags=tcp_flags, window=window)
        packet = ip_layer / tcp_layer

        # Ajout padding si spécifié
        padding = strategy.get("padding", 0)
        if padding > 0:
            packet = packet / Raw(b"X" * padding)

        # Fragmentation si demandée
        if strategy.get("fragment", False):
            # Fragment en morceaux de 8 octets
            fragments = fragment(packet, fragsize=8)
            return fragments if isinstance(fragments, list) else [fragments]

        return packet

    def _send_decoys(self, ip: str, port: int, strategy: Dict, sport: int):
        """Envoie des paquets decoys"""
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
        """Envoie un RST pour fermer proprement la connexion"""
        rst_packet = IP(dst=ip) / TCP(sport=sport, dport=port, flags="R", seq=ack_seq)
        send(rst_packet, verbose=0)

    # noinspection PyMethodMayBeStatic
    def _interpret_response(self, response, scan_type: str) -> Tuple[str, bool, str]:
        """Interprète la réponse selon le type de scan et retourne (status, is_open, flags_str)"""
        # Note: Cette fonction assume que 'response' n'est PAS None.

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

        # Récupérer la stratégie
        strategy = self.strategies[self.strategy]
        scan_type = strategy.get("scan_type", "syn")

        # Parser les ports
        if strategy.get("ports") == "<ports>" and self.ports:
            ports_to_scan = self.parse_ports(self.ports)
        else:
            try:
                port = int(strategy.get("ports", 443))
                ports_to_scan = [port]
            except ValueError:
                ports_to_scan = [443]

        # Extraire paramètres
        delay = float(strategy.get("delay", 0.5))
        timeout = float(strategy.get("timeout", 2))
        send_rst = strategy.get("send_rst", False)

        port_results = []

        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id,
                                  'message': f"[{time.ctime()}] Début du scan Scapy ({scan_type}) de {ip} avec {len(ports_to_scan)} ports"}})

        # Boucler sur chaque port
        for port in ports_to_scan:
            if stop_flag():
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
                break  # Sortir de la boucle

            # ... (logique de délai, decoys, construction de paquet reste identique) ...
            if strategy.get("timing_pattern"):
                actual_delay = AdvancedEvasion.get_polymorphic_delay(
                    ports_to_scan.index(port), delay, strategy["timing_pattern"]
                )
            else:
                actual_delay = random.uniform(0, delay)
            time.sleep(actual_delay)
            sport = self._get_source_port(strategy)
            self._send_decoys(ip, port, strategy, sport)
            packet = self._build_packet(ip, port, strategy, sport)
            if strategy.get("advanced_evasion", False):
                if isinstance(packet, list):
                    packet = [AdvancedEvasion.apply_advanced_evasion(p, strategy) for p in packet]
                else:
                    packet = AdvancedEvasion.apply_advanced_evasion(packet, strategy)
            if isinstance(packet, list):
                for frag in packet[:-1]:
                    send(frag, verbose=0)
                response = sr1(packet[-1], timeout=timeout, verbose=0)
            else:
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
                # Log mais ne stocke pas les ports fermés/filtrés (sauf si vous le souhaitez)
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Port {port} {status} (flags: {flags_str})"}})

        # Trier les résultats par numéro de port
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

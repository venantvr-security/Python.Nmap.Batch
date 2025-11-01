import random
import time
from typing import Dict

import yaml
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from ScannerInterface import ScannerInterface, ScanResult


class ScapyScanner(ScannerInterface):
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

    # noinspection PyTypeHints
    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> ScanResult:
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, None

        # Récupérer la stratégie (un dictionnaire)
        strategy = self.strategies[self.strategy]

        # Vérifier si <ports> est présent dans la stratégie et utiliser self.ports
        if strategy.get("ports") == "<ports>" and self.ports:
            ports_to_scan = self.parse_ports(self.ports)  # Utiliser parse_ports de la classe mère
        else:
            # Sinon, utiliser la valeur de "ports" dans la stratégie ou un défaut
            try:
                port = int(strategy.get("ports", 443))
                ports_to_scan = [port]
            except ValueError:
                ports_to_scan = [443]  # Port par défaut si non spécifié ou invalide
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Port non spécifié ou invalide, utilisation par défaut : 443"}})

        # Extraire delay et timeout de la stratégie (valeurs par défaut si absentes)
        delay = float(strategy.get("delay", 0.5))
        timeout = float(strategy.get("timeout", 2))

        # Initialiser les résultats globaux
        all_ports = []

        # Boucler sur chaque port à scanner
        for port in ports_to_scan:
            if stop_flag():
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
                return ip, False, "Cancelled", {"ports": all_ports}, None

            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Début du scan de {ip}:{port} avec Scapy (delay={delay}, timeout={timeout})"}})

            time.sleep(random.uniform(0, delay))
            packet = IP(dst=ip) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            response = sr1(packet, timeout=timeout, verbose=0)

            if response:
                if response.haslayer(TCP) and response[TCP].flags & 0x12 == 0x12:  # SYN-ACK
                    event_queue.put({'event': 'thread_update',
                                     'data': {'thread_id': thread_id,
                                              'message': f"[{time.ctime()}] Port {port} ouvert"}})
                    all_ports.append(port)
                elif response[TCP].flags & 0x14 == 0x14:  # RST-ACK
                    event_queue.put({'event': 'thread_update',
                                     'data': {'thread_id': thread_id,
                                              'message': f"[{time.ctime()}] Port {port} fermé"}})
                else:
                    event_queue.put({'event': 'thread_update',
                                     'data': {'thread_id': thread_id,
                                              'message': f"[{time.ctime()}] Port {port} réponse inattendue"}})
            else:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Port {port} filtré ou pas de réponse"}})

        # Résultats finaux
        details = {"ports": sorted(list(set(all_ports)))}
        if all_ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} actif (ports: {all_ports})"}})
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
        return ip, True, None, details, None

# ScapyScanner.py
import random
import time
from typing import Dict, Tuple, Optional

import yaml
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1

from ScannerInterface import ScannerInterface


class ScapyScanner(ScannerInterface):
    def _load_strategies(self) -> Dict[str, Dict[str, any]]:
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

    # noinspection PyTypeChecker
    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> Tuple[str, bool, Optional[str], Dict, Optional[str]]:
        # Tuple[str, bool, Optional[str], Dict, Optional[str]]
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, None

        strategy_params = self.strategies[self.strategy]
        port = int(strategy_params.get("port", 443))
        delay = float(strategy_params.get("delay", 0.5))
        timeout = float(strategy_params.get("timeout", 2))

        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Début du scan de {ip}:{port} avec Scapy"}})

        time.sleep(random.uniform(0, delay))
        packet = IP(dst=ip) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)

        if response:
            if response.haslayer(TCP) and response[TCP].flags & 0x12 == 0x12:  # SYN-ACK
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Port {port} ouvert"}})
                return ip, True, None, {"ports": [port]}, None
            elif response[TCP].flags & 0x14 == 0x14:  # RST-ACK
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Port {port} fermé"}})
                return ip, True, None, {"ports": []}, None
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Port {port} filtré ou pas de réponse"}})
            return ip, True, None, {"ports": []}, None

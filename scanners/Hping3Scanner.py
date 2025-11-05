import os
import sys
import time
from typing import List, Dict

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from BaseSubprocessScanner import BaseSubprocessScanner
from ScannerInterface import ScanResult


class Hping3Scanner(BaseSubprocessScanner):

    def load_strategies(self) -> Dict[str, List[str]]:
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
            return ip, False, "Cancelled", {}, {}

        # Récupérer la stratégie
        strategy = self.strategies[self.strategy]

        # Vérifier si <ports> est présent et utiliser self.ports
        if '<ports>' in strategy and self.ports:
            try:
                ports_to_scan = self.parse_ports(self.ports)
            except ValueError as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur parsing ports: {str(e)}"}})
                return ip, False, f"Invalid ports: {str(e)}", {}, {}
        else:
            # Sinon, chercher -p dans la stratégie
            try:
                port_index = strategy.index('-p') + 1
                port = int(strategy[port_index])
                ports_to_scan = [port]
            except (ValueError, IndexError):
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur : Port non spécifié dans la stratégie"}})
                return ip, False, "No port specified", {}, {}

        # Initialiser les résultats globaux
        all_ports = []
        all_commands = []

        # Boucler sur chaque port à scanner
        for port in ports_to_scan:
            if stop_flag():
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
                return ip, False, "Cancelled", {"ports": all_ports}, {"commands": all_commands}

            # Construire la commande en remplaçant <ports> par le port actuel
            cmd_template = [arg if arg != '<ports>' else str(port) for arg in strategy]

            try:
                hping3_path = self._get_command_path("hping3", ["/usr/sbin/hping3", "/usr/bin/hping3"])
            except FileNotFoundError as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] {str(e)}"}})
                return ip, False, str(e), {"ports": all_ports}, {"commands": all_commands}

            cmd = [hping3_path] + [ip] + cmd_template + ["-c", "10"]  # Limite à 10 paquets

            # Utiliser la méthode factorisée _run_command
            success, error, output_lines = self._run_command(
                cmd=cmd,
                ip=ip,
                port=port,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag,
                timeout=5,
                capture_output=True
            )

            all_commands.append(" ".join(cmd))

            if not success:
                continue

            # Traitement des lignes pour ce port
            self._send_output_to_queue(output_lines, thread_id, event_queue)

            for line in output_lines:
                if "flags=SA" in line:  # Réponse SYN-ACK indique un port ouvert
                    all_ports.append(port)
                    break

        # Résultats finaux
        details = {"ports": sorted(set(all_ports))}
        if all_ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} actif (ports: {all_ports})"}})
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
        return ip, True, None, details, {"commands": all_commands}

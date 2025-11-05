import os
import sys
import time
from typing import List, Dict

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from BaseSubprocessScanner import BaseSubprocessScanner
from ScannerInterface import ScanResult


class NetcatScanner(BaseSubprocessScanner):

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
                port_index = strategy.index("-p")
                if port_index + 1 < len(strategy):  # Vérifier qu’il y a une valeur après -p
                    port = int(strategy[port_index + 1])
                    ports_to_scan = [port]
                else:
                    raise IndexError("Option -p présente mais aucun port spécifié après")
            except (ValueError, IndexError):
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur : Port non spécifié ou mal formé dans la stratégie"}})
                return ip, False, "No port specified or malformed strategy", {}, {}

        # Initialiser les résultats globaux
        all_ports = []
        all_commands = []

        # Boucler sur chaque port à scanner
        for port in ports_to_scan:
            if stop_flag():
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
                return ip, False, "Cancelled", {"ports": all_ports}, {"commands": all_commands}

            # Construire la commande : le port doit être après l’IP
            cmd_template = [arg for arg in strategy if arg != '<ports>']  # Retirer <ports> si présent
            if "-p" in cmd_template:
                port_index = cmd_template.index("-p")
                if port_index + 1 < len(cmd_template):  # Vérifier qu’il y a une valeur après -p
                    cmd_template.pop(port_index + 1)  # Retirer la valeur après -p
                cmd_template.pop(port_index)  # Retirer -p

            # Construire la commande finale sans sudo
            try:
                nc_path = self._get_command_path("nc", ["/bin/nc", "/usr/bin/nc"])
            except FileNotFoundError as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] {str(e)}"}})
                return ip, False, str(e), {"ports": all_ports}, {"commands": all_commands}

            cmd = [nc_path] + cmd_template + [ip, str(port)]

            # Utiliser la méthode factorisée _run_command
            success, error, output_lines = self._run_command(
                cmd=cmd,
                ip=ip,
                port=port,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag,
                timeout=10,
                capture_output=True
            )

            all_commands.append(" ".join(cmd))

            if not success:
                continue

            # Parsing de la sortie Netcat pour ce port
            self._send_output_to_queue(output_lines, thread_id, event_queue)

            for line in output_lines:
                if "open" in line.lower() or "succeeded" in line.lower():
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

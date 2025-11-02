import subprocess
import time
from typing import List, Dict

import yaml

from ScannerInterface import ScannerInterface, ScanResult


class Hping3Scanner(ScannerInterface):

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
            ports_to_scan = self.parse_ports(self.ports)  # Utiliser parse_ports de la classe mère
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
            cmd = ["/usr/sbin/hping3"] + [ip] + cmd_template + ["-c", "10"]  # Limite à 10 paquets
            cmd_str = " ".join(cmd)
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Début du scan de {ip}:{port} avec {cmd_str}"}})

            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

                if self.process_manager is not None:
                    if isinstance(self.process_manager, list):
                        self.process_manager.append(process)
                    else:
                        self.process_manager.register(process, "hping3", self.strategy, ip, thread_id)
            except Exception as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur lancement Hping3 : {str(e)}"}})
                return ip, False, str(e), {"ports": all_ports}, {"commands": all_commands + [cmd_str]}

            try:
                stdout, _ = process.communicate(timeout=5)  # 5 secondes max par port
                output_lines = stdout.splitlines()
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Scan terminé pour port {port}"}})
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, _ = process.communicate()
                output_lines = stdout.splitlines()
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Scan timeout après 5s pour port {port}"}})
                return ip, False, "Timeout", {"ports": all_ports}, {"commands": all_commands + [cmd_str]}

            # Traitement des lignes pour ce port
            for line in output_lines:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}})
                if "flags=SA" in line:  # Réponse SYN-ACK indique un port ouvert
                    all_ports.append(port)

            all_commands.append(cmd_str)

        # Résultats finaux
        details = {"ports": list(set(all_ports))}
        if all_ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} actif (ports: {all_ports})"}})
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
        return ip, True, None, details, {"commands": all_commands}

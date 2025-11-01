import os
import subprocess
import time
from typing import List, Dict

import yaml

from ScannerInterface import ScannerInterface, ScanResult


# echo "rvv ALL=(ALL) NOPASSWD: /bin/nc" | sudo tee -a /etc/sudoers.d/netcat
# sudo chmod 440 /etc/sudoers.d/netcat
class NetcatScanner(ScannerInterface):
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

            # Vérifier si déjà root
            if os.geteuid() == 0:
                cmd = ["/bin/nc"] + cmd_template + [ip, str(port)]
            else:
                cmd = ["/usr/bin/sudo", "/bin/nc"] + cmd_template + [ip, str(port)]

            cmd_str = " ".join(cmd)
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Début du scan de {ip}:{port} avec {cmd_str}"}})

            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                self.active_processes.append(process)

                # Enregistrer dans ProcessManager
                try:
                    from main import process_manager

                    scanner_type = "netcat"
                    process_manager.register(process, scanner_type, self.strategy, ip, thread_id)
                except Exception:
                    pass
            except Exception as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur lancement Netcat : {str(e)}"}})
                return ip, False, str(e), {"ports": all_ports}, {"commands": all_commands + [cmd_str]}

            try:
                stdout, stderr = process.communicate(timeout=10)  # Timeout ajusté pour Netcat
                output_lines = stdout.splitlines() + (stderr.splitlines() if stderr else [])
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Scan terminé pour port {port}"}})
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                output_lines = stdout.splitlines() + (stderr.splitlines() if stderr else [])
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Scan timeout après 10s pour port {port}"}})
                self.active_processes.remove(process)
                return ip, False, "Timeout", {"ports": all_ports}, {"commands": all_commands + [cmd_str]}

            self.active_processes.remove(process)

            # Parsing de la sortie Netcat pour ce port
            for line in output_lines:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}})
                if "open" in line.lower() or "succeeded" in line.lower():
                    all_ports.append(port)

            all_commands.append(cmd_str)

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
        return ip, True, None, details, {"commands": all_commands}

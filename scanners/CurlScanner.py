import subprocess
import time
from typing import List, Dict

import yaml

from ScannerInterface import ScannerInterface, ScanResult


class CurlScanner(ScannerInterface):
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

    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> ScanResult:
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, {}

        # Récupérer les paramètres de la stratégie
        strategy = self.strategies[self.strategy]

        # Vérifier si self.ports est défini (requis par le frontend)
        if not self.ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Erreur : Aucun port spécifié via l’interface"}})
            return ip, False, "No ports specified from interface", {}, {}

        # Trouver l’URL de base dans la stratégie (ex. "http://<ip>:<ports>")
        url_base = next((arg for arg in strategy if '<ip>' in arg), None)
        if not url_base or '<ports>' not in url_base:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Erreur : <ports> ou <ip> manquant dans l’URL de la stratégie"}})
            return ip, False, "Invalid strategy: missing <ports> or <ip> in URL", {}, {}

        ports_to_scan = self.parse_ports(self.ports)  # Utiliser parse_ports de la classe mère

        # Initialiser les résultats globaux
        all_ports = []
        all_outputs = []

        # Boucler sur chaque port à scanner
        for port in ports_to_scan:
            if stop_flag():
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
                return ip, False, "Cancelled", {"ports": all_ports}, {"commands": all_outputs}

            # Construire l’URL avec l’IP et le port actuel
            url = url_base.replace("<ip>", ip).replace("<ports>", str(port))

            # Construire la commande en remplaçant l’URL de base par l’URL complète
            cmd_template = [arg if arg != url_base else url for arg in strategy]
            cmd = ["/usr/bin/curl"] + cmd_template
            cmd_str = " ".join(cmd)
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Début du scan de {ip}:{port} avec {cmd_str}"}})

            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                self.active_processes.append(process)
            except Exception as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur lancement curl : {str(e)}"}})
                return ip, False, str(e), {"ports": all_ports}, {"commands": all_outputs + [cmd_str]}

            try:
                stdout, _ = process.communicate(timeout=5)
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
                self.active_processes.remove(process)
                return ip, False, "Timeout", {"ports": all_ports}, {"commands": all_outputs + [cmd_str]}

            self.active_processes.remove(process)

            # Traitement des lignes pour ce port
            for line in output_lines:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}})
                if line.startswith("HTTP/") and (" 2" in line or " 3" in line):  # Codes 2xx ou 3xx
                    all_ports.append(port)

            all_outputs.append(cmd_str)

        # Résultats finaux
        details = {"ports": all_ports}
        if all_ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} actif (ports: {all_ports})"}})
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
        return ip, True, None, details, {"commands": all_outputs}

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

        # Extraire le port depuis -p
        try:
            port_index = strategy.index("-p") + 1
            port = int(strategy[port_index])
        except (ValueError, IndexError):
            port = 80  # Port par défaut si -p est absent ou invalide
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Port non spécifié, utilisation par défaut : {port}"}})

        # Construire l’URL avec l’IP et le port
        url_base = next((arg for arg in strategy if arg.startswith("http")), "http://<ip>")
        url = url_base.replace("<ip>", ip) + f":{port}"

        # Construire la commande en remplaçant l’URL
        cmd_template = [arg for arg in strategy if arg not in ["-p", str(port)]]  # Retirer -p et le port
        cmd = ["/usr/bin/curl"] + [arg.replace(url_base, url) if arg == url_base else arg for arg in cmd_template]
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
            return ip, False, str(e), {}, {"command": cmd_str}

        ports = []
        try:
            stdout, _ = process.communicate(timeout=5)
            output_lines = stdout.splitlines()
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan terminé"}})
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, _ = process.communicate()
            output_lines = stdout.splitlines()
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Scan timeout après 5s"}})
            self.active_processes.remove(process)
            return ip, False, "Timeout", {}, {"command": cmd_str}

        self.active_processes.remove(process)

        # Traitement des lignes
        for line in output_lines:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}})
            if line.startswith("HTTP/") and (" 2" in line or " 3" in line):  # Codes 2xx ou 3xx
                ports.append(port)

        details = {"ports": ports}
        if ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} actif (ports: {ports})"}})
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
        return ip, True, None, details, {"command": cmd_str}

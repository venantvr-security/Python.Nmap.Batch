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

    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> ScanResult:
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, {}

        # Utiliser Netcat au lieu de Nmap
        cmd = ["/usr/bin/sudo", "/bin/nc"] + self.strategies[self.strategy] + [ip]
        # Ajuster pour que le port soit en dernier (Netcat attend "ip port")
        port_index = cmd.index("-p") + 1 if "-p" in cmd else -1
        if 0 < port_index < len(cmd) - 1:
            port = cmd.pop(port_index)  # Retire le port
            cmd.pop(port_index - 1)  # Retire "-p"
            cmd.append(port)  # Ajoute le port à la fin

        cmd_str = " ".join(cmd)
        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id,
                                  'message': f"[{time.ctime()}] Début du scan de {ip} avec {cmd_str}"}})

        try:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Lancement de Popen"}})
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.active_processes.append(process)
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Popen lancé avec succès"}})
        except Exception as e:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Erreur lancement Netcat : {str(e)}"}})
            return ip, False, str(e), {}, {"command": cmd_str}

        ports = []
        extra = {"command": cmd_str}

        try:
            stdout, stderr = process.communicate(timeout=10)  # Timeout ajusté pour Netcat
            output_lines = stdout.splitlines() + (stderr.splitlines() if stderr else [])
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Communicate terminé"}})
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            # noinspection PyUnusedLocal
            output_lines = stdout.splitlines() + (stderr.splitlines() if stderr else [])
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Scan timeout après 10s"}})
            self.active_processes.remove(process)
            return ip, False, "Timeout", {}, extra

        self.active_processes.remove(process)

        # Parsing de la sortie Netcat
        for line in output_lines:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}})
            if "open" in line.lower() or "succeeded" in line.lower():
                try:
                    port = int(cmd[-1])  # Le dernier argument est le port
                    ports.append(port)
                except ValueError:
                    pass

        if process.returncode == 0:
            details = {"ports": ports}
            if ports:
                event_queue.put({'event': 'thread_update', 'data': {
                    'thread_id': thread_id,
                    'message': f"[{time.ctime()}] {ip} actif (ports: {ports})"
                }})
            else:
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id,
                                                                    'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
            return ip, True, None, details, extra
        else:
            error = f"Netcat a échoué avec le code {process.returncode}"
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error}"}})
            return ip, False, error, {}, extra

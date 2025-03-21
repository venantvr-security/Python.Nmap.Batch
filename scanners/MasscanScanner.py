# MasscanScanner.py
import subprocess
import time
from typing import List, Dict

import yaml

from ScannerInterface import ScannerInterface, ScanResult


class MasscanScanner(ScannerInterface):
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

        cmd = ["/usr/bin/masscan"] + [ip] + self.strategies[self.strategy]
        cmd_str = " ".join(cmd)  # Commande sous forme de chaîne pour persistance
        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id,
                                  'message': f"[{time.ctime()}] Début du scan de {ip} avec {cmd_str}"}})

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(process)
        except Exception as e:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Erreur lancement Masscan : {e}"}})
            return ip, False, str(e), {}, {}

        ports = []
        buffer = []
        last_emit = time.time()

        for line in iter(process.stdout.readline, ''):
            if stop_flag():
                process.terminate()
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan interrompu"}})
                self.active_processes.remove(process)
                return ip, False, "Interrupted", {}, {}
            buffer.append(f"[{time.ctime()}] {line.strip()}")

            if "open" in line:
                try:
                    port = int(line.split()[3].split('/')[0])
                    ports.append(port)
                except (IndexError, ValueError):
                    pass

            if time.time() - last_emit >= 0.5:
                event_queue.put(
                    {'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})
                buffer = []
                last_emit = time.time()

        if buffer:
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})

        process.wait()
        self.active_processes.remove(process)
        if process.returncode == 0:
            details = {"ports": ports}
            if ports:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Ports ouverts : {ports}"}})
            else:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Aucun port ouvert"}})
            return ip, True, None, details, {"command": cmd_str}
        else:
            error = f"Masscan a échoué avec le code {process.returncode}"
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error}"}})
            return ip, False, error, {}, {"command": cmd_str}

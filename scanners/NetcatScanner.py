# NetcatScanner.py
import random
import subprocess
import time
from typing import List, Dict, Tuple, Optional

import yaml

from ScannerInterface import ScannerInterface


class NetcatScanner(ScannerInterface):
    def _load_strategies(self) -> Dict[str, List[str]]:
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

    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> Tuple[str, bool, Optional[str], Dict, Optional[str]]:
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, None

        cmd = ["/usr/bin/nc"] + self.strategies[self.strategy] + [ip]
        delay = random.uniform(0.5, 2.0)
        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Attente aléatoire de {delay:.2f}s pour {ip}"}})
        time.sleep(delay)

        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Début du scan de {ip} avec {cmd}"}})

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(process)
        except Exception as e:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Erreur lancement Netcat : {e}"}})
            return ip, False, str(e), {}, None

        ports = []
        buffer = []
        last_emit = time.time()

        for line in iter(process.stdout.readline, ''):
            if stop_flag():
                process.terminate()
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan interrompu"}})
                self.active_processes.remove(process)
                return ip, False, "Interrupted", {}, None
            buffer.append(f"[{time.ctime()}] {line.strip()}")

            if "succeeded" in line or "open" in line:
                try:
                    port = int(self.strategies[self.strategy][-1])
                    ports.append(port)
                except ValueError:
                    pass

            if time.time() - last_emit >= 0.5:
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})
                buffer = []
                last_emit = time.time()

        if buffer:
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})

        process.wait()
        self.active_processes.remove(process)
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
            return ip, True, None, details, None
        else:
            error = f"Netcat a échoué avec le code {process.returncode}"
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error}"}})
            return ip, False, error, {}, None

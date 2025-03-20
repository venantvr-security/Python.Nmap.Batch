# Hping3Scanner.py
import subprocess
import time
from typing import List, Dict, Tuple, Optional

import yaml

from ScannerInterface import ScannerInterface


class Hping3Scanner(ScannerInterface):
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

        cmd = ["/usr/bin/hping3"] + [ip] + self.strategies[self.strategy]
        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Début du scan de {ip} avec {cmd}"}})

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(process)
        except Exception as e:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Erreur lancement Hping3 : {e}"}})
            return ip, False, str(e), {}, None

        ports = []
        buffer = []
        last_emit = time.time()
        port = int(self.strategies[self.strategy][self.strategies[self.strategy].index('-p') + 1])

        start_time = time.time()
        while time.time() - start_time < 5:  # Limite à 5 secondes
            if stop_flag():
                process.terminate()
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan interrompu"}})
                self.active_processes.remove(process)
                return ip, False, "Interrupted", {}, None

            line = process.stdout.readline()
            if not line:
                break
            buffer.append(f"[{time.ctime()}] {line.strip()}")

            if "flags=SA" in line:
                ports.append(port)

            if time.time() - last_emit >= 0.5:
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})
                buffer = []
                last_emit = time.time()

        process.terminate()
        self.active_processes.remove(process)

        details = {"ports": ports}
        if ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Port {port} ouvert"}})
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Aucun port ouvert ou filtré"}})
        return ip, True, None, details, None

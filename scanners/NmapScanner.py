# NmapScanner.py
import subprocess
import time
from typing import List, Dict, Tuple, Optional

import yaml

from ScannerInterface import ScannerInterface


class NmapScanner(ScannerInterface):
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

    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> Tuple[str, bool, Optional[str], Dict, Optional[str]]:
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, None

        cmd = ["/usr/bin/nmap"] + [ip] + self.strategies[self.strategy]
        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Début du scan de {ip} avec {cmd}"}})

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            self.active_processes.append(process)
        except Exception as e:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Erreur lancement Nmap : {e}"}})
            return ip, False, str(e), {}, None

        output_lines = []
        ports = []
        os_info = None
        versions = {}
        vulns = []
        buffer = []
        last_emit = time.time()

        for line in iter(process.stdout.readline, ''):
            if stop_flag():
                process.terminate()
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan interrompu"}})
                self.active_processes.remove(process)
                return ip, False, "Interrupted", {}, None
            output_lines.append(line.strip())
            buffer.append(f"[{time.ctime()}] {line.strip()}")

            if time.time() - last_emit >= 0.5:
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})
                buffer = []
                last_emit = time.time()

            if "open port" in line:
                try:
                    port = int(line.split()[4].split('/')[0])
                    ports.append(port)
                except (IndexError, ValueError):
                    pass
            if "OS details" in line:
                os_info = line.split("OS details: ")[1].strip()
            if "Service Info" in line or ("open" in line and "/" in line and "version" not in line.lower()):
                parts = line.split()
                if len(parts) > 2 and "/" in parts[0]:
                    try:
                        port = int(parts[0].split('/')[0])
                        version = " ".join(parts[2:]) if len(parts) > 2 else "Unknown"
                        versions[port] = version
                    except (IndexError, ValueError):
                        pass
            if "VULNERABLE" in line:
                vulns.append(line.strip())

        if buffer:
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})

        process.wait()
        self.active_processes.remove(process)
        if process.returncode == 0:
            details = {"ports": ports, "os": os_info, "versions": versions, "vulns": vulns}
            if ports:
                event_queue.put({'event': 'thread_update', 'data': {
                    'thread_id': thread_id,
                    'message': f"[{time.ctime()}] {ip} actif (ports: {ports}, OS: {os_info}, Vulns: {len(vulns)})"
                }})
            else:
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id,
                                                                    'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
            return ip, True, None, details, None
        else:
            error = f"Nmap a échoué avec le code {process.returncode}"
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error}"}})
            return ip, False, error, {}, None
# NetcatScanner.py
import subprocess
import time
from typing import List, Dict

import yaml

from ScannerInterface import ScannerInterface, ScanResult


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

        cmd = ["/usr/bin/nmap"] + [ip] + self.strategies[self.strategy]
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
                                      'message': f"[{time.ctime()}] Erreur lancement Nmap : {str(e)}"}})
            return ip, False, str(e), {}, {"command": cmd_str}

        # output_lines = []
        ports = []
        os_info = None
        versions = {}
        vulns = []
        mac_address = None
        lan_name = None

        try:
            stdout, stderr = process.communicate(timeout=3600)
            output_lines = stdout.splitlines() + (stderr.splitlines() if stderr else [])
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Communicate terminé"}})
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            # output_lines = stdout.splitlines() + (stderr.splitlines() if stderr else [])
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Scan timeout après 3600s - Processus terminé"}})
            self.active_processes.remove(process)
            return ip, False, "Timeout", {}, {"command": cmd_str}

        self.active_processes.remove(process)
        # Traitement des lignes (inchangé)
        for line in output_lines:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}})
            if "open port" in line:
                try:
                    port = int(line.split()[4].split('/')[0])
                    ports.append(port)
                except (IndexError, ValueError):
                    pass
            if "OS details" in line:
                os_info = line.split("OS details: ")[1].strip()
            if "MAC Address" in line:
                mac_address = line.split("MAC Address: ")[1].split()[0]
            if "Nmap scan report for" in line and len(line.split()) > 4:
                lan_name = line.split()[4].strip("()")
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

        extra = {"command": cmd_str}
        if mac_address:
            extra["mac_address"] = mac_address
        if lan_name:
            extra["lan_name"] = lan_name

        if process.returncode == 0:
            details = {"ports": ports, "os": os_info, "versions": versions, "vulns": vulns}
            if ports:
                event_queue.put({'event': 'thread_update', 'data': {
                    'thread_id': thread_id,
                    'message': f"[{time.ctime()}] {ip} actif (ports: {ports}, OS: {os_info}, Vulns: {len(vulns)}, MAC: {mac_address}, LAN: {lan_name})"
                }})
            else:
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id,
                                                                    'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
            return ip, True, None, details, extra
        else:
            error = f"Nmap a échoué avec le code {process.returncode}"
            event_queue.put(
                {'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error}"}})
            return ip, False, error, {}, extra

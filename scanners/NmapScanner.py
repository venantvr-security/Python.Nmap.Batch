import time
from queue import Queue
from typing import List, Dict, Any, Callable

import yaml

from BaseSubprocessScanner import BaseSubprocessScanner
from scanners.ScannerInterface import ScanResult


class NmapScanner(BaseSubprocessScanner):

    def load_strategies(self) -> Dict[str, List[str]]:
        try:
            with open(self.yaml_file, 'r') as file:
                data = yaml.safe_load(file)
                if 'strategies' not in data:
                    raise KeyError
                return data['strategies']
        except FileNotFoundError:
            raise FileNotFoundError(f"Le fichier {self.yaml_file} n'a pas été trouvé.")
        except yaml.YAMLError as e:
            raise ValueError(f"Erreur lors du chargement du fichier YAML : {e}")
        except KeyError:
            raise ValueError(f"Le fichier {self.yaml_file} doit contenir une clé 'strategies'.")

    def scan(self, ip: str, thread_id: str, event_queue: Queue, stop_flag: Callable[[], bool]) -> ScanResult:
        if stop_flag():
            return ip, False, "Cancelled", {}, {}

        strategy: List[str] = self.strategies[self.strategy]
        cmd_template: List[str] = [arg if arg != '<ports>' else self.ports for arg in strategy] if self.ports and '<ports>' in strategy else strategy

        try:
            nmap_path: str = self._get_command_path("nmap", ["/usr/bin/nmap", "/usr/local/bin/nmap"])
        except FileNotFoundError as e:
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {e}"}})
            return ip, False, str(e), {}, {}

        cmd: List[str] = [nmap_path, ip] + cmd_template
        success, error, output_lines = self._run_command(
            cmd=cmd, ip=ip, port=None, thread_id=thread_id, event_queue=event_queue,
            stop_flag=stop_flag, timeout=3600
        )

        ports, os_info, versions, vulns, mac_address, lan_name = [], None, {}, [], None, None
        for line in output_lines:
            try:
                if "open port" in line or ("open" in line and "/" in line):
                    parts = line.split()
                    for part in parts:
                        if '/' in part and part.split('/')[0].isdigit():
                            port = int(part.split('/')[0])
                            if 1 <= port <= 65535:
                                ports.append(port)
                                if len(parts) > 2: versions[port] = " ".join(parts[2:])
                                break
                if "OS details:" in line:
                    os_info = line.split("OS details:")[1].strip()
                elif "Too many fingerprints match this host" in line:
                    os_info = "Too many fingerprints match this host"
                if "MAC Address:" in line and len(line.split("MAC Address:")) > 1: mac_address = line.split("MAC Address:")[1].split()[0]
                if "Nmap scan report for" in line and len(line.split()) > 4: lan_name = line.split()[4].strip("()")
                if "VULNERABLE" in line: vulns.append(line.strip())
            except (IndexError, ValueError):
                continue

        extra: Dict[str, Any] = {"command": " ".join(cmd)}
        if mac_address: extra["mac_address"] = mac_address
        if lan_name: extra["lan_name"] = lan_name

        details: Dict[str, Any] = {"ports": sorted(list(set(ports))), "os": os_info, "versions": versions, "vulns": vulns}
        if success and ports:
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {ip} actif (ports: {ports})"}})
            return ip, True, None, details, extra
        elif success:
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
            return ip, True, None, details, extra
        else:
            event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error}"}})
            return ip, False, error, {}, extra

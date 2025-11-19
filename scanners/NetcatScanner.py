import time
from queue import Queue
from typing import List, Dict, Callable, Any

import yaml

from BaseSubprocessScanner import BaseSubprocessScanner
from scanners.ScannerInterface import ScanResult


class NetcatScanner(BaseSubprocessScanner):

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
        ports_to_scan: List[int]

        if self.ports and '<ports>' in strategy:
            try:
                ports_to_scan = self.parse_ports(self.ports)
            except ValueError as e:
                error_msg: str = f"Invalid ports format: {e}"
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error_msg}"}})
                return ip, False, error_msg, {}, {}
        else:
            # Tente de trouver un port défini avec -p dans la stratégie
            try:
                port_index: int = strategy.index("-p")
                if port_index + 1 < len(strategy):
                    ports_to_scan = [int(strategy[port_index + 1])]
                else:
                    raise IndexError()
            except (ValueError, IndexError):
                error_msg = "Port non spécifié ou mal formé dans la stratégie"
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Erreur : {error_msg}"}})
                return ip, False, error_msg, {}, {}

        all_ports: List[int] = []
        all_commands: List[str] = []

        for port in ports_to_scan:
            if stop_flag():
                return ip, False, "Cancelled", {"ports": all_ports}, {"commands": all_commands}

            cmd_template: List[str] = [arg for arg in strategy if arg != '<ports>']
            if "-p" in cmd_template:
                try:
                    port_idx = cmd_template.index("-p")
                    if port_idx + 1 < len(cmd_template): cmd_template.pop(port_idx + 1)
                    cmd_template.pop(port_idx)
                except ValueError:
                    pass

            try:
                nc_path: str = self._get_command_path("nc", ["/bin/nc", "/usr/bin/nc"])
            except FileNotFoundError as e:
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {e}"}})
                return ip, False, str(e), {}, {}

            cmd: List[str] = [nc_path] + cmd_template + [ip, str(port)]
            success, _, output_lines = self._run_command(
                cmd=cmd, ip=ip, port=port, thread_id=thread_id, event_queue=event_queue,
                stop_flag=stop_flag, timeout=10
            )

            all_commands.append(" ".join(cmd))
            if not success:
                continue

            for line in output_lines:
                if "open" in line.lower() or "succeeded" in line.lower():
                    all_ports.append(port)
                    break

        details: Dict[str, Any] = {"ports": sorted(list(set(all_ports)))}
        return ip, True, None, details, {"commands": all_commands}

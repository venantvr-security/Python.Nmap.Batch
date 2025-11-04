import subprocess
import time
from typing import List, Dict

import yaml

from ScannerInterface import ScannerInterface, ScanResult


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

    # noinspection PyTypeHints
    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> ScanResult:
        if stop_flag():
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
            return ip, False, "Cancelled", {}, {}

        # Récupérer la stratégie et remplacer <ports> si présent
        strategy = self.strategies[self.strategy]
        if '<ports>' in strategy and self.ports:
            cmd_template = [arg if arg != '<ports>' else self.ports for arg in strategy]
        else:
            cmd_template = strategy  # Si pas de <ports>, utiliser la stratégie telle quelle

        # Construire la commande finale sans sudo
        cmd = ["/usr/bin/nmap"] + [ip] + cmd_template

        cmd_str = " ".join(cmd)
        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id,
                                  'message': f"[{time.ctime()}] Début du scan de {ip} avec {cmd_str}"}})

        output_lines = []
        ports = []
        os_info = None
        versions = {}
        vulns = []
        mac_address = None
        lan_name = None

        try:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Lancement de Popen"}})

            # MODIFIÉ : Utiliser PIPE au lieu d'un fichier temporaire
            # bufsize=1 pour forcer le line-buffering
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if self.process_manager is not None:
                if isinstance(self.process_manager, list):
                    self.process_manager.append(process)
                else:
                    self.process_manager.register(process, "nmap", self.strategy, ip, thread_id)

            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Popen lancé (PID: {process.pid}), streaming output..."}})

            buffer = []
            last_emit = time.time()
            start_time = time.time()
            timeout_seconds = 3600  # 1 heure de timeout

            # MODIFIÉ : Boucle de lecture en temps réel (style Masscan)
            for line in iter(process.stdout.readline, ''):
                # 1. Gérer le stop_flag
                if stop_flag():
                    process.terminate()
                    event_queue.put({'event': 'thread_update',
                                     'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan interrompu"}})
                    return ip, False, "Interrupted", {}, {"command": cmd_str}

                # 2. Gérer le timeout manuel (car process.wait() est bloquant)
                if time.time() - start_time > timeout_seconds:
                    process.kill()
                    event_queue.put({'event': 'thread_update',
                                     'data': {'thread_id': thread_id,
                                              'message': f"[{time.ctime()}] Scan timeout après {timeout_seconds}s"}})
                    # On continue pour parser ce qu'on a déjà eu
                    break  # Sortir de la boucle de lecture

                # 3. Stocker la ligne pour le parsing final
                line_stripped = line.strip()
                output_lines.append(line_stripped)
                buffer.append(f"[{time.ctime()}] {line_stripped}")

                # 4. Envoyer les logs groupés à l'UI
                if time.time() - last_emit >= 0.5:  # Envoyer par paquets
                    event_queue.put(
                        {'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})
                    buffer = []
                    last_emit = time.time()

            if buffer:  # Envoyer le reste du buffer
                event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(buffer)}})

            process.wait()
            returncode = process.returncode

        except Exception as e:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Erreur lancement Nmap : {str(e)}"}})
            return ip, False, str(e), {}, {"command": cmd_str}

        # Pas besoin d'envoyer les lignes ici, elles ont été streamées
        for line in output_lines:
            # event_queue.put({'event': 'thread_update',
            #                  'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}}) # Redondant
            try:
                if "open port" in line:
                    parts = line.split()
                    if len(parts) > 4 and '/' in parts[4]:
                        port = int(parts[4].split('/')[0])
                        ports.append(port)
                if "OS details" in line and "OS details: " in line:
                    os_info = line.split("OS details: ")[1].strip()
                elif "Too many fingerprints match this host" in line:
                    os_info = "Too many fingerprints match this host to give specific OS details"
                if "MAC Address" in line:
                    mac_address = line.split("MAC Address: ")[1].split()[0]
                if "Nmap scan report for" in line and len(line.split()) > 4:
                    lan_name = line.split()[4].strip("()")
                if "Service Info" in line or ("open" in line and "/" in line and "version" not in line.lower()):
                    parts = line.split()
                    if len(parts) > 2 and "/" in parts[0]:
                        port_str = parts[0].split('/')[0]
                        if port_str.isdigit():
                            port = int(port_str)
                            version = " ".join(parts[2:]) if len(parts) > 2 else "Unknown"
                            versions[port] = version
                if "VULNERABLE" in line:
                    vulns.append(line.strip())
            except (IndexError, ValueError) as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur parsing ligne '{line}': {str(e)}"}})
                continue  # Passe à la ligne suivante en cas d’erreur

        extra = {"command": cmd_str}
        if mac_address:
            extra["mac_address"] = mac_address
        if lan_name:
            extra["lan_name"] = lan_name

        if returncode == 0:
            details = {"ports": list(set(ports)), "os": os_info, "versions": versions, "vulns": vulns}
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
            error = f"Nmap a échoué avec le code {returncode}"
            event_queue.put(
                {'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error}"}})
            return ip, False, error, {}, extra

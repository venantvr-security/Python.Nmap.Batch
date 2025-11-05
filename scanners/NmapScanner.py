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
        import shutil

        nmap_path = shutil.which("nmap") or "/usr/bin/nmap"
        if not shutil.which(nmap_path):
            error = "Commande 'nmap' introuvable. Installez-la ou vérifiez votre PATH."
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {error}"}})
            return ip, False, error, {}, {}

        cmd = [nmap_path] + [ip] + cmd_template

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

            # Enregistrer le processus dans le process_manager
            if self.process_manager is not None:
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

            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                error = "Nmap timeout lors de l'attente de fin"
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {error}"}})
                return ip, False, error, {}, {"command": cmd_str}

            returncode = process.returncode

        except Exception as e:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Erreur lancement Nmap : {str(e)}"}})
            return ip, False, str(e), {}, {"command": cmd_str}

        # Pas besoin d'envoyer les lignes ici, elles ont été streamées
        for line in output_lines:
            try:
                # Parsing des ports ouverts
                if "open port" in line or ("open" in line and "/" in line):
                    parts = line.split()
                    for part in parts:
                        if '/' in part:
                            port_str = part.split('/')[0]
                            if port_str.isdigit():
                                port = int(port_str)
                                if 1 <= port <= 65535:  # Validation range
                                    ports.append(port)
                                    # Extraire version si disponible
                                    if len(parts) > 2:
                                        version = " ".join(parts[2:])
                                        versions[port] = version
                                break

                # OS detection
                if "OS details:" in line:
                    os_info = line.split("OS details:")[1].strip()
                elif "Too many fingerprints match this host" in line:
                    os_info = "Too many fingerprints match this host"

                # MAC address
                if "MAC Address:" in line:
                    mac_parts = line.split("MAC Address:")
                    if len(mac_parts) > 1:
                        mac_address = mac_parts[1].split()[0]

                # LAN name
                if "Nmap scan report for" in line:
                    parts = line.split()
                    if len(parts) > 4:
                        lan_name = parts[4].strip("()")

                # Vulns
                if "VULNERABLE" in line:
                    vulns.append(line.strip())

            except (IndexError, ValueError, AttributeError) as e:
                # Ignorer les lignes mal formées silencieusement
                continue

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

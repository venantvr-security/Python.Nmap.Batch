import os
import subprocess
import tempfile
import time
from typing import List, Dict

import yaml

from ScannerInterface import ScannerInterface, ScanResult


# echo "votre_utilisateur ALL=(ALL) NOPASSWD: /usr/bin/nmap" | sudo tee -a /etc/sudoers.d/nmap
# sudo chmod 440 /etc/sudoers.d/nmap
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

        # Vérifier si déjà root
        if os.geteuid() == 0:
            cmd = ["/usr/bin/nmap"] + [ip] + cmd_template
        else:
            cmd = ["/usr/bin/sudo", "/usr/bin/nmap"] + [ip] + cmd_template

        cmd_str = " ".join(cmd)
        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id,
                                  'message': f"[{time.ctime()}] Début du scan de {ip} avec {cmd_str}"}})

        # Utiliser un fichier temporaire pour capturer la sortie
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_filename = temp_file.name
            try:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Lancement de Popen"}})
                # FIX: Utiliser liste args au lieu de shell=True pour éviter injection
                with open(temp_filename, 'w') as outfile:
                    process = subprocess.Popen(cmd, stdout=outfile, stderr=subprocess.STDOUT)

                if self.process_manager:
                    self.process_manager.register(process, "nmap", self.strategy, ip, thread_id)

                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Popen lancé avec succès (PID: {process.pid})"}})

                try:
                    returncode = process.wait(timeout=3600)
                except subprocess.TimeoutExpired:
                    process.kill()
                    event_queue.put({'event': 'thread_update',
                                     'data': {'thread_id': thread_id,
                                              'message': f"[{time.ctime()}] Scan timeout après 3600s"}})
                    with open(temp_filename, 'r') as f:
                        output_lines = f.read().splitlines()
                    os.remove(temp_filename)
                    return ip, False, "Timeout", {}, {"command": cmd_str}

                with open(temp_filename, 'r') as f:
                    output_lines = f.read().splitlines()
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Scan terminé, lecture du fichier"}})

            except Exception as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur lancement Nmap : {str(e)}"}})
                os.remove(temp_filename)
                return ip, False, str(e), {}, {"command": cmd_str}

            finally:
                os.remove(temp_filename)
        ports = []
        os_info = None
        versions = {}
        vulns = []
        mac_address = None
        lan_name = None

        # Traitement robuste des lignes
        for line in output_lines:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}})
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
                        port = int(parts[0].split('/')[0])
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

import subprocess
import time
from typing import List, Dict

import yaml

from ScannerInterface import ScannerInterface, ScanResult


class CurlScanner(ScannerInterface):

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

        # Récupérer les paramètres de la stratégie
        strategy = self.strategies[self.strategy]

        # Vérifier si self.ports est défini (requis par le frontend)
        if not self.ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Erreur : Aucun port spécifié via l’interface"}})
            return ip, False, "No ports specified from interface", {}, {}

        # Trouver l’URL de base dans la stratégie (ex. "http://<ip>:<ports>")
        url_base = next((arg for arg in strategy if '<ip>' in arg), None)
        if not url_base or '<ports>' not in url_base:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Erreur : <ports> ou <ip> manquant dans l’URL de la stratégie"}})
            return ip, False, "Invalid strategy: missing <ports> or <ip> in URL", {}, {}

        ports_to_scan = self.parse_ports(self.ports)  # Utiliser parse_ports de la classe mère

        # Initialiser les résultats globaux
        all_ports = []
        all_outputs = []

        all_banners = {}  # Dictionnaire pour stocker les bannières

        # Définir les erreurs de connexion
        connection_failed_errors = [
            "failed to connect",
            "connection refused",
            "connection timed out",
            "no route to host",
            "network is unreachable",
            "operation timed out"
        ]

        # Boucler sur chaque port à scanner
        for port in ports_to_scan:
            if stop_flag():
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] Scan de {ip} annulé"}})
                return ip, False, "Cancelled", {"ports": all_ports, "banners": all_banners}, {"commands": all_outputs}

            # Construire l’URL avec l’IP et le port actuel
            url = url_base.replace("<ip>", ip).replace("<ports>", str(port))

            # Construire la commande en remplaçant l’URL de base par l’URL complète
            cmd_template = [arg if arg != url_base else url for arg in strategy]

            # Forcer des timeouts courts
            timeout_flags = ["--connect-timeout", "3", "-m", "5"]

            cmd = ["/usr/bin/curl"] + timeout_flags + cmd_template
            cmd_str = " ".join(cmd)
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] Début du scan de {ip}:{port} avec {cmd_str}"}})

            try:
                # Utiliser un timeout Popen légèrement plus long que celui de curl (-m 5)
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

                if self.process_manager is not None:
                    if isinstance(self.process_manager, list):
                        self.process_manager.append(process)
                    else:
                        self.process_manager.register(process, "curl", self.strategy, ip, thread_id)
            except Exception as e:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Erreur lancement curl : {str(e)}"}})
                all_outputs.append(cmd_str)
                continue

            try:
                # Utiliser un timeout Popen de 6s (légèrement > -m 5s de curl)
                stdout, _ = process.communicate(timeout=6)
                output_lines = stdout.splitlines()
                output_full_string = stdout.lower()  # Sortie complète en minuscules
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Scan terminé pour port {port}"}})
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, _ = process.communicate()
                output_lines = stdout.splitlines()
                output_full_string = stdout.lower()
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id,
                                          'message': f"[{time.ctime()}] Scan (sub) timeout après 6s pour port {port}"}})
                all_outputs.append(cmd_str)
                continue

            # 1. Vérifier si une erreur de connexion a été explicitement trouvée
            is_failed = False
            for error_msg in connection_failed_errors:
                if error_msg in output_full_string:
                    is_failed = True
                    break

            # 2. Si aucune erreur de connexion n'est trouvée, le port est ouvert
            if not is_failed:
                all_ports.append(port)

                banner = "N/A"
                if output_lines:
                    # Trouver la première ligne non vide (c'est généralement la bannière)
                    first_meaningful_line = next((line.strip() for line in output_lines if line.strip()), None)
                    if first_meaningful_line:
                        # Troncquer à 120 caractères pour éviter de polluer le JSON
                        banner = first_meaningful_line[:120]
                all_banners[port] = banner

            # 3. Envoyer TOUTE la sortie au tile, pour débogage
            for line in output_lines:
                event_queue.put({'event': 'thread_update',
                                 'data': {'thread_id': thread_id, 'message': f"[{time.ctime()}] {line.strip()}"}})

            # 4. (Fin de la boucle)
            all_outputs.append(cmd_str)

        details = {"ports": all_ports, "banners": all_banners}

        if all_ports:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} actif (ports: {all_ports})"}})
        else:
            event_queue.put({'event': 'thread_update',
                             'data': {'thread_id': thread_id,
                                      'message': f"[{time.ctime()}] {ip} n’a pas de ports ouverts"}})
        return ip, True, None, details, {"commands": all_outputs}
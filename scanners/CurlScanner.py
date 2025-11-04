import sys
import os
import time
from typing import List, Dict

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from BaseSubprocessScanner import BaseSubprocessScanner
from ScannerInterface import ScanResult


class CurlScanner(BaseSubprocessScanner):

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

            # Utiliser la méthode factorisée _run_command
            success, error, output_lines = self._run_command(
                cmd=cmd,
                ip=ip,
                port=port,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag,
                timeout=6,  # Légèrement > -m 5s de curl
                capture_output=True
            )

            all_outputs.append(" ".join(cmd))

            if not success and error == "Timeout":
                continue
            elif not success:
                continue

            output_full_string = "\n".join(output_lines).lower()

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
            self._send_output_to_queue(output_lines, thread_id, event_queue)

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
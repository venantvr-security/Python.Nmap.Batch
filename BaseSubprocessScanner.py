import shutil
import subprocess
import time
from queue import Queue
from typing import List, Tuple, Optional, Callable

from ScannerInterface import ScannerInterface


class BaseSubprocessScanner(ScannerInterface):
    """Classe de base factorisant la logique commune de gestion des sous-processus."""

    def _get_command_path(self, command: str, fallback_paths: List[str] = None) -> str:
        """
        Trouve le chemin de la commande avec shutil.which() ou fallback.

        Args:
            command: Nom de la commande (ex: 'curl')
            fallback_paths: Liste de chemins de secours (ex: ['/usr/bin/curl', '/bin/curl'])

        Returns:
            Chemin complet de la commande

        Raises:
            FileNotFoundError: Si la commande n'est pas trouvée
        """
        # Essayer shutil.which()
        cmd_path = shutil.which(command)
        if cmd_path:
            return cmd_path

        # Essayer les fallbacks
        if fallback_paths:
            for path in fallback_paths:
                if shutil.which(path):
                    return path

        raise FileNotFoundError(f"Commande '{command}' introuvable. Installez-la ou vérifiez votre PATH.")

    def _run_command(
            self,
            cmd: List[str],
            ip: str,
            port: int,
            thread_id: str,
            event_queue: Queue,
            stop_flag: Callable[[], bool],
            timeout: int = 5,
            capture_output: bool = True
    ) -> Tuple[bool, Optional[str], List[str]]:
        """
        Exécute une commande subprocess avec gestion d'erreurs et timeouts.

        Args:
            cmd: Commande à exécuter (liste de tokens)
            ip: IP cible
            port: Port cible
            thread_id: ID du thread
            event_queue: Queue pour les événements
            stop_flag: Flag d'arrêt
            timeout: Timeout en secondes
            capture_output: Si True, capture stdout/stderr

        Returns:
            Tuple (success, error_msg, output_lines)
            - success: True si la commande s'est exécutée sans erreur fatale
            - error_msg: Message d'erreur si échec, None sinon
            - output_lines: Lignes de sortie (stdout + stderr)
        """
        cmd_str = " ".join(cmd)
        event_queue.put({
            'event': 'thread_update',
            'data': {
                'thread_id': thread_id,
                'message': f"[{time.ctime()}] Début du scan de {ip}:{port} avec {cmd_str}"
            }
        })

        try:
            if capture_output:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
            else:
                process = subprocess.Popen(cmd)

            # Enregistrer le processus dans le process_manager
            if self.process_manager is not None:
                scanner_type = self.__class__.__name__.replace("Scanner", "").lower()
                self.process_manager.register(
                    process,
                    scanner_type,
                    self.strategy,
                    ip,
                    thread_id
                )

        except Exception as e:
            error_msg = f"Erreur lancement commande : {str(e)}"
            event_queue.put({
                'event': 'thread_update',
                'data': {
                    'thread_id': thread_id,
                    'message': f"[{time.ctime()}] {error_msg}"
                }
            })
            return False, error_msg, []

        # Attendre la fin du processus avec timeout
        try:
            if capture_output:
                stdout, _ = process.communicate(timeout=timeout)
                output_lines = stdout.splitlines() if stdout else []
            else:
                process.wait(timeout=timeout)
                output_lines = []

            event_queue.put({
                'event': 'thread_update',
                'data': {
                    'thread_id': thread_id,
                    'message': f"[{time.ctime()}] Scan terminé pour port {port}"
                }
            })
            return True, None, output_lines

        except subprocess.TimeoutExpired:
            process.kill()
            if capture_output:
                stdout, _ = process.communicate()
                output_lines = stdout.splitlines() if stdout else []
            else:
                output_lines = []

            event_queue.put({
                'event': 'thread_update',
                'data': {
                    'thread_id': thread_id,
                    'message': f"[{time.ctime()}] Scan timeout après {timeout}s pour port {port}"
                }
            })
            return False, "Timeout", output_lines

    def _send_output_to_queue(self, output_lines: List[str], thread_id: str, event_queue: Queue):
        """Envoie les lignes de sortie à la queue d'événements."""
        for line in output_lines:
            if line.strip():
                event_queue.put({
                    'event': 'thread_update',
                    'data': {
                        'thread_id': thread_id,
                        'message': f"[{time.ctime()}] {line.strip()}"
                    }
                })

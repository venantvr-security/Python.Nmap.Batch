import os
import shutil
import subprocess
import time
from queue import Queue
from typing import List, Tuple, Callable, Optional

from scanners.ScannerInterface import ScannerInterface


class BaseSubprocessScanner(ScannerInterface):
    """
    Classe de base pour les scanners qui dépendent de l'exécution d'un
    outil externe en ligne de commande via un sous-processus.
    """

    def _get_command_path(self, command_name: str, common_paths: List[str]) -> str:
        """
        Trouve le chemin absolu d'une commande en utilisant shutil.which ou
        en cherchant dans des emplacements courants.
        """
        path = shutil.which(command_name)
        if path:
            return path

        for p in common_paths:
            if os.path.exists(p):
                return p

        raise FileNotFoundError(f"Commande '{command_name}' introuvable. Installez-la ou vérifiez votre PATH.")

    def _run_command(
            self,
            cmd: List[str],
            ip: str,
            port: Optional[int],
            thread_id: str,
            event_queue: Queue,
            stop_flag: Callable[[], bool],
            timeout: int,
            capture_output: bool = True
    ) -> Tuple[bool, Optional[str], List[str]]:
        """
        Exécute une commande en sous-processus, gère le streaming de la sortie,
        le timeout et l'arrêt propre.
        """
        cmd_str = " ".join(cmd)
        event_queue.put({'event': 'thread_update',
                         'data': {'thread_id': thread_id,
                                  'message': f"[{time.ctime()}] Exécution: {cmd_str}"}})

        output_lines: List[str] = []
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
                stderr=subprocess.STDOUT if capture_output else subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
            if self.process_manager:
                self.process_manager.register(process, self.__class__.__name__, self.strategy, ip, thread_id)

            if not capture_output:
                # Si on ne capture pas la sortie, on attend simplement la fin
                process.wait(timeout=timeout)
                if process.returncode == 0:
                    return True, None, []
                else:
                    return False, f"Process exited with code {process.returncode}", []

            # Boucle de lecture en temps réel
            buffer: List[str] = []
            last_emit: float = time.time()
            start_time: float = time.time()

            for line in iter(process.stdout.readline, ''):
                if stop_flag():
                    process.terminate()
                    return False, "Interrupted", output_lines

                if time.time() - start_time > timeout:
                    process.kill()
                    return False, "Timeout", output_lines

                line_stripped = line.strip()
                output_lines.append(line_stripped)
                buffer.append(f"[{time.ctime()}] {line_stripped}")

                if time.time() - last_emit >= 0.5:
                    self._send_output_to_queue(buffer, thread_id, event_queue)
                    buffer = []
                    last_emit = time.time()

            if buffer:
                self._send_output_to_queue(buffer, thread_id, event_queue)

            process.wait()
            if process.returncode == 0:
                return True, None, output_lines
            else:
                return False, f"Process exited with code {process.returncode}", output_lines

        except FileNotFoundError:
            return False, f"Commande non trouvée: {cmd[0]}", []
        except subprocess.TimeoutExpired:
            process.kill()
            return False, "Timeout", output_lines
        except Exception as e:
            return False, f"Erreur d'exécution: {e}", output_lines

    def _send_output_to_queue(self, lines: List[str], thread_id: str, event_queue: Queue) -> None:
        """Envoie un bloc de lignes à la file d'attente des événements."""
        if not lines:
            return
        event_queue.put({'event': 'thread_update', 'data': {'thread_id': thread_id, 'message': "\n".join(lines)}})

import threading
from datetime import datetime
from typing import Dict, List, Optional

import psutil


class ProcessManager:
    """Gestionnaire centralisé des processus avec monitoring."""

    def __init__(self):
        self.processes: Dict[str, Dict] = {}  # {process_id: {process, metadata}}
        self.lock = threading.Lock()

    def register(self, process, scanner_type: str, strategy: str, ip: str, thread_id: str):
        """Enregistre un nouveau processus avec metadata."""
        with self.lock:
            process_id = f"{scanner_type}_{thread_id}_{process.pid}"
            self.processes[process_id] = {
                "process": process,
                "pid": process.pid,
                "scanner_type": scanner_type,
                "strategy": strategy,
                "ip": ip,
                "thread_id": thread_id,
                "start_time": datetime.now(),
                "status": "running"
            }
        return process_id

    def get_all(self) -> List[Dict]:
        """Retourne tous les processus avec leurs infos."""
        with self.lock:
            result = []
            for proc_id, data in list(self.processes.items()):
                try:
                    proc = data["process"]
                    p = psutil.Process(proc.pid)

                    result.append({
                        "id": proc_id,
                        "pid": data["pid"],
                        "scanner": data["scanner_type"],
                        "strategy": data["strategy"],
                        "ip": data["ip"],
                        "thread_id": data["thread_id"],
                        "status": data["status"],
                        "start_time": data["start_time"].isoformat(),
                        "cpu_percent": p.cpu_percent(interval=0.1),
                        "memory_mb": p.memory_info().rss / 1024 / 1024,
                        "uptime_seconds": (datetime.now() - data["start_time"]).total_seconds(),
                        "cmdline": " ".join(p.cmdline()[:3])  # Limiter taille
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Processus terminé
                    data["status"] = "terminated"
            return result

    def get_by_id(self, process_id: str) -> Optional[Dict]:
        """Récupère info d'un processus spécifique."""
        with self.lock:
            data = self.processes.get(process_id)
            if not data:
                return None

            try:
                proc = data["process"]
                p = psutil.Process(proc.pid)

                return {
                    "id": process_id,
                    "pid": data["pid"],
                    "scanner": data["scanner_type"],
                    "strategy": data["strategy"],
                    "ip": data["ip"],
                    "status": data["status"],
                    "cpu_percent": p.cpu_percent(interval=0.1),
                    "memory_mb": p.memory_info().rss / 1024 / 1024,
                    "num_threads": p.num_threads(),
                    "open_files": len(p.open_files()),
                    "connections": len(p.connections()),
                    "cmdline": " ".join(p.cmdline())
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return {"id": process_id, "status": "terminated"}

    def kill(self, process_id: str) -> bool:
        """Tue un processus spécifique."""
        with self.lock:
            data = self.processes.get(process_id)
            if not data:
                return False

            # ÉTAPE 1: Trouver le processus
            try:
                proc = data["process"]
                p = psutil.Process(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Le processus n'existe déjà plus ou on n'a pas les droits
                data["status"] = "terminated"
                return False

            # ÉTAPE 2: Tenter de le terminer poliment (terminate)
            try:
                p.terminate()
                p.wait(timeout=3)
                # S'il se termine à temps, 'p.wait()' ne lève pas d'exception
            except psutil.TimeoutExpired:
                # Il n'a pas voulu s'arrêter, on force (kill)
                try:
                    p.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
                    pass  # Mort entre-temps, ou permissions
            except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
                # Mort entre-temps, ou permissions
                pass

            data["status"] = "killed"
            return True

    def kill_all(self):
        """Tue tous les processus enregistrés."""
        with self.lock:
            for proc_id in list(self.processes.keys()):
                self.kill(proc_id)

    def cleanup_terminated(self):
        """Nettoie les processus terminés."""
        with self.lock:
            to_remove = []
            for proc_id, data in self.processes.items():
                try:
                    proc = data["process"]
                    if proc.poll() is not None:  # Terminé
                        to_remove.append(proc_id)
                except Exception:
                    to_remove.append(proc_id)

            for proc_id in to_remove:
                del self.processes[proc_id]

    def get_stats(self) -> Dict:
        """Statistiques globales."""
        with self.lock:
            total = len(self.processes)
            running = sum(1 for d in self.processes.values() if d["status"] == "running")
            by_scanner = {}

            for data in self.processes.values():
                scanner = data["scanner_type"]
                by_scanner[scanner] = by_scanner.get(scanner, 0) + 1

            return {
                "total": total,
                "running": running,
                "by_scanner": by_scanner
            }

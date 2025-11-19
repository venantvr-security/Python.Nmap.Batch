from abc import ABC, abstractmethod
from queue import Queue
from typing import Dict, List, Tuple, Optional, Any, Callable

# Alias de type pour clarifier ce que la méthode scan doit retourner.
# (ip, success, error_message, details_dict, extra_info_dict)
ScanResult = Tuple[str, bool, Optional[str], Dict[str, Any], Optional[Dict[str, Any]]]


class ScannerInterface(ABC):
    """
    Interface abstraite pour tous les scanners.
    Définit le contrat que chaque classe de scanner doit respecter.
    """

    def __init__(self, strategy: str, process_manager: Any, yaml_file: str):
        self.strategy: str = strategy
        self.process_manager: Any = process_manager
        self.yaml_file: str = yaml_file
        self.ports: Optional[str] = None
        self.strategies: Dict[str, Any] = self.load_strategies()

    @abstractmethod
    def load_strategies(self) -> Dict[str, Any]:
        """
        Charge les stratégies depuis le fichier YAML spécifique au scanner.
        """
        raise NotImplementedError

    @abstractmethod
    def scan(self, ip: str, thread_id: str, event_queue: Queue, stop_flag: Callable[[], bool]) -> ScanResult:
        """
        Exécute un scan sur une adresse IP donnée.

        Args:
            ip: L'adresse IP cible à scanner.
            thread_id: Un identifiant unique pour ce thread/processus de scan.
            event_queue: La file d'attente pour envoyer les mises à jour à l'interface.
            stop_flag: Une fonction callable qui retourne True si le scan doit s'arrêter.

        Returns:
            Un tuple ScanResult contenant les résultats du scan.
        """
        raise NotImplementedError

    def parse_ports(self, port_string: str) -> List[int]:
        """
        Parse une chaîne de ports au format Nmap et renvoie une liste d'entiers.
        Méthode utilitaire partagée par tous les scanners.
        """
        ports: List[int] = []
        if not port_string:
            return ports

        items: List[str] = port_string.split(',')
        for item in items:
            item = item.strip()
            if '-' in item:
                try:
                    start_str, end_str = item.split('-')
                    start = int(start_str)
                    end = int(end_str)
                    if not (1 <= start <= 65535 and 1 <= end <= 65535):
                        raise ValueError(f"Ports hors limites (1-65535) dans la plage {item}")
                    if start > end:
                        raise ValueError(f"Plage invalide dans {item}: le début est après la fin")
                    ports.extend(range(start, end + 1))
                except ValueError as e:
                    # Log l'erreur ou la remonte
                    print(f"Avertissement : Ignorer la plage de ports invalide '{item}': {e}")
                    continue
            else:
                try:
                    port = int(item)
                    if not (1 <= port <= 65535):
                        raise ValueError(f"Port hors limites (1-65535): {port}")
                    ports.append(port)
                except ValueError:
                    print(f"Avertissement : Ignorer le port invalide '{item}'")
                    continue

        return sorted(list(set(ports)))

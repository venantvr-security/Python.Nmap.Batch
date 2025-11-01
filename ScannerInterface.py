from abc import ABC, abstractmethod
from typing import List, Dict, Tuple, TypedDict

# Alias de type pour le retour des méthodes scan
# ScanResult = Tuple[str, bool, Optional[str], Dict, Dict[str, str]]
ScanResult = Tuple[str, bool, str or None, dict, TypedDict]


class ScannerInterface(ABC):
    def __init__(self, strategy: str, active_processes: List, yaml_file: str):
        self.strategy = strategy
        self.active_processes = active_processes if active_processes is not None else []
        self.yaml_file = yaml_file
        self.strategies = self.load_strategies()
        self.ports = None  # Ajouter cet attribut

        if strategy not in self.strategies:
            raise ValueError(f"Stratégie inconnue : {strategy}. Options valides : {list(self.strategies.keys())}")

    @abstractmethod
    def load_strategies(self) -> Dict[str, any]:
        """Charge les stratégies depuis le fichier YAML. Retourne un dictionnaire."""
        pass

    @abstractmethod
    def scan(self, ip: str, thread_id: str, event_queue, stop_flag) -> ScanResult:
        """
        Effectue un scan sur une IP donnée et retourne un tuple avec un format standardisé :
        - ip (str): L'adresse IP scannée.
        - success (bool): True si le scan a réussi, False sinon.
        - error (Optional[str]): Message d'erreur si le scan échoue, None sinon.
        - details (Dict): Détails du scan, incluant au moins {"ports": [int]} (liste des ports ouverts).
        - extra (Optional[str]): Informations supplémentaires (non utilisé ici, mais pour compatibilité future).
        """
        pass

    # noinspection PyMethodMayBeStatic
    def parse_ports(self, port_string: str) -> List[int]:
        """Parse une chaîne de ports au format Nmap (ex. '80,443' ou '1-1000')."""
        ports = []
        items = port_string.split(',')
        for item in items:
            item = item.strip()
            if '-' in item:
                start, end = map(int, item.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError(f"Ports hors limites (1-65535) dans la plage {item}")
                if start > end:
                    raise ValueError(f"Plage invalide dans {item}: début > fin")
                ports.extend(range(start, end + 1))
            else:
                port = int(item)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port hors limites (1-65535): {port}")
                ports.append(port)
        return sorted(list(set(ports)))

"""
Fixtures communes pour les tests des scanners réseau.

Ces fixtures simulent des comportements réseau réalistes :
- Firewalls qui filtrent/bloquent le trafic
- Ports ouverts qui répondent correctement
- Ports fermés qui rejettent les connexions
- Timeouts réseau
"""
import os
import sys
from queue import Queue
from unittest.mock import Mock, MagicMock
import pytest

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ============================================================================
# FIXTURES : CONFIGURATIONS RÉSEAU RÉALISTES
# ============================================================================

@pytest.fixture
def ip_target():
    """IP cible pour les tests (IP privée, pas de vrai scan)."""
    return "192.168.1.100"


@pytest.fixture
def thread_id():
    """ID de thread fictif pour les tests."""
    return "test-thread-12345"


@pytest.fixture
def event_queue():
    """Queue pour capturer les événements du scanner."""
    return Queue()


@pytest.fixture
def stop_flag_never():
    """Stop flag qui ne s'active jamais (scan complet)."""
    return lambda: False


@pytest.fixture
def stop_flag_immediate():
    """Stop flag qui s'active immédiatement (scan annulé)."""
    return lambda: True


@pytest.fixture
def process_manager_mock():
    """Mock du ProcessManager pour enregistrer les processus."""
    manager = Mock()
    manager.register = Mock()
    return manager


# ============================================================================
# FIXTURES : COMPORTEMENTS FIREWALL/RÉSEAU
# ============================================================================

class FirewallBehavior:
    """Classe représentant le comportement d'un firewall."""

    def __init__(self, name: str):
        self.name = name
        self.open_ports = set()
        self.closed_ports = set()
        self.filtered_ports = set()
        self.timeout_ports = set()
        self.banners = {}  # {port: "banner text"}

    def allows(self, *ports):
        """Ports ouverts qui répondent (SYN-ACK)."""
        self.open_ports.update(ports)
        return self

    def rejects(self, *ports):
        """Ports fermés qui envoient RST."""
        self.closed_ports.update(ports)
        return self

    def filters(self, *ports):
        """Ports filtrés (aucune réponse)."""
        self.filtered_ports.update(ports)
        return self

    def timeouts_on(self, *ports):
        """Ports qui provoquent un timeout."""
        self.timeout_ports.update(ports)
        return self

    def with_banner(self, port, banner):
        """Définir une bannière pour un port."""
        self.banners[port] = banner
        return self

    def __repr__(self):
        return f"<FirewallBehavior: {self.name}>"


@pytest.fixture
def firewall_blocks_everything():
    """
    Firewall qui bloque TOUT le trafic.
    Scénario : Serveur derrière un firewall strict, aucun port accessible.
    """
    return FirewallBehavior("blocks_everything").filters(22, 80, 443, 8080)


@pytest.fixture
def firewall_allows_web_server():
    """
    Firewall qui autorise uniquement HTTP/HTTPS.
    Scénario : Serveur web classique, SSH bloqué.
    """
    return (FirewallBehavior("allows_web_server")
            .allows(80, 443)
            .rejects(22)  # SSH fermé
            .filters(3306))  # MySQL filtré


@pytest.fixture
def firewall_allows_ssh_only():
    """
    Firewall qui autorise uniquement SSH.
    Scénario : Serveur de gestion, seul SSH accessible.
    """
    return (FirewallBehavior("allows_ssh_only")
            .allows(22)
            .with_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu")
            .rejects(80, 443))


@pytest.fixture
def firewall_stealth_mode():
    """
    Firewall en mode furtif : tous les ports filtrés (DROP).
    Scénario : IDS/IPS actif, aucune réponse pour éviter la détection.
    """
    return FirewallBehavior("stealth_mode").filters(22, 80, 443, 3306, 8080)


@pytest.fixture
def firewall_open_relay():
    """
    Serveur mal configuré : tous les ports ouverts.
    Scénario : Serveur compromis ou mal sécurisé.
    """
    return (FirewallBehavior("open_relay")
            .allows(22, 80, 443, 3306, 8080)
            .with_banner(80, "HTTP/1.1 200 OK\nServer: nginx/1.18.0")
            .with_banner(22, "SSH-2.0-OpenSSH_7.4"))


@pytest.fixture
def network_unreachable():
    """
    Réseau complètement inaccessible (timeout sur tout).
    Scénario : Câble débranché, IP inexistante, routage cassé.
    """
    return FirewallBehavior("unreachable").timeouts_on(22, 80, 443)


# ============================================================================
# FIXTURES : PROCESSUS SUBPROCESS MOCKÉS
# ============================================================================

@pytest.fixture
def curl_response_open_port():
    """
    Réponse curl pour un port HTTP ouvert.
    Simule une connexion réussie avec bannière HTTP.
    """
    mock_process = Mock()
    mock_process.communicate.return_value = (
        "HTTP/1.1 200 OK\nServer: Apache/2.4.41\nContent-Type: text/html",
        None
    )
    mock_process.returncode = 0
    mock_process.pid = 12345
    mock_process.poll.return_value = 0
    return mock_process


@pytest.fixture
def curl_response_connection_refused():
    """
    Réponse curl pour un port fermé (connection refused).
    """
    mock_process = Mock()
    mock_process.communicate.return_value = (
        "curl: (7) Failed to connect to 192.168.1.100 port 80: Connection refused",
        None
    )
    mock_process.returncode = 7
    mock_process.pid = 12346
    mock_process.poll.return_value = 7
    return mock_process


@pytest.fixture
def curl_response_timeout():
    """
    Réponse curl pour un timeout (port filtré).
    """
    from subprocess import TimeoutExpired
    mock_process = Mock()
    mock_process.communicate.side_effect = TimeoutExpired(cmd="curl", timeout=6)
    mock_process.kill = Mock()
    mock_process.pid = 12347
    mock_process.poll.return_value = None
    return mock_process


# ============================================================================
# FIXTURES : PAQUETS SCAPY MOCKÉS
# ============================================================================

@pytest.fixture
def scapy_syn_ack_response():
    """
    Paquet Scapy : Réponse SYN-ACK (port ouvert).
    """
    from unittest.mock import Mock
    response = Mock()
    response.haslayer.return_value = True
    tcp_layer = Mock()
    tcp_layer.flags = 0x12  # SYN-ACK
    response.__getitem__ = lambda self, key: tcp_layer if key == "TCP" else None
    response.TCP = tcp_layer
    return response


@pytest.fixture
def scapy_rst_response():
    """
    Paquet Scapy : Réponse RST (port fermé).
    """
    from unittest.mock import Mock
    response = Mock()
    response.haslayer.return_value = True
    tcp_layer = Mock()
    tcp_layer.flags = 0x14  # RST-ACK
    response.__getitem__ = lambda self, key: tcp_layer if key == "TCP" else None
    response.TCP = tcp_layer
    return response


@pytest.fixture
def scapy_no_response():
    """
    Paquet Scapy : Aucune réponse (port filtré ou timeout).
    """
    return None


# ============================================================================
# FIXTURES : YAML STRATEGIES
# ============================================================================

@pytest.fixture
def strategy_file_curl(tmp_path):
    """Fichier de stratégie YAML pour CurlScanner."""
    yaml_content = """strategies:
  http_basic:
    - "http://<ip>:<ports>"
"""
    yaml_file = tmp_path / "curl.yaml"
    yaml_file.write_text(yaml_content)
    return str(yaml_file)


@pytest.fixture
def strategy_file_scapy(tmp_path):
    """Fichier de stratégie YAML pour ScapyScanner."""
    yaml_content = """strategies:
  syn_scan:
    scan_type: syn
    ports: "<ports>"
    timeout: 2
    delay: 0.1
"""
    yaml_file = tmp_path / "scapy.yaml"
    yaml_file.write_text(yaml_content)
    return str(yaml_file)

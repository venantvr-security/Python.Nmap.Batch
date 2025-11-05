"""
Tests pour MasscanScanner avec simulation de sorties masscan réalistes.

Ces tests vérifient que le parsing de sortie masscan fonctionne correctement :
- Détection des ports ouverts
- Parsing du format "Discovered open port X/tcp on Y"
- Gestion des scans massifs
"""
import os
import sys
from subprocess import TimeoutExpired
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.MasscanScanner import MasscanScanner


class TestMasscanScannerParsing:
    """Tests de parsing des sorties masscan."""

    def test_parse_ports_ouverts(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : Masscan détecte 3 ports ouverts (22, 80, 443).

        Comportement attendu :
        - Ports 22, 80, 443 extraits correctement
        - success = True
        """
        yaml_content = """strategies:
  fast_scan:
    - "-p"
    - "<ports>"
    - "--rate"
    - "1000"
    - "<ip>"
"""
        yaml_file = tmp_path / "masscan.yaml"
        yaml_file.write_text(yaml_content)

        scanner = MasscanScanner(
            strategy="fast_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "22,80,443"

        masscan_output = """Starting masscan 1.3.2
Initiating SYN Stealth Scan
Scanning 1 hosts [3 ports/host]
Discovered open port 22/tcp on 192.168.1.100
Discovered open port 80/tcp on 192.168.1.100
Discovered open port 443/tcp on 192.168.1.100
"""

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(
                side_effect=masscan_output.splitlines(keepends=True) + ['']
            )
            mock_process.poll.side_effect = [None, None, None, None, None, None, 0]
            mock_process.wait.return_value = None
            mock_process.returncode = 0
            mock_process.pid = 88887
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True, "Le scan aurait dû réussir"
        assert 22 in details["ports"], "Port 22 devrait être détecté"
        assert 80 in details["ports"], "Port 80 devrait être détecté"
        assert 443 in details["ports"], "Port 443 devrait être détecté"
        assert len(details["ports"]) == 3

    def test_parse_aucun_port_ouvert(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : Masscan ne détecte aucun port ouvert (firewall bloque tout).

        Comportement attendu :
        - success = True
        - Liste de ports vide
        """
        yaml_content = """strategies:
  fast_scan:
    - "-p"
    - "<ports>"
    - "--rate"
    - "1000"
    - "<ip>"
"""
        yaml_file = tmp_path / "masscan.yaml"
        yaml_file.write_text(yaml_content)

        scanner = MasscanScanner(
            strategy="fast_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "22,80,443"

        masscan_output = """Starting masscan 1.3.2
Initiating SYN Stealth Scan
Scanning 1 hosts [3 ports/host]
"""

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(
                side_effect=masscan_output.splitlines(keepends=True) + ['']
            )
            mock_process.poll.side_effect = [None, None, None, 0]
            mock_process.wait.return_value = None
            mock_process.returncode = 0
            mock_process.pid = 88887
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert len(details["ports"]) == 0, "Aucun port ne devrait être détecté"

    def test_parse_format_alternatif(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : Masscan avec format de sortie légèrement différent.

        Comportement attendu :
        - Parsing robuste qui gère les variations
        """
        yaml_content = """strategies:
  fast_scan:
    - "-p"
    - "<ports>"
    - "--rate"
    - "1000"
    - "<ip>"
"""
        yaml_file = tmp_path / "masscan.yaml"
        yaml_file.write_text(yaml_content)

        scanner = MasscanScanner(
            strategy="fast_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80,8080"

        masscan_output = """Starting masscan 1.3.2
Discovered open port 80/tcp on 192.168.1.100
Discovered open port 8080/tcp on 192.168.1.100
"""

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(
                side_effect=masscan_output.splitlines(keepends=True) + ['']
            )
            mock_process.poll.side_effect = [None, None, None, 0]
            mock_process.wait.return_value = None
            mock_process.returncode = 0
            mock_process.pid = 88887
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert 80 in details["ports"]
        assert 8080 in details["ports"]

    def test_scan_avec_stop_flag(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_immediate,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : Scan interrompu par stop_flag.

        Comportement attendu :
        - Scan s'arrête proprement
        - success = False
        """
        yaml_content = """strategies:
  fast_scan:
    - "-p"
    - "<ports>"
    - "--rate"
    - "1000"
    - "<ip>"
"""
        yaml_file = tmp_path / "masscan.yaml"
        yaml_file.write_text(yaml_content)

        scanner = MasscanScanner(
            strategy="fast_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "1-1000"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(return_value="Starting masscan\n")
            mock_process.poll.return_value = None
            mock_process.kill = Mock()
            mock_process.wait.return_value = None
            mock_process.pid = 88887
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_immediate
            )

        assert success is False, "Le scan devrait être annulé"
        assert "interrompu" in error.lower() or "cancelled" in error.lower()

    def test_timeout_handling(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : Process.wait() timeout.

        Comportement attendu :
        - Processus tué proprement
        - success = False avec message timeout
        """
        yaml_content = """strategies:
  fast_scan:
    - "-p"
    - "<ports>"
    - "--rate"
    - "1000"
    - "<ip>"
"""
        yaml_file = tmp_path / "masscan.yaml"
        yaml_file.write_text(yaml_content)

        scanner = MasscanScanner(
            strategy="fast_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "1-1000"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(return_value='')
            mock_process.poll.return_value = None
            # Premier wait() timeout, deuxième wait() réussit
            mock_process.wait.side_effect = [TimeoutExpired("masscan", 10), None]
            mock_process.kill = Mock()
            mock_process.pid = 88887
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is False
        assert "timeout" in error.lower()

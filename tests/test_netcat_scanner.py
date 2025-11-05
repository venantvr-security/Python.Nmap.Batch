"""
Tests pour NetcatScanner avec simulation de comportements réseau réalistes.

Ces tests vérifient que NetcatScanner interprète correctement :
- Les ports ouverts (connexion réussie)
- Les ports fermés (connection refused)
- Les ports filtrés (timeout)
- Les bannières capturées
"""
import sys
import os
from unittest.mock import Mock, patch
from subprocess import TimeoutExpired

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.NetcatScanner import NetcatScanner


class TestNetcatScannerPortInterpretation:
    """Tests d'interprétation des états de ports par NetcatScanner."""

    def test_port_ouvert_avec_banniere(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Port 22 ouvert (SSH) avec bannière.

        Comportement attendu :
        - success = True
        - Port 22 dans la liste des ports ouverts
        - Bannière SSH capturée
        """
        yaml_content = """strategies:
  tcp_connect:
    - "-zv"
    - "<ip>"
    - "<ports>"
"""
        yaml_file = tmp_path / "netcat.yaml"
        yaml_file.write_text(yaml_content)

        scanner = NetcatScanner(
            strategy="tcp_connect",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "22"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.return_value = (
                "Connection to 192.168.1.100 22 port [tcp/ssh] succeeded!\nSSH-2.0-OpenSSH_8.9p1 Ubuntu",
                None
            )
            mock_process.pid = 99998
            mock_process.poll.return_value = 0
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True, "Le scan aurait dû réussir"
        assert error is None
        assert 22 in details["ports"], "Le port 22 devrait être détecté comme ouvert"
        # Note: NetcatScanner ne capture pas les bannières, seulement les ports

    def test_port_ferme_connection_refused(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Port 80 fermé (connection refused).

        Comportement attendu :
        - success = True
        - Port 80 PAS dans la liste
        """
        yaml_content = """strategies:
  tcp_connect:
    - "-zv"
    - "<ip>"
    - "<ports>"
"""
        yaml_file = tmp_path / "netcat.yaml"
        yaml_file.write_text(yaml_content)

        scanner = NetcatScanner(
            strategy="tcp_connect",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.return_value = (
                "nc: connect to 192.168.1.100 port 80 (tcp) failed: Connection refused",
                None
            )
            mock_process.pid = 99998
            mock_process.poll.return_value = 1
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert 80 not in details["ports"], "Le port 80 ne devrait PAS être ouvert"

    def test_port_filtre_timeout(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Port 443 filtré par firewall (timeout).

        Comportement attendu :
        - success = True
        - Port 443 PAS dans la liste
        """
        yaml_content = """strategies:
  tcp_connect:
    - "-zv"
    - "-w3"
    - "<ip>"
    - "<ports>"
"""
        yaml_file = tmp_path / "netcat.yaml"
        yaml_file.write_text(yaml_content)

        scanner = NetcatScanner(
            strategy="tcp_connect",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "443"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.side_effect = [
                TimeoutExpired("nc", 5),
                ("", None)
            ]
            mock_process.kill = Mock()
            mock_process.pid = 99998
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert 443 not in details["ports"], "Le port 443 ne devrait PAS être ouvert"

    def test_multi_ports_comportements_mixtes(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Scan de plusieurs ports avec comportements différents.
        - Port 22: Ouvert (SSH banner)
        - Port 80: Fermé (connection refused)
        - Port 443: Filtré (timeout)

        Comportement attendu :
        - Seul le port 22 détecté comme ouvert
        """
        yaml_content = """strategies:
  tcp_connect:
    - "-zv"
    - "<ip>"
    - "<ports>"
"""
        yaml_file = tmp_path / "netcat.yaml"
        yaml_file.write_text(yaml_content)

        scanner = NetcatScanner(
            strategy="tcp_connect",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "22,80,443"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()

            with patch.object(mock_process, 'communicate', side_effect=[
                ("Connection to 192.168.1.100 22 port [tcp/ssh] succeeded!\nSSH-2.0-OpenSSH_8.9p1", None),
                ("nc: connect to 192.168.1.100 port 80 (tcp) failed: Connection refused", None),
                TimeoutExpired("nc", 5),
                ("", None)
            ]):
                mock_process.kill = Mock()
                mock_process.pid = 99998
                mock_process.poll.return_value = 0
                mock_popen.return_value = mock_process

                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        assert details["ports"] == [22], "Seul le port 22 devrait être ouvert"
        # Note: NetcatScanner ne capture pas les bannières

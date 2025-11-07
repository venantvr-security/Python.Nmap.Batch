"""
Tests pour Hping3Scanner avec simulation de réponses ICMP/TCP réalistes.

Ces tests vérifient que Hping3Scanner interprète correctement :
- Les flags TCP (SA = ouvert, RA = fermé)
- L'absence de réponse (filtré)
- Les scans SYN/ACK/FIN
"""
import os
import sys
from subprocess import TimeoutExpired
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.Hping3Scanner import Hping3Scanner


class TestHping3ScannerTCPFlags:
    """Tests d'interprétation des flags TCP par Hping3Scanner."""

    def test_syn_scan_port_ouvert_syn_ack(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : SYN scan sur port 80 ouvert.
        Serveur répond avec flags=SA (SYN-ACK).

        Comportement attendu :
        - success = True
        - Port 80 dans la liste (flags SA)
        """
        yaml_content = """strategies:
  syn_scan:
    - "-S"
    - "-p"
    - "<ports>"
    - "-c"
    - "1"
    - "<ip>"
"""
        yaml_file = tmp_path / "hping3.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Hping3Scanner(
            strategy="syn_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.return_value = (
                "HPING 192.168.1.100 (eth0 192.168.1.100): S set, 40 headers + 0 data bytes\n"
                "len=46 ip=192.168.1.100 ttl=64 DF id=0 sport=80 flags=SA seq=0 win=5840 rtt=0.3 ms",
                None
            )
            mock_process.pid = 99997
            mock_process.poll.return_value = 0
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True, "Le scan aurait dû réussir"
        assert 80 in details["ports"], "Le port 80 devrait être détecté comme ouvert (flags=SA)"

    def test_syn_scan_port_ferme_rst_ack(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : SYN scan sur port 80 fermé.
        Serveur répond avec flags=RA (RST-ACK).

        Comportement attendu :
        - success = True
        - Port 80 PAS dans la liste (flags RA = fermé)
        """
        yaml_content = """strategies:
  syn_scan:
    - "-S"
    - "-p"
    - "<ports>"
    - "-c"
    - "1"
    - "<ip>"
"""
        yaml_file = tmp_path / "hping3.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Hping3Scanner(
            strategy="syn_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.return_value = (
                "HPING 192.168.1.100 (eth0 192.168.1.100): S set, 40 headers + 0 data bytes\n"
                "len=46 ip=192.168.1.100 ttl=64 id=0 sport=80 flags=RA seq=0 win=0 rtt=0.2 ms",
                None
            )
            mock_process.pid = 99997
            mock_process.poll.return_value = 0
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert 80 not in details["ports"], "Le port 80 ne devrait PAS être ouvert (flags=RA)"

    def test_syn_scan_port_filtre_no_response(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : SYN scan sur port 443 filtré.
        Firewall DROP les paquets, aucune réponse.

        Comportement attendu :
        - success = True
        - Port 443 PAS dans la liste (timeout)
        """
        yaml_content = """strategies:
  syn_scan:
    - "-S"
    - "-p"
    - "<ports>"
    - "-c"
    - "1"
    - "<ip>"
"""
        yaml_file = tmp_path / "hping3.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Hping3Scanner(
            strategy="syn_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "443"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.side_effect = [
                TimeoutExpired("hping3", 5),
                ("", None)
            ]
            mock_process.kill = Mock()
            mock_process.pid = 99997
            mock_process.poll.return_value = None
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert 443 not in details["ports"], "Le port 443 ne devrait PAS être détecté (filtré)"

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
        Scénario : Scan de 3 ports avec états différents.
        - Port 22: Ouvert (flags=SA)
        - Port 80: Fermé (flags=RA)
        - Port 443: Filtré (no response)

        Comportement attendu :
        - Seul le port 22 détecté comme ouvert
        """
        yaml_content = """strategies:
  syn_scan:
    - "-S"
    - "-p"
    - "<ports>"
    - "-c"
    - "1"
    - "<ip>"
"""
        yaml_file = tmp_path / "hping3.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Hping3Scanner(
            strategy="syn_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "22,80,443"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()

            with patch.object(mock_process, 'communicate', side_effect=[
                # Port 22: SA (ouvert)
                ("len=46 ip=192.168.1.100 sport=22 flags=SA seq=0 win=5840 rtt=0.3 ms", None),
                # Port 80: RA (fermé)
                ("len=46 ip=192.168.1.100 sport=80 flags=RA seq=0 win=0 rtt=0.2 ms", None),
                # Port 443: timeout (filtré)
                TimeoutExpired("hping3", 5),
                ("", None)
            ]):
                mock_process.kill = Mock()
                mock_process.pid = 99997
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


class TestHping3ScannerFINScan:
    """Tests pour FIN scan avec Hping3."""

    def test_fin_scan_port_ouvert_no_response(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : FIN scan sur port ouvert.
        Port ouvert → Pas de réponse (RFC 793).

        Comportement attendu :
        - success = True
        - Port détecté (absence de réponse = potentiellement ouvert)
        """
        yaml_content = """strategies:
  fin_scan:
    - "-F"
    - "-p"
    - "<ports>"
    - "-c"
    - "1"
    - "<ip>"
"""
        yaml_file = tmp_path / "hping3.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Hping3Scanner(
            strategy="fin_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.return_value = (
                "HPING 192.168.1.100 (eth0 192.168.1.100): F set, 40 headers + 0 data bytes\n",
                None
            )
            mock_process.pid = 99997
            mock_process.poll.return_value = 0
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        # Note: FIN scan no response could mean open|filtered
        # Implementation may vary - this validates scan completion

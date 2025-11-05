"""
Tests pour NmapScanner avec simulation de sorties nmap réalistes.

Ces tests vérifient que le parsing de sortie nmap fonctionne correctement :
- Détection des ports ouverts
- Extraction des versions de services
- Détection OS
- MAC address
"""
import sys
import os
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.NmapScanner import NmapScanner


class TestNmapScannerParsing:
    """Tests de parsing des sorties nmap."""

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
        Scénario : Nmap détecte 2 ports ouverts (22, 80).

        Comportement attendu :
        - Ports 22 et 80 extraits correctement
        - success = True
        """
        yaml_content = """strategies:
  default_scan:
    - "-sT"
    - "-p"
    - "<ports>"
"""
        yaml_file = tmp_path / "nmap.yaml"
        yaml_file.write_text(yaml_content)

        scanner = NmapScanner(
            strategy="default_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "22,80,443"

        # Sortie nmap simulée
        nmap_output = """Starting Nmap 7.92
Nmap scan report for 192.168.1.100
Host is up (0.00050s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp closed https

Nmap done: 1 IP address (1 host up) scanned in 0.12 seconds
"""

        with patch('scanners.NmapScanner.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(side_effect=nmap_output.splitlines(keepends=True) + [''])
            mock_process.wait.return_value = None
            mock_process.returncode = 0
            mock_process.pid = 88888
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert 22 in details["ports"], "Port 22 devrait être détecté"
        assert 80 in details["ports"], "Port 80 devrait être détecté"
        assert 443 not in details["ports"], "Port 443 est fermé, pas ouvert"

    def test_parse_versions_services(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Nmap avec détection de version (-sV).

        Comportement attendu :
        - Versions extraites dans details["versions"]
        """
        yaml_content = """strategies:
  version_scan:
    - "-sV"
    - "-p"
    - "<ports>"
"""
        yaml_file = tmp_path / "nmap.yaml"
        yaml_file.write_text(yaml_content)

        scanner = NmapScanner(
            strategy="version_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "22,80"

        nmap_output = """Starting Nmap 7.92
Nmap scan report for 192.168.1.100

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    nginx 1.18.0

Service detection performed.
Nmap done: 1 IP address scanned in 6.28 seconds
"""

        with patch('scanners.NmapScanner.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(side_effect=nmap_output.splitlines(keepends=True) + [''])
            mock_process.wait.return_value = None
            mock_process.returncode = 0
            mock_process.pid = 88889
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert 22 in details["ports"]
        assert 80 in details["ports"]
        assert "versions" in details
        # Vérifier que les versions ont été extraites
        assert 22 in details["versions"] or 80 in details["versions"]

    def test_parse_os_detection(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Nmap avec détection OS (-O).

        Comportement attendu :
        - OS détecté dans details["os"]
        """
        yaml_content = """strategies:
  os_scan:
    - "-O"
"""
        yaml_file = tmp_path / "nmap.yaml"
        yaml_file.write_text(yaml_content)

        scanner = NmapScanner(
            strategy="os_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = None

        nmap_output = """Starting Nmap 7.92
Nmap scan report for 192.168.1.100
Host is up (0.00050s latency).

Device type: general purpose
Running: Linux 5.X
OS details: Linux 5.10 - 5.15
Network Distance: 1 hop

Nmap done: 1 IP address scanned in 2.45 seconds
"""

        with patch('scanners.NmapScanner.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(side_effect=nmap_output.splitlines(keepends=True) + [''])
            mock_process.wait.return_value = None
            mock_process.returncode = 0
            mock_process.pid = 88890
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert details["os"] is not None, "OS devrait être détecté"
        assert "Linux" in details["os"]


    def test_parse_mac_address(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Nmap détecte une adresse MAC (scan local).

        Comportement attendu :
        - MAC address dans extra["mac_address"]
        """
        yaml_content = """strategies:
  local_scan:
    - "-sT"
"""
        yaml_file = tmp_path / "nmap.yaml"
        yaml_file.write_text(yaml_content)

        scanner = NmapScanner(
            strategy="local_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        nmap_output = """Starting Nmap 7.92
Nmap scan report for 192.168.1.100
Host is up (0.00050s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:11:22:33:44:55 (Vendor Name)

Nmap done: 1 IP address scanned in 0.15 seconds
"""

        with patch('scanners.NmapScanner.subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.stdout = Mock()
            mock_process.stdout.readline = Mock(side_effect=nmap_output.splitlines(keepends=True) + [''])
            mock_process.wait.return_value = None
            mock_process.returncode = 0
            mock_process.pid = 88891
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True
        assert "mac_address" in extra
        assert extra["mac_address"] == "00:11:22:33:44:55"

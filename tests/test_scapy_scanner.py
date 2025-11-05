"""
Tests pour ScapyScanner avec simulation de réponses TCP réalistes.

Ces tests vérifient que ScapyScanner interprète correctement les flags TCP :
- SYN-ACK (0x12) = Port ouvert
- RST-ACK (0x14) = Port fermé
- Aucune réponse = Port filtré
- Scans FIN/XMAS/NULL avec logique inversée
"""
import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.ScapyScanner import ScapyScanner


class TestScapyScannerTCPFlags:
    """Tests d'interprétation des flags TCP par ScapyScanner."""

    def test_syn_scan_port_ouvert_syn_ack(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            strategy_file_scapy
    ):
        """
        Scénario : SYN scan sur port 80 ouvert.
        Serveur répond avec SYN-ACK (flags=0x12).

        Comportement attendu :
        - status = "open"
        - is_open = True
        - flags = "SA"
        """
        scanner = ScapyScanner(
            strategy="syn_scan",
            yaml_file=strategy_file_scapy,
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        # Mock Scapy sr1() pour retourner SYN-ACK
        with patch('scanners.ScapyScanner.sr1') as mock_sr1:
            mock_response = Mock()
            mock_response.haslayer.return_value = True

            # TCP layer avec flags SYN-ACK (0x12)
            mock_tcp = Mock()
            mock_flags = Mock()
            mock_flags.__str__ = Mock(return_value="SA")
            mock_flags.__and__ = Mock(return_value=0x12)  # For flags & 0x12
            mock_tcp.flags = mock_flags

            # Mock __getitem__ to return tcp layer
            mock_response.__getitem__ = Mock(return_value=mock_tcp)
            mock_sr1.return_value = mock_response

            # Mock send() pour les decoys
            with patch('scanners.ScapyScanner.send'):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        assert len(details["ports"]) > 0, "Au moins un port devrait être détecté"
        port_data = details["ports"][0]
        assert port_data["port"] == 80
        assert port_data["status"] == "open", "Port devrait être ouvert (SYN-ACK reçu)"
        assert "SA" in str(port_data["response_flags"]) or port_data["response_flags"] == "SA"

    def test_syn_scan_port_ferme_rst_ack(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            strategy_file_scapy
    ):
        """
        Scénario : SYN scan sur port 80 fermé.
        Serveur répond avec RST-ACK (flags=0x14).

        Comportement attendu :
        - status = "closed"
        - is_open = False
        - flags = "RA"
        """
        scanner = ScapyScanner(
            strategy="syn_scan",
            yaml_file=strategy_file_scapy,
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('scanners.ScapyScanner.sr1') as mock_sr1:
            mock_response = Mock()
            mock_response.haslayer.return_value = True

            mock_tcp = Mock()
            mock_flags = Mock()
            mock_flags.__str__ = Mock(return_value="RA")
            mock_flags.__and__ = Mock(return_value=0x14)  # For flags & 0x14
            mock_tcp.flags = mock_flags

            mock_response.__getitem__ = Mock(return_value=mock_tcp)
            mock_sr1.return_value = mock_response

            with patch('scanners.ScapyScanner.send'):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        assert len(details["ports"]) > 0
        port_data = details["ports"][0]
        assert port_data["status"] == "closed", "Port devrait être fermé (RST-ACK reçu)"

    def test_syn_scan_port_filtre_no_response(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            strategy_file_scapy
    ):
        """
        Scénario : SYN scan sur port 443 filtré.
        Firewall DROP les paquets, aucune réponse (timeout).

        Comportement attendu :
        - status = "filtered"
        - is_open = False
        - flags = "none"
        """
        scanner = ScapyScanner(
            strategy="syn_scan",
            yaml_file=strategy_file_scapy,
            process_manager=process_manager_mock
        )
        scanner.ports = "443"

        with patch('scanners.ScapyScanner.sr1') as mock_sr1:
            # sr1 retourne None (timeout)
            mock_sr1.return_value = None

            with patch('scanners.ScapyScanner.send'):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        assert len(details["ports"]) > 0
        port_data = details["ports"][0]
        assert port_data["status"] == "filtered", "Port devrait être filtré (aucune réponse)"
        assert port_data["response_flags"] == "none"

    def test_multi_ports_comportements_mixtes(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            strategy_file_scapy
    ):
        """
        Scénario : Scan de 3 ports avec états différents.
        - Port 22: Ouvert (SYN-ACK)
        - Port 80: Fermé (RST-ACK)
        - Port 443: Filtré (no response)

        Comportement attendu :
        - 3 résultats dans details["ports"]
        - Chacun avec le bon status
        """
        scanner = ScapyScanner(
            strategy="syn_scan",
            yaml_file=strategy_file_scapy,
            process_manager=process_manager_mock
        )
        scanner.ports = "22,80,443"

        # Simuler réponses différentes pour chaque port
        responses = [
            # Port 22: SYN-ACK (ouvert)
            self._create_tcp_response(0x12),
            # Port 80: RST-ACK (fermé)
            self._create_tcp_response(0x14),
            # Port 443: None (filtré)
            None
        ]

        with patch('scanners.ScapyScanner.sr1') as mock_sr1:
            mock_sr1.side_effect = responses

            with patch('scanners.ScapyScanner.send'):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        assert len(details["ports"]) == 3, "3 ports devraient être dans les résultats"

        # Vérifier chaque port
        ports_status = {p["port"]: p["status"] for p in details["ports"]}
        assert ports_status[22] == "open", "Port 22 devrait être ouvert"
        assert ports_status[80] == "closed", "Port 80 devrait être fermé"
        assert ports_status[443] == "filtered", "Port 443 devrait être filtré"

    def _create_tcp_response(self, flags):
        """Helper pour créer un mock de réponse TCP avec flags spécifiques."""
        mock_response = Mock()
        mock_response.haslayer.return_value = True

        mock_tcp = Mock()
        mock_tcp.flags = flags

        mock_response.__getitem__ = Mock(return_value=mock_tcp)
        return mock_response


class TestScapyScannerFINScan:
    """Tests pour FIN scan (logique inversée)."""

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
        - status = "open|filtered"
        - is_open = True
        """
        # Créer stratégie FIN
        yaml_content = """strategies:
  fin_scan:
    scan_type: fin
    ports: "<ports>"
    timeout: 2
"""
        yaml_file = tmp_path / "scapy_fin.yaml"
        yaml_file.write_text(yaml_content)

        scanner = ScapyScanner(
            strategy="fin_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('scanners.ScapyScanner.sr1') as mock_sr1:
            mock_sr1.return_value = None  # Aucune réponse

            with patch('scanners.ScapyScanner.send'):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        port_data = details["ports"][0]
        assert port_data["status"] == "open|filtered", "FIN scan sans réponse = open|filtered"

    def test_fin_scan_port_ferme_rst(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            tmp_path
    ):
        """
        Scénario : FIN scan sur port fermé.
        Port fermé → RST (RFC 793).

        Comportement attendu :
        - status = "closed"
        - is_open = False
        """
        yaml_content = """strategies:
  fin_scan:
    scan_type: fin
    ports: "<ports>"
    timeout: 2
"""
        yaml_file = tmp_path / "scapy_fin.yaml"
        yaml_file.write_text(yaml_content)

        scanner = ScapyScanner(
            strategy="fin_scan",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('scanners.ScapyScanner.sr1') as mock_sr1:
            mock_response = Mock()
            mock_response.haslayer.return_value = True

            mock_tcp = Mock()
            mock_flags = Mock()
            mock_flags.__and__ = Mock(return_value=0x14)  # For flags & 0x14
            mock_tcp.flags = mock_flags

            mock_response.__getitem__ = Mock(return_value=mock_tcp)
            mock_sr1.return_value = mock_response

            with patch('scanners.ScapyScanner.send'):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        port_data = details["ports"][0]
        assert port_data["status"] == "closed", "FIN scan avec RST = closed"

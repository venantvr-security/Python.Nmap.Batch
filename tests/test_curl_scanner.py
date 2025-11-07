"""
Tests pour CurlScanner avec simulation de comportements firewall réalistes.

Ces tests vérifient que CurlScanner interprète correctement :
- Les ports ouverts (bannière capturée)
- Les ports fermés (connection refused)
- Les ports filtrés (timeout)
"""
import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.CurlScanner import CurlScanner


class TestCurlScannerPortInterpretation:
    """Tests d'interprétation des états de ports par CurlScanner."""

    def test_port_ouvert_http_avec_banniere(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            strategy_file_curl
    ):
        """
        Scénario : Port 80 ouvert avec serveur HTTP qui répond.

        Comportement attendu :
        - success = True
        - Port 80 dans la liste des ports ouverts
        - Bannière HTTP capturée
        """
        scanner = CurlScanner(
            strategy="http_basic",
            yaml_file=strategy_file_curl,
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        # Mock subprocess.Popen pour simuler une réponse HTTP
        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.return_value = (
                "HTTP/1.1 200 OK\nServer: nginx/1.18.0\nContent-Type: text/html",
                None
            )
            mock_process.pid = 99999
            mock_process.poll.return_value = 0
            mock_popen.return_value = mock_process

            # Exécuter le scan
            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        # Assertions
        assert success is True, "Le scan aurait dû réussir"
        assert error is None, "Pas d'erreur attendue"
        assert 80 in details["ports"], "Le port 80 devrait être détecté comme ouvert"
        assert "banners" in details, "Les bannières devraient être présentes"
        assert 80 in details["banners"], "Bannière pour le port 80 devrait exister"
        assert "HTTP/1.1 200 OK" in details["banners"][80], "Bannière HTTP devrait être capturée"

    def test_port_ferme_connection_refused(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            strategy_file_curl
    ):
        """
        Scénario : Port 80 fermé (serveur éteint ou port non écouté).

        Comportement attendu :
        - success = True (scan réussi, mais port fermé)
        - Port 80 PAS dans la liste (connection refused détecté)
        """
        scanner = CurlScanner(
            strategy="http_basic",
            yaml_file=strategy_file_curl,
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.return_value = (
                "curl: (7) Failed to connect to 192.168.1.100 port 80: Connection refused",
                None
            )
            mock_process.pid = 99999
            mock_process.poll.return_value = 7
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True, "Le scan devrait réussir même si le port est fermé"
        assert 80 not in details["ports"], "Le port 80 ne devrait PAS être dans les ports ouverts"
        assert len(details["ports"]) == 0, "Aucun port ouvert attendu"

    def test_port_filtre_timeout(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            strategy_file_curl
    ):
        """
        Scénario : Port 443 filtré par firewall (timeout, aucune réponse).

        Comportement attendu :
        - success = True (scan termine malgré timeout)
        - Port 443 PAS dans la liste (timeout = filtré)
        """
        scanner = CurlScanner(
            strategy="http_basic",
            yaml_file=strategy_file_curl,
            process_manager=process_manager_mock
        )
        scanner.ports = "443"

        from subprocess import TimeoutExpired

        with patch('subprocess.Popen') as mock_popen:
            mock_process = Mock()
            mock_process.communicate.side_effect = TimeoutExpired(cmd="curl", timeout=6)
            mock_process.kill = Mock()
            mock_process.pid = 99999
            mock_process.poll.return_value = None
            # Après kill, communicate retourne vide
            mock_process.communicate.side_effect = [TimeoutExpired("", 6), ("", None)]
            mock_popen.return_value = mock_process

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is True, "Le scan devrait réussir même avec timeout"
        assert 443 not in details["ports"], "Le port 443 ne devrait PAS être ouvert (timeout)"

    def test_multi_ports_comportements_mixtes(
            self,
            ip_target,
            thread_id,
            event_queue,
            stop_flag_never,
            process_manager_mock,
            strategy_file_curl
    ):
        """
        Scénario : Scan de plusieurs ports avec comportements différents.
        - Port 80: Ouvert (HTTP)
        - Port 8080: Fermé (connection refused)
        - Port 443: Filtré (timeout)

        Comportement attendu :
        - Seul le port 80 détecté comme ouvert
        """
        scanner = CurlScanner(
            strategy="http_basic",
            yaml_file=strategy_file_curl,
            process_manager=process_manager_mock
        )
        scanner.ports = "80,443,8080"

        from subprocess import TimeoutExpired

        responses = [
            # Port 80: ouvert
            ("HTTP/1.1 200 OK\nServer: Apache", None),
            # Port 443: timeout
            TimeoutExpired("", 6),
            # Port 8080: fermé
            ("curl: (7) Failed to connect to 192.168.1.100 port 8080: Connection refused", None),
        ]

        with patch('subprocess.Popen') as mock_popen:
            call_count = [0]

            def side_effect_communicate(timeout=None):
                response = responses[call_count[0]]
                call_count[0] += 1
                if isinstance(response, Exception):
                    raise response
                return response

            mock_process = Mock()
            mock_process.communicate = side_effect_communicate
            mock_process.kill = Mock()
            mock_process.pid = 99999
            mock_process.poll.return_value = 0
            mock_popen.return_value = mock_process

            # Bypass du timeout sur le 2e appel
            with patch.object(mock_process, 'communicate', side_effect=[
                ("HTTP/1.1 200 OK\nServer: Apache", None),
                TimeoutExpired("", 6),
                ("", None),  # Après kill du timeout
                ("curl: (7) Failed to connect to 192.168.1.100 port 8080: Connection refused", None)
            ]):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        assert details["ports"] == [80], "Seul le port 80 devrait être ouvert"
        assert 80 in details["banners"]
        assert "HTTP/1.1 200 OK" in details["banners"][80]

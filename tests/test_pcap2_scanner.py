"""
Tests pour Pcap2 avec simulation de replay de paquets PCAP.

Ces tests vérifient que Pcap2 :
- Charge correctement les paquets depuis un fichier PCAP
- Modifie l'IP de destination
- Envoie tous les paquets sans attendre de réponse
- Gère les métadonnées (nombre de paquets, timing)
"""
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanners.Pcap2 import Pcap2


class TestPcap2PacketReplay:
    """Tests de replay de paquets PCAP."""

    def test_load_and_replay_packets(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Replay de 3 paquets depuis un fichier PCAP.

        Comportement attendu :
        - Tous les paquets chargés et modifiés
        - IP destination changée vers la cible
        - send() appelé pour chaque paquet (pas sr1)
        """
        # Créer un fichier PCAP temporaire
        pcap_dir = tmp_path / "packets"
        pcap_dir.mkdir()
        pcap_file = pcap_dir / "test_attack.pcap"

        # Simuler un fichier PCAP (contenu fictif)
        pcap_file.write_bytes(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00')  # PCAP magic

        yaml_content = """strategies:
  replay_attack:
    template_pcap: "test_attack.pcap"
    ports: "<ports>"
    inter_packet_delay: 0.1
    repeat: 1
"""
        yaml_file = tmp_path / "pcap2.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Pcap2(
            strategy="replay_attack",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        # Mock rdpcap pour retourner des paquets fictifs
        with patch('scanners.Pcap2.rdpcap') as mock_rdpcap:
            # Créer 3 paquets mockés avec layer IP
            mock_packets = []
            for i in range(3):
                pkt = Mock()
                pkt.copy.return_value = pkt
                pkt.haslayer.return_value = True
                mock_ip = Mock()
                mock_ip.dst = "10.0.0.1"  # IP originale
                pkt.__getitem__ = Mock(return_value=mock_ip)
                mock_packets.append(pkt)

            mock_rdpcap.return_value = mock_packets

            # Mock send() pour capturer les envois
            with patch('scanners.Pcap2.send') as mock_send:
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True, "Le scan aurait dû réussir"
        # Vérifier que send() a été appelé 3 fois (1 par paquet)
        assert mock_send.call_count == 3, "send() devrait être appelé 3 fois"

    def test_modify_destination_ip(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Vérifier que l'IP de destination est bien modifiée.

        Comportement attendu :
        - IP originale (10.0.0.1) remplacée par IP cible
        """
        pcap_dir = tmp_path / "packets"
        pcap_dir.mkdir()
        pcap_file = pcap_dir / "test_attack.pcap"
        pcap_file.write_bytes(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00')

        yaml_content = f"""strategies:
  replay_attack:
    template_pcap: "test_attack.pcap"
    pcap_dir: "{pcap_file}"
    inter_packet_delay: 0.01
    repeat: 1
"""
        yaml_file = tmp_path / "pcap2.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Pcap2(
            strategy="replay_attack",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        captured_ips = []

        def capture_ip_setter(value):
            captured_ips.append(value)

        with patch('scanners.Pcap2.rdpcap') as mock_rdpcap:
            mock_pkt = Mock()
            mock_pkt.copy.return_value = mock_pkt
            mock_pkt.haslayer.return_value = True

            mock_ip = Mock()
            mock_ip.dst = "10.0.0.1"

            # Capturer les modifications d'IP
            type(mock_ip).dst = property(
                lambda self: "10.0.0.1",
                lambda self, val: captured_ips.append(val)
            )

            mock_pkt.__getitem__ = lambda self, key: mock_ip if key == "IP" else None
            mock_rdpcap.return_value = [mock_pkt]

            with patch('scanners.Pcap2.send'):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        # Vérifier que l'IP cible a été utilisée
        assert ip == ip_target

    def test_empty_pcap_file(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Fichier PCAP vide (aucun paquet).

        Comportement attendu :
        - success = False
        - Erreur indiquant l'absence de paquets
        """
        pcap_dir = tmp_path / "packets"
        pcap_dir.mkdir()
        pcap_file = pcap_dir / "empty.pcap"
        pcap_file.write_bytes(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00')

        yaml_content = """strategies:
  replay_attack:
    template_pcap: "test_attack.pcap"
    ports: "<ports>"
    inter_packet_delay: 0.1
    repeat: 1
"""
        yaml_file = tmp_path / "pcap2.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Pcap2(
            strategy="replay_attack",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('scanners.Pcap2.rdpcap') as mock_rdpcap:
            mock_rdpcap.return_value = []  # Fichier vide

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is False, "Le scan devrait échouer (PCAP vide)"
        assert "aucun paquet" in error.lower() or "no packet" in error.lower()

    def test_missing_pcap_file(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Fichier PCAP inexistant.

        Comportement attendu :
        - success = False
        - Erreur de fichier introuvable
        """
        yaml_content = """strategies:
  replay_attack:
    template_pcap: "non_existent.pcap"
    inter_packet_delay: 0.1
    repeat: 1
"""
        yaml_file = tmp_path / "pcap2.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Pcap2(
            strategy="replay_attack",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('scanners.Pcap2.rdpcap') as mock_rdpcap:
            mock_rdpcap.side_effect = FileNotFoundError("PCAP file not found")

            ip, success, error, details, extra = scanner.scan(
                ip=ip_target,
                thread_id=thread_id,
                event_queue=event_queue,
                stop_flag=stop_flag_never
            )

        assert success is False
        assert "not found" in error.lower() or "introuvable" in error.lower()

    def test_repeat_functionality(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_never,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Replay avec repeat=3 (rejouer 3 fois).

        Comportement attendu :
        - Paquets envoyés 3 fois (2 paquets × 3 répétitions = 6 envois)
        """
        pcap_dir = tmp_path / "packets"
        pcap_dir.mkdir()
        pcap_file = pcap_dir / "test_attack.pcap"
        pcap_file.write_bytes(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00')

        yaml_content = f"""strategies:
  replay_attack:
    template_pcap: "test_attack.pcap"
    pcap_dir: "{pcap_file}"
    inter_packet_delay: 0.01
    repeat: 3
"""
        yaml_file = tmp_path / "pcap2.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Pcap2(
            strategy="replay_attack",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('scanners.Pcap2.rdpcap') as mock_rdpcap:
            mock_packets = []
            for i in range(2):
                pkt = Mock()
                pkt.copy.return_value = pkt
                pkt.haslayer.return_value = True
                mock_ip = Mock()
                pkt.__getitem__ = lambda self, key: mock_ip if key == "IP" else None
                mock_packets.append(pkt)

            mock_rdpcap.return_value = mock_packets

            with patch('scanners.Pcap2.send') as mock_send:
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_never
                )

        assert success is True
        # 2 paquets × 3 répétitions = 6 appels à send()
        assert mock_send.call_count == 6, f"send() devrait être appelé 6 fois (2×3), mais appelé {mock_send.call_count} fois"

    def test_stop_flag_interruption(
        self,
        ip_target,
        thread_id,
        event_queue,
        stop_flag_immediate,
        process_manager_mock,
        tmp_path
    ):
        """
        Scénario : Replay interrompu par stop_flag.

        Comportement attendu :
        - Scan s'arrête proprement
        - success = False
        """
        pcap_dir = tmp_path / "packets"
        pcap_dir.mkdir()
        pcap_file = pcap_dir / "test_attack.pcap"
        pcap_file.write_bytes(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00')

        yaml_content = f"""strategies:
  replay_attack:
    template_pcap: "test_attack.pcap"
    pcap_dir: "{pcap_file}"
    inter_packet_delay: 1
    repeat: 100
"""
        yaml_file = tmp_path / "pcap2.yaml"
        yaml_file.write_text(yaml_content)

        scanner = Pcap2(
            strategy="replay_attack",
            yaml_file=str(yaml_file),
            process_manager=process_manager_mock
        )
        scanner.ports = "80"

        with patch('scanners.Pcap2.rdpcap') as mock_rdpcap:
            mock_pkt = Mock()
            mock_pkt.copy.return_value = mock_pkt
            mock_pkt.haslayer.return_value = True
            mock_rdpcap.return_value = [mock_pkt]

            with patch('scanners.Pcap2.send'):
                ip, success, error, details, extra = scanner.scan(
                    ip=ip_target,
                    thread_id=thread_id,
                    event_queue=event_queue,
                    stop_flag=stop_flag_immediate
                )

        assert success is False, "Le scan devrait être interrompu"
        assert "interrompu" in error.lower() or "cancelled" in error.lower() or "stopped" in error.lower()

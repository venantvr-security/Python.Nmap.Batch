import math
import random
import time
from typing import Dict, List, Tuple

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw


class AdvancedEvasion:
    """Module de techniques d'évasion avancées pour contourner firewalls IA"""

    # Options TCP réalistes par OS
    OS_FINGERPRINTS = {
        "windows10": [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')],
        "windows11": [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('Timestamp', (0, 0))],
        "linux": [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (0, 0)), ('NOP', None), ('WScale', 7)],
        "macos": [('MSS', 1460), ('NOP', None), ('WScale', 6), ('SAckOK', b''), ('Timestamp', (0, 0))],
        "ios": [('MSS', 1460), ('NOP', None), ('WScale', 4), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('Timestamp', (0, 0))],
        "android": [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (0, 0)), ('NOP', None), ('WScale', 8)],
    }

    # Payloads protocoles légitimes
    PROTOCOL_PAYLOADS = {
        80: b"GET / HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        443: b"\x16\x03\x03\x00\x00",  # TLS 1.2 ClientHello
        53: b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",  # DNS query
        22: b"SSH-2.0-OpenSSH_8.9p1\r\n",
        21: b"USER anonymous\r\n",
        25: b"EHLO client.example.com\r\n",
        110: b"USER test\r\n",
        143: b"A001 CAPABILITY\r\n",
    }

    @staticmethod
    def get_realistic_tcp_options(os_type: str) -> List[Tuple]:
        """Retourne options TCP réalistes selon OS"""
        return AdvancedEvasion.OS_FINGERPRINTS.get(os_type, AdvancedEvasion.OS_FINGERPRINTS["linux"])

    @staticmethod
    def get_fake_timestamp(fake_uptime_days: int = 30) -> Tuple[int, int]:
        """Génère timestamp TCP mimant un uptime spécifique"""
        current_ts = int(time.time() * 100)
        fake_ts = current_ts - (fake_uptime_days * 86400 * 100)
        return fake_ts % 0xFFFFFFFF, 0

    @staticmethod
    def get_realistic_seq_number(mode: str = "timestamp_based") -> int:
        """Génère ISN TCP réaliste"""
        if mode == "timestamp_based":
            # RFC 6528: ISN basé sur timestamp
            return int(time.time() * 250000) & 0xFFFFFFFF
        elif mode == "incremental":
            return random.randint(1000, 100000)
        else:
            return random.randint(0, 0xFFFFFFFF)

    @staticmethod
    def get_polymorphic_delay(port_index: int, base_delay: float, pattern: str = "exponential") -> float:
        """Génère délai non-linéaire pour éviter détection ML"""
        patterns = {
            "exponential": lambda i: base_delay * (1.5 ** (i % 5)),
            "fibonacci": lambda i: base_delay * ([1, 1, 2, 3, 5, 8, 13][i % 7]),
            "prime": lambda i: base_delay * ([2, 3, 5, 7, 11, 13, 17][i % 7] / 10),
            "sine": lambda i: base_delay * (1 + 0.5 * math.sin(i * 0.5)),
            "random": lambda i: base_delay * random.uniform(0.5, 2.0),
        }
        return patterns.get(pattern, patterns["exponential"])(port_index)

    @staticmethod
    def add_protocol_mimicry(packet: Packet, port: int) -> Packet:
        """Ajoute payload imitant protocole légitime"""
        if port in AdvancedEvasion.PROTOCOL_PAYLOADS:
            return packet / Raw(AdvancedEvasion.PROTOCOL_PAYLOADS[port])
        return packet

    @staticmethod
    def get_realistic_window_size(os_type: str) -> int:
        """Window size TCP réaliste selon OS"""
        windows = {
            "windows10": 64240,
            "windows11": 65535,
            "linux": 29200,
            "macos": 65535,
            "ios": 65535,
            "android": 65535,
        }
        return windows.get(os_type, 29200)

    @staticmethod
    def get_realistic_ttl(os_type: str, randomize: bool = False) -> int:
        """TTL réaliste selon OS"""
        ttls = {
            "windows10": 128,
            "windows11": 128,
            "linux": 64,
            "macos": 64,
            "ios": 64,
            "android": 64,
        }
        base_ttl = ttls.get(os_type, 64)

        if randomize:
            # Variation réaliste (routeurs intermédiaires)
            return base_ttl - random.randint(1, 15)
        return base_ttl

    @staticmethod
    def get_random_ipid(mode: str = "random") -> int:
        """Génère IPID avec différents modes"""
        if mode == "random":
            # Totalement aléatoire (éviter corrélation)
            return random.randint(0, 65535)
        elif mode == "incremental":
            # Séquentiel (comportement OS classique)
            return random.randint(1000, 10000)
        elif mode == "zero":
            # IPID=0 (certains OS modernes)
            return 0
        elif mode == "odd":
            # Uniquement impairs (BSD)
            return random.randrange(1, 65535, 2)
        else:
            return random.randint(0, 65535)

    @staticmethod
    def get_ephemeral_port(os_type: str) -> int:
        """Port source éphémère réaliste selon OS"""
        ranges = {
            "windows10": (49152, 65535),  # RFC 6335
            "windows11": (49152, 65535),
            "linux": (32768, 60999),
            "macos": (49152, 65535),
            "ios": (49152, 65535),
            "android": (32768, 61000),
        }
        start, end = ranges.get(os_type, (49152, 65535))
        return random.randint(start, end)

    @staticmethod
    def apply_advanced_evasion(packet: Packet, strategy: Dict) -> Packet:
        """Pipeline complet de transformations anti-IA"""
        if not packet.haslayer(TCP):
            return packet

        os_type = strategy.get("os_fingerprint", "linux")

        # 1. Options TCP réalistes
        if strategy.get("realistic_tcp_options", True):
            options = AdvancedEvasion.get_realistic_tcp_options(os_type)

            # Remplacer timestamp si présent
            if strategy.get("fake_uptime_days"):
                ts = AdvancedEvasion.get_fake_timestamp(strategy["fake_uptime_days"])
                options = [(k, ts if k == "Timestamp" else v) for k, v in options]

            packet[TCP].options = options

        # 2. Window size réaliste
        if strategy.get("realistic_window"):
            packet[TCP].window = AdvancedEvasion.get_realistic_window_size(os_type)

        # 3. SEQ number réaliste
        if strategy.get("seq_mode"):
            packet[TCP].seq = AdvancedEvasion.get_realistic_seq_number(strategy["seq_mode"])

        # 4. TTL réaliste
        if packet.haslayer(IP) and strategy.get("realistic_ttl"):
            packet[IP].ttl = AdvancedEvasion.get_realistic_ttl(
                os_type, strategy.get("randomize_ttl", False)
            )

        # 5. IPID manipulation
        if packet.haslayer(IP) and strategy.get("ipid_mode"):
            packet[IP].id = AdvancedEvasion.get_random_ipid(strategy["ipid_mode"])

        # 6. Protocol mimicry
        if strategy.get("protocol_mimicry") and packet.haslayer(TCP):
            port = packet[TCP].dport
            packet = AdvancedEvasion.add_protocol_mimicry(packet, port)

        return packet

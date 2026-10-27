
from collections import defaultdict, deque
from time import time

from scapy.all import IP, TCP


class PortScanDetector:
    def __init__(self, threshold=10, time_window=10):
        self.threshold = threshold
        self.time_window = time_window
        self.connections = defaultdict(deque)
        self.alerted_ips = set()

    def analyze_packet(self, packet):
        if IP not in packet or TCP not in packet:
            return None

        # Detect initial TCP connection attempts (SYN set, ACK unset)
        tcp_flags = packet[TCP].flags
        if not (tcp_flags & 0x02) or (tcp_flags & 0x10):
            return None

        source_ip = packet[IP].src
        destination_port = packet[TCP].dport
        current_time = time()

        attempts = self.connections[source_ip]
        attempts.append((current_time, destination_port))

        # Keep only attempts from the last time_window seconds
        while attempts and current_time - attempts[0][0] > self.time_window:
            attempts.popleft()

        unique_ports = {port for _, port in attempts}

        if (
            len(unique_ports) >= self.threshold
            and source_ip not in self.alerted_ips
        ):
            self.alerted_ips.add(source_ip)
            return {
                "alert": "POSSIBLE TCP PORT SCAN",
                "source_ip": source_ip,
                "unique_ports": len(unique_ports),
                "ports": sorted(unique_ports),
                "severity": "HIGH",
            }

        return None

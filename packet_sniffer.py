
from scapy.all import sniff, IP, TCP, UDP, ICMP
from detectors.port_scan import PortScanDetector

# Network settings
INTERFACE = "Wi-Fi"
PACKET_LIMIT = 0  # 0 means keep capturing until Ctrl+C

# Create the port-scan detector
detector = PortScanDetector()


def analyze_packet(packet):
    """Display packet details and check for possible port scans."""

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol_number = packet[IP].proto

    source_port = "-"
    destination_port = "-"

    if TCP in packet:
        protocol_name = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol_name = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol_name = "ICMP"

    else:
        protocol_name = str(protocol_number)

    print(f"Source IP:        {source_ip}")
    print(f"Destination IP:   {destination_ip}")
    print(f"Protocol:         {protocol_name}")
    print(f"Source Port:      {source_port}")
    print(f"Destination Port: {destination_port}")
    print("-" * 45)

    # Check the packet for possible TCP port-scan activity
    alert = detector.analyze_packet(packet)

    if alert:
        print("\n!!! SECURITY ALERT !!!")
        for key, value in alert.items():
            print(f"{key}: {value}")
        print("-" * 45)


def main():
    print("=" * 50)
    print("PYTHON NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 50)
    print(f"Network interface: {INTERFACE}")
    print("Port-scan threshold: 10 unique TCP ports")
    print("Detection time window: 10 seconds")
    print("Capturing packets continuously.")
    print("Press Ctrl+C to stop.")
    print("=" * 50)

    try:
        sniff(
            iface=INTERFACE,
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nPacket capture stopped by user.")

    except Exception as error:
        print(f"\nError during packet capture: {error}")
        print("Check the interface name and required permissions.")

    finally:
        print("NIDS stopped.")


if __name__ == "__main__":
    main()

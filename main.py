
from collections import defaultdict

PORT_SCAN_THRESHOLD = 5
connections = defaultdict(set)


def analyze_event(source_ip, destination_port):
    """Detect a source IP contacting multiple unique ports."""
    connections[source_ip].add(destination_port)
    port_count = len(connections[source_ip])

    if port_count >= PORT_SCAN_THRESHOLD:
        return {
            "alert": "POSSIBLE PORT SCAN",
            "source_ip": source_ip,
            "ports_contacted": port_count,
            "severity": "HIGH",
        }

    return None


def main():
    # Simulated traffic for our first detection test
    test_events = [
        ("192.168.1.50", 21),
        ("192.168.1.50", 22),
        ("192.168.1.50", 23),
        ("192.168.1.50", 80),
        ("192.168.1.50", 443),
    ]

    print("Python Network IDS started")
    print("-" * 40)

    for source_ip, destination_port in test_events:
        print(f"Traffic: {source_ip} -> port {destination_port}")
        alert = analyze_event(source_ip, destination_port)

        if alert:
            print("\n!!! SECURITY ALERT !!!")
            for key, value in alert.items():
                print(f"{key}: {value}")
            print("-" * 40)


if __name__ == "__main__":
    main()

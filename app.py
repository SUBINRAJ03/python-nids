
from flask import Flask, render_template_string, redirect, url_for
from datetime import datetime
from threading import Lock
from collections import deque

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP
from detectors.port_scan import PortScanDetector

app = Flask(__name__)

# Network configuration
INTERFACE = "Wi-Fi"

# Shared dashboard data
data_lock = Lock()
control_lock = Lock()

detector = PortScanDetector(threshold=10, time_window=10)

packets = deque(maxlen=100)
alerts = deque(maxlen=50)

stats = {
    "packet_count": 0,
    "status": "Stopped",
    "monitoring": False
}

sniffer = None


def analyze_packet(packet):
    """Analyze packets and update the dashboard."""

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    sport = "-"
    dport = "-"
    protocol = str(packet[IP].proto)

    if TCP in packet:
        protocol = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
    elif ICMP in packet:
        protocol = "ICMP"

    packet_record = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "sport": sport,
        "dport": dport
    }

    alert = detector.analyze_packet(packet)

    with data_lock:
        stats["packet_count"] += 1
        packets.appendleft(packet_record)

        if alert:
            alert["time"] = datetime.now().strftime("%H:%M:%S")
            alerts.appendleft(alert)


def start_monitoring():
    """Start packet capture if it is not already running."""
    global sniffer

    with control_lock:
        if stats["monitoring"]:
            return

        try:
            new_sniffer = AsyncSniffer(
                iface=INTERFACE,
                prn=analyze_packet,
                store=False
            )
            new_sniffer.start()
            sniffer = new_sniffer

            with data_lock:
                stats["monitoring"] = True
                stats["status"] = f"Monitoring {INTERFACE}"

            print(f"Monitoring started on {INTERFACE}")

        except Exception as error:
            with data_lock:
                stats["monitoring"] = False
                stats["status"] = f"Capture error: {error}"

            print(f"Could not start capture: {error}")


def stop_monitoring():
    """Stop packet capture safely."""
    global sniffer

    with control_lock:
        current_sniffer = sniffer
        sniffer = None

        try:
            if current_sniffer and current_sniffer.running:
                current_sniffer.stop()

            with data_lock:
                stats["monitoring"] = False
                stats["status"] = "Stopped"

            print("Monitoring stopped")

        except Exception as error:
            with data_lock:
                stats["monitoring"] = False
                stats["status"] = f"Stop error: {error}"

            print(f"Could not stop capture: {error}")


@app.route("/")
def dashboard():
    with data_lock:
        packet_snapshot = list(packets)
        alert_snapshot = list(alerts)
        packet_count = stats["packet_count"]
        status = stats["status"]
        monitoring = stats["monitoring"]

    return render_template_string(
        HTML_PAGE,
        packets=packet_snapshot,
        alerts=alert_snapshot,
        packet_count=packet_count,
        alert_count=len(alert_snapshot),
        high_count=sum(
            1 for a in alert_snapshot if a["severity"] == "HIGH"
        ),
        status=status,
        monitoring=monitoring,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


@app.route("/start", methods=["POST"])
def start_route():
    start_monitoring()
    return redirect(url_for("dashboard"))


@app.route("/stop", methods=["POST"])
def stop_route():
    stop_monitoring()
    return redirect(url_for("dashboard"))


@app.route("/test-alert")
def test_alert():
    """Add a simulated alert for local testing only."""
    with data_lock:
        alerts.appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "alert": "TEST: POSSIBLE TCP PORT SCAN",
            "source_ip": "192.0.2.10",
            "unique_ports": 10,
            "ports": [21, 22, 23, 25, 53, 80, 110, 443, 445, 8080],
            "severity": "HIGH"
        })

    return redirect(url_for("dashboard"))


HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="3">
<title>Python NIDS Dashboard</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    padding: 28px;
    background: #0b1120;
    color: #e5e7eb;
    font-family: Arial, sans-serif;
}
header { margin-bottom: 26px; }
h1 { color: #38bdf8; }
.muted { color: #94a3b8; }
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.card, .panel {
    background: #151f32;
    border: 1px solid #263449;
    border-radius: 12px;
    padding: 20px;
}
.card p { color: #94a3b8; }
.number { font-size: 30px; font-weight: bold; }
.panel { margin-bottom: 22px; overflow-x: auto; }
h2 { font-size: 19px; }
table { width: 100%; border-collapse: collapse; }
th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #263449;
}
th { color: #7dd3fc; }
.high { color: #f87171; font-weight: bold; }
.empty { color: #94a3b8; }
.status { color: #4ade80; font-weight: bold; }
.controls {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin: 20px 0;
}
button {
    border: 0;
    border-radius: 8px;
    padding: 12px 20px;
    font-size: 15px;
    font-weight: bold;
    cursor: pointer;
}
.start { background: #16a34a; color: white; }
.stop { background: #dc2626; color: white; }
button:disabled { opacity: 0.45; cursor: not-allowed; }
footer { color: #64748b; font-size: 13px; margin-top: 20px; }
</style>
</head>
<body>
<header>
    <h1>Python Network IDS</h1>
    <p class="muted">Network Intrusion Detection System</p>
    <p class="status">● {{ status }}</p>
    <p class="muted">Interface: Wi-Fi | Updated: {{ now }}</p>
</header>

<section class="controls">
    <form action="/start" method="post">
        <button class="start" type="submit"
            {% if monitoring %}disabled{% endif %}>
            Start Monitoring
        </button>
    </form>

    <form action="/stop" method="post">
        <button class="stop" type="submit"
            {% if not monitoring %}disabled{% endif %}>
            Stop Monitoring
        </button>
    </form>
</section>

<section class="cards">
    <div class="card">
        <p>Packets Captured</p>
        <div class="number">{{ packet_count }}</div>
    </div>
    <div class="card">
        <p>Security Alerts</p>
        <div class="number">{{ alert_count }}</div>
    </div>
    <div class="card">
        <p>High Severity Alerts</p>
        <div class="number">{{ high_count }}</div>
    </div>
</section>

<section class="panel">
<h2>Recent Network Packets</h2>
<table>
<tr>
    <th>Time</th><th>Source IP</th><th>Destination IP</th>
    <th>Protocol</th><th>Source Port</th><th>Destination Port</th>
</tr>
{% for p in packets %}
<tr>
    <td>{{ p.time }}</td><td>{{ p.src }}</td><td>{{ p.dst }}</td>
    <td>{{ p.protocol }}</td><td>{{ p.sport }}</td><td>{{ p.dport }}</td>
</tr>
{% else %}
<tr><td colspan="6" class="empty">No packets captured yet.</td></tr>
{% endfor %}
</table>
</section>

<section class="panel">
<h2>Security Alerts</h2>
<table>
<tr>
    <th>Time</th><th>Alert</th><th>Source IP</th>
    <th>Unique Ports</th><th>Severity</th>
</tr>
{% for a in alerts %}
<tr>
    <td>{{ a.time }}</td><td>{{ a.alert }}</td><td>{{ a.source_ip }}</td>
    <td>{{ a.unique_ports }}</td><td class="high">{{ a.severity }}</td>
</tr>
{% else %}
<tr><td colspan="5" class="empty">No security alerts detected yet.</td></tr>
{% endfor %}
</table>
</section>

<footer>
Educational project. Test alerts are simulated.
Alerts indicate possible suspicious activity, not confirmed attacks.
Only monitor networks you are authorized to inspect.
</footer>
</body>
</html>
"""


if __name__ == "__main__":
    print("Starting Python NIDS dashboard...")
    print("Open http://127.0.0.1:5000 in your browser.")
    print("Use the dashboard buttons to control packet capture.")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )

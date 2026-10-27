# Python Network Intrusion Detection System (NIDS)

## Overview

A Python-based Network Intrusion Detection System (NIDS) that captures network packets, analyzes TCP traffic, and detects potential TCP port-scanning activity. The project includes a Flask web dashboard for monitoring packets and viewing security alerts.

## Features

- **Live Packet Capture:** Capture network traffic using Scapy.
- **TCP Port Scan Detection:** Identify a possible scan when a source IP attempts connections to multiple unique ports within a configured time window.
- **Web Dashboard:** View captured packets, packet counts, monitoring status, and security alerts.
- **Monitoring Controls:** Start, stop, and restart packet monitoring.
- **Alert Severity:** Display detected port-scan alerts with severity information.
- **Testing Support:** Generate a test alert to verify dashboard functionality.

## Technologies Used

- Python
- Scapy
- Flask
- HTML
- TCP/IP networking

## Project Structure

```text
python-nids/
├── app.py
├── main.py
├── packet_sniffer.py
├── detectors/
│   └── port_scan.py
└── README.md
```

## Requirements

- Python 3
- Npcap on Windows for packet capture
- Required Python packages: Scapy and Flask

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/SUBINRAJ03/python-nids.git
   cd python-nids
   ```

2. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

3. Activate it on Windows:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```bash
   python -m pip install scapy flask
   ```

5. Install Npcap if needed for Windows packet capture.

## Run the Application

From the project root directory, run:

```powershell
python app.py
```

Open the dashboard in your browser:

http://127.0.0.1:5000

Select the monitoring controls on the dashboard to start or stop packet capture.

## Detection Logic

The port-scan detector examines initial TCP SYN packets and tracks unique destination ports for each source IP within a configurable time window. When the number of unique ports reaches the configured threshold, it generates a possible port-scan alert.

## Limitations

- This is an educational, rule-based detection project, not a production-grade IDS.
- Detection depends on the configured threshold, time window, capture interface, and available packet visibility.
- Real port-scan detection should be tested in an authorized lab environment.

## Future Improvements

- Add additional detection rules for suspicious traffic.
- Export alerts to CSV or JSON.
- Add packet and alert filtering to the dashboard.
- Improve logging, error handling, and automated testing.
- Integrate with SIEM platforms for further investigation.

## Disclaimer

For educational and authorized security testing only. Monitor only networks and systems you own or have explicit permission to test.

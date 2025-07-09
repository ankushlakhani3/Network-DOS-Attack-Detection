# DoS Attack Detection and Mitigation Using POX Controller and Mininet

## Overview
This project demonstrates real-time monitoring, detection, and mitigation of Denial-of-Service (DoS) attacks using the POX SDN controller with a custom traffic monitoring module and a Mininet virtual network topology.

## Features
- Custom Mininet topology simulating hosts and switches
- POX controller module (`traffic_monitoring.py`) for traffic analysis
- Real-time anomaly detection (packet rate, throughput)
- Automatic blocking of malicious IPs via flow modifications
- Verification of legitimate traffic continuity during attacks
- Optional Wireshark traffic analysis for deeper inspection

## Setup and Usage

### 1. Install Dependencies
- Python 3
- Mininet
- POX controller
- hping3, iperf (for traffic simulation)
- Wireshark (optional for packet capture)

### 2. Clone POX Controller
```bash
git clone https://github.com/noxrepo/pox.git
cd pox
3. Configure Network Topology
Place topology.py in your working directory.

Run the topology:

bash
Copy
Edit
sudo python3 topology.py
Verify connectivity:

bash
Copy
Edit
pingall
4. Configure POX Controller
Place traffic_monitoring.py in pox/ext/.

Run the POX controller with your module:

bash
Copy
Edit
./pox.py traffic_monitoring
5. Simulate Traffic
Open Mininet CLI:

bash
Copy
Edit
sudo python3 topology.py
Start HTTP server on host h3:

bash
Copy
Edit
xterm h3
python3 -m http.server 80
Generate normal traffic from h1:

bash
Copy
Edit
xterm h1
iperf -c <h3_IP> -u -b 10M -t 60
Simulate DoS attack from h2:

bash
Copy
Edit
xterm h2
hping3 -S --flood -V -p 80 <h3_IP>
6. Monitor and Mitigate
Watch POX controller logs for anomalies and blocking actions.

Confirm malicious IP blocking by pinging h3 from h2 (should fail).

Verify legitimate traffic continues uninterrupted.

7. (Optional) Wireshark Analysis
bash
Copy
Edit
sudo apt-get install wireshark
sudo wireshark
Capture and filter traffic on Mininet interfaces.

Testing
Monitor POX logs for connection, traffic stats, and anomaly alerts.

Verify traffic blocking and legitimate traffic flow.

Observe network behavior changes under attack and mitigation.

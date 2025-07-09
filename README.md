# DoS Attack Detection and Mitigation Using POX Controller and Mininet

## Overview  
This project demonstrates real-time monitoring, detection, and mitigation of Denial-of-Service (DoS) attacks in an SDN environment. It uses a custom POX controller module (`traffic_monitoring.py`) and a Mininet virtual network topology to simulate both legitimate and malicious traffic, detect anomalies, and automatically block offending hosts.

---

## Table of Contents  
- [Features](#features)  
- [Prerequisites](#prerequisites)  
- [Installation](#installation)  
- [Network Topology](#network-topology)  
- [Usage](#usage)  
  - [1. Start Mininet Topology](#1-start-mininet-topology)  
  - [2. Launch POX Controller](#2-launch-pox-controller)  
  - [3. Simulate Traffic](#3-simulate-traffic)  
  - [4. Monitor & Mitigate](#4-monitor--mitigate)  
- [Test Cases](#test-cases)  
- [Wireshark Analysis (Optional)](#wireshark-analysis-optional)  
- [Performance Verification](#performance-verification)  
- [Contributing](#contributing)  
- [License](#license)  

---

## Features  
- Custom Mininet topology with multiple hosts and switches  
- Traffic‐monitoring POX module to compute per‐port byte and packet rates  
- Anomaly detection based on configurable thresholds (packet rate, throughput)  
- Dynamic flow‐rule insertion to block malicious IPs  
- Real‐time controller logging for visibility  

---

## Prerequisites  
- Python 3.x  
- Mininet 2.3+  
- POX SDN controller  
- `hping3`, `iperf3` (for traffic generation)  
- (Optional) Wireshark  

---

## Installation
# 1. Clone POX
git clone https://github.com/noxrepo/pox.git
cd pox

# 2. Place controller module
# Copy your traffic_monitoring.py into the pox/ext directory
cp /path/to/traffic_monitoring.py ext/

# 3. Copy the Mininet topology script
# Save topology.py into your working directory (outside the pox/ tree)
cp /path/to/topology.py ~/mininet_topo/

2. Place controller module
Copy traffic_monitoring.py into the pox/ext directory

bash
Copy
Edit
cp /path/to/traffic_monitoring.py ext/
3. Copy Mininet topology script
Save topology.py into your working directory (outside the pox/ directory)

bash
Copy
Edit
cp /path/to/topology.py ~/mininet_topo/
Network Topology
The custom topology simulates multiple hosts and switches as defined in topology.py.

Use Mininet CLI commands to verify connectivity and test network behavior.

Usage
1. Start Mininet Topology
bash
Copy
Edit
sudo python3 ~/mininet_topo/topology.py
Verify connectivity using:

bash
Copy
Edit
pingall
2. Launch POX Controller
bash
Copy
Edit
cd pox
./pox.py traffic_monitoring
For detailed debugging logs, run:

bash
Copy
Edit
./pox.py log.level --DEBUG traffic_monitoring
3. Simulate Traffic
Open terminal windows for hosts using xterm:

bash
Copy
Edit
xterm h3
python3 -m http.server 80     # Start HTTP server on h3
bash
Copy
Edit
xterm h1
iperf -c <h3_IP> -u -b 10M -t 60   # Normal traffic from h1 to h3
bash
Copy
Edit
xterm h2
hping3 -S --flood -V -p 80 <h3_IP>   # Simulate SYN flood DoS attack from h2 to h3
4. Monitor & Mitigate
Watch POX controller logs for anomaly detection and blocking notifications.

Confirm blocking by pinging h3 from h2 (ping should fail if blocked).

Validate that legitimate traffic from other hosts continues normally.

Test Cases
Monitor Controller Logs
Start POX controller and verify switch connections and traffic stats.

Look for log entries indicating anomalies and blocked IPs.

Generate Traffic and Simulate Attacks
Use iperf for normal traffic and hping3 for malicious traffic.

Confirm POX logs detect anomalies and block attackers.

Verify Blocking and Legitimate Traffic Flow
Confirm malicious IPs are blocked with flow mods.

Check legitimate hosts maintain connectivity.

Wireshark Analysis (Optional)
Install Wireshark
bash
Copy
Edit
sudo apt-get install wireshark
sudo wireshark
Capture Traffic
Capture traffic on Mininet virtual interfaces.

Use filters like tcp.port == 80 to observe HTTP traffic and attack patterns.

Performance Verification
Measure server response time and throughput under normal conditions (e.g., ~20ms response, 10MB/s throughput).

During attacks, expect degraded performance (response time >50ms, throughput <5MB/s).

After mitigation, confirm server performance returns to baseline.

Contributing
Contributions, issues, and feature requests are welcome!

Feel free to fork the repository and submit pull requests.

License
This project is licensed under the MIT License.


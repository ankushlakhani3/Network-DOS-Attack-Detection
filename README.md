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

```bash
# 1. Clone POX
git clone https://github.com/noxrepo/pox.git
cd pox

# 2. Place controller module
# Copy your traffic_monitoring.py into the pox/ext directory
cp /path/to/traffic_monitoring.py ext/

# 3. Copy the Mininet topology script
# Save topology.py into your working directory (outside the pox/ tree)
cp /path/to/topology.py ~/mininet_topo/

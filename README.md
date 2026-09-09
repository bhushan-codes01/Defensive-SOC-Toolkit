# Defensive SOC Toolkit — Computer Networks Monitoring & Threat Detection System

A robust, local **Computer Networks (CN) Network Monitoring & Threat Detection System** aligned with the Mumbai University B.Tech CSE (IoT & Cybersecurity with Blockchain Technology) NEP 2020 curriculum.

---

## 🌟 Key Features

1. **SQLite Database Persistence (`soc_toolkit/db.py`)**: Zero-ORM lightweight persistence for alerts, decoded packets, incidents, and audit logs.
2. **Packet Analysis & PCAP Decoder (`soc_toolkit/packet_analyzer.py`)**: Live interface packet capture via Scapy and offline `.pcap` file parser decoding `Ethernet -> IP -> TCP/UDP/ICMP/ARP/DNS`.
3. **Modular Rule-Based Detection Engine (`soc_toolkit/detection/`)**:
   - **Port Scan Detection** (MITRE T1046)
   - **ARP Spoofing / Poisoning** (MITRE T1557.002)
   - **DNS Tunneling / High-Entropy Exfiltration** (MITRE T1071.004)
   - **SYN Flood Denial of Service** (MITRE T1498.001)
   - **Plaintext Auth Protocol Warning** (MITRE T1040)
4. **Network Topology Discovery & OS Fingerprinting (`soc_toolkit/topology.py`)**: Subnet ARP sweep, ICMP traceroute hop calculation, and TTL-based OS estimation.
5. **Tamper-Evident SHA-256 Audit Chain (`soc_toolkit/chain.py`)**: Cryptographic block hashing and Merkle root integrity verification.
6. **IoT Network Monitoring & Telemetry Simulator (`soc_toolkit/iot_monitor.py`, `simulator.py`)**: MQTT device telemetry monitor, whitelist validator, and hardware-free synthetic simulator.
7. **Incident Report PDF / Text Exporter (`soc_toolkit/pdf_export.py`)**: One-click download of official incident response reports for evaluation submissions.
8. **Containerization & Pytest Suite**: Complete Docker / Docker-Compose setup and 100% passing unit test suite.

---

## 🚀 Quickstart

### 1. Local Run
```powershell
python -m pip install -r requirements.txt
python app.py
```

Open dashboard in browser:
```text
http://127.0.0.1:8765
```

### 2. Run IoT Telemetry Simulator (Hardware-Free Demo)
In a secondary terminal window while `app.py` is running:
```powershell
python simulator.py
```

### 3. Run Automated Pytest Suite
```powershell
python -m pytest tests/
```

### 4. Docker Deployment
```powershell
docker-compose up --build
```

---

## 📁 Project Structure

```text
app.py                  # Main server launcher
simulator.py            # Hardware-free IoT telemetry simulator
Dockerfile              # Container build definition
docker-compose.yml      # Multi-container compose configuration
requirements.txt        # Python package dependencies
soc_toolkit/            # Core backend package
  ├── db.py             # SQLite persistence layer
  ├── packet_analyzer.py # Scapy packet decoder & PCAP parser
  ├── topology.py       # Topology discovery & OS fingerprinting
  ├── chain.py          # Cryptographic SHA-256 audit chain
  ├── iot_monitor.py    # MQTT IoT telemetry monitor
  ├── auth.py           # Session authentication handler
  ├── pdf_export.py     # Incident report exporter
  ├── server.py         # HTTP Server & REST API routes
  └── detection/        # Rule-based threat detection engine
      ├── base.py
      ├── port_scan.py
      ├── arp_spoof.py
      ├── dns_tunnel.py
      ├── syn_flood.py
      └── plaintext_auth.py
public/                 # Animated Cyber-Lab Frontend Dashboard
  ├── index.html
  ├── app.js
  └── style.css
docs/                   # CN Documentation & Viva Guide
  └── ARCHITECTURE.md
tests/                  # Automated pytest suite
```

---

## 🛡️ Safety & Lab Scope

This tool is designed strictly for educational network research, owned lab devices, private networks, and authorized academic evaluations. Public IP scanning is explicitly restricted.

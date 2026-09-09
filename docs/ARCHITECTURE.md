# Defensive SOC Toolkit — Computer Networks Architecture & Curriculum Alignment

This document outlines the system architecture, network layer mapping, Data Flow Diagrams (DFDs), and viva evaluation guide for the **Defensive SOC Toolkit — Network Monitoring & Threat Detection System** (aligned with Mumbai University B.Tech CSE NEP 2020 curriculum).

---

## 1. OSI & TCP/IP Model Mapping

| Layer No. | OSI Model Layer | Protocols Handled | Toolkit Module / Component | Functionality |
| :--- | :--- | :--- | :--- | :--- |
| **Layer 7** | Application | HTTP, HTTPS, DNS, MQTT, FTP, Telnet | `packet_analyzer.py`, `dns_tunnel.py`, `iot_monitor.py` | Entropy analysis, DNS tunneling detection, MQTT telemetry validation, Plaintext auth warnings |
| **Layer 4** | Transport | TCP, UDP | `packet_analyzer.py`, `syn_flood.py`, `port_scan.py` | TCP SYN/ACK handshake validation, Port fan-out scan detection, Bandwidth aggregation |
| **Layer 3** | Network | IP (v4/v6), ICMP | `topology.py`, `scanner.py` | Subnet sweeps, ICMP traceroute hop count, TTL-based OS estimation |
| **Layer 2** | Data Link | Ethernet, ARP | `packet_analyzer.py`, `arp_spoof.py` | MAC address tracking, ARP spoofing / poisoning anomaly detection |

---

## 2. Block Diagram

```text
  [ Network Traffic / PCAP File / IoT MQTT Sensors ]
                         │
                         ▼
        ┌──────────────────────────────────┐
        │     Scapy Packet Decoder         │
        └──────────────────────────────────┘
                         │
                         ▼
        ┌──────────────────────────────────┐
        │     Detection Engine Rules       │
        │  (PortScan, ARP, DNS, SYN, Auth) │
        └──────────────────────────────────┘
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
┌──────────────┐                 ┌─────────────────┐
│ SQLite DB    │                 │ SHA-256 Chain   │
│ Persistence  │                 │ Audit Verifier  │
└──────────────┘                 └─────────────────┘
        │                                 │
        └────────────────┬────────────────┘
                         ▼
        ┌──────────────────────────────────┐
        │   Web Dashboard & REST Server    │
        │     (http://127.0.0.1:8765)      │
        └──────────────────────────────────┘
```

---

## 3. Data Flow Diagram (DFD)

### DFD Level 0 (Context Diagram)
```text
  [ External Network / Sensors ] ───(Packets / Telemetry)───► [ 1.0 CN SOC System ] ───(Alerts & Reports)───► [ SOC Analyst / Evaluator ]
```

### DFD Level 1 (Process Decomposition)
1. **Process 1.0 Packet Ingestion**: Capture live interface packets or parse uploaded `.pcap` files.
2. **Process 2.0 Feature Aggregation**: Summarize protocols, top talkers, conversation pairs, and bandwidth.
3. **Process 3.0 Detection Engine Execution**: Run rule-based heuristic checks (Port Scan, ARP Spoofing, DNS Tunneling, SYN Flood, Plaintext Auth).
4. **Process 4.0 Audit Chain Append**: Hash generated alert payloads with SHA-256 and link to previous block hash.
5. **Process 5.0 Dashboard & PDF Rendering**: Present real-time alerts, topology graph, and PDF incident export to user.

---

## 4. Viva Evaluation Q&A Guide

### Q1: How does the system detect ARP Poisoning (Man-in-the-Middle)?
**Answer**: The ARP spoofing detection rule monitors mapping changes between IP addresses and MAC addresses. If an IP (e.g. default gateway `192.168.1.1`) is claimed by a new MAC address different from its established binding, or if gratuitous ARP replies are broadcast, the system flags a **CRITICAL** alert (MITRE T1557.002).

### Q2: How is DNS Tunneling identified using Shannon Entropy?
**Answer**: Malicious data exfiltration via DNS often encodes binary data into DNS subdomain names (e.g., `a1f9e2b8c4d3.exfil.domain.com`). The `dns_tunnel.py` module calculates the Shannon Entropy of query names:
$$\text{Entropy} = -\sum P(x) \log_2 P(x)$$
Standard domain names have entropy $< 3.5$, whereas encrypted/encoded exfiltration payloads exhibit entropy $> 4.2$, triggering a **HIGH** alert (MITRE T1071.004).

### Q3: How does the Tamper-Evident Audit Chain guarantee integrity?
**Answer**: Each alert block incorporates the SHA-256 hash of its payload and the hash of the preceding block ($H_{n} = \text{SHA256}(\text{Index} \parallel \text{Timestamp} \parallel H_{\text{payload}} \parallel H_{n-1})$). Any unauthorized modification to SQLite alert records alters $H_{\text{payload}}$, invalidating subsequent block hashes and allowing `/api/chain/verify` to pin-point the exact tampered block index.

### Q4: Why is TTL-based OS Fingerprinting considered an estimation?
**Answer**: Different operating systems set default IP Time-To-Live (TTL) values (Linux = 64, Windows = 128, Cisco Router = 255). As packets traverse intermediate routers, each hop decrements the TTL by 1. Therefore, initial TTL values provide an accurate heuristic estimate, though intermediate NAT/firewalls can alter TTL values.

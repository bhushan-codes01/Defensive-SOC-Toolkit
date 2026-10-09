# Defensive SOC Toolkit — Network Analyzer & Security Toolkit

A **local-first Security Operations Center (SOC) lab** for learning computer networks and threat detection. It captures or imports network traffic, runs explainable rule-based detections, keeps a tamper-evident audit trail, and presents everything in a single web dashboard.

Built for the **Mumbai University B.Tech CSE (IoT & Cybersecurity with Blockchain), NEP 2020** curriculum — but useful for anyone learning how packet analysis, detection engineering, and incident response fit together.

> No cloud account, no hardware, and no security background needed. Install Python, run one command, open the dashboard.

---

## What does this project actually do?

Think of it as a **mini SOC in a box**:

1. **Ingest traffic** — parse an uploaded `.pcap` / `.pcapng` file (or live-capture with Scapy where permitted).
2. **Understand it** — decode `Ethernet → IP → TCP/UDP/ICMP/ARP/DNS`, summarize protocols, top talkers, and conversations.
3. **Detect threats** — run 5 transparent rules mapped to MITRE ATT&CK (port scan, ARP spoofing, DNS tunneling, SYN flood, plaintext auth).
4. **Prove integrity** — hash every important event into a SHA-256 chain so tampering is detectable.
5. **Respond** — track incidents and export styled **PDF / TXT / web audit reports** for viva or lab submission.
6. **Monitor IoT** — accept MQTT-style telemetry, enforce a device whitelist, and flag rogue/overheating devices (with a hardware-free simulator).

Everything runs on **Python's standard-library HTTP server + SQLite + vanilla JS**. No Flask, no ORM, no build step.

---

## Live dashboard tour

Open `http://127.0.0.1:8765` after `python app.py`:

| Tab | What you see | Try this |
| --- | --- | --- |
| **Overview** | Packet count, alert count, chain integrity | Baseline health at a glance |
| **Packet Analyzer** | Upload `.pcap`, protocol breakdown, top talkers, packet table | Upload any Wireshark capture |
| **Detection Engine** | Alerts with severity, rule ID, MITRE technique | Click **Run Detection Rules Now** |
| **Topology & OS** | Discovered nodes, traceroute hops, TTL-based OS guess | Click **Run Traceroute (8.8.8.8)** |
| **Audit Chain** | SHA-256 block list + integrity check | Click **Verify Audit Chain Integrity** |
| **IoT Monitor** | Whitelist + live telemetry stream | Run `python simulator.py` in a 2nd terminal |
| **Network Scanner** | Port scan on a private target | Scan `192.168.1.1` (lab only) |
| **Vulnerabilities** | CVE/keyword lookup | Try `CVE-2023-38606` |
| **Log Analysis** | Paste logs, get pattern summary | Paste any syslog/auth lines |
| **Phishing Detector** | Score a message/URL | Paste a suspicious link |
| **Incident Response** | Incident list + one-click exports | Download **Incident PDF / Audit PDF / Web Audit** |

---

## Detection rules (explainable, no ML black box)

| Rule | MITRE | Heuristic in plain English |
| --- | --- | --- |
| Port scan | T1046 | One source touches many ports on one host in a short window |
| ARP spoofing | T1557.002 | Same IP suddenly claims a new MAC, or gratuitous ARP storm |
| DNS tunneling | T1071.004 | DNS query names with abnormally high Shannon entropy (> ~4.2) |
| SYN flood | T1498.001 | Flood of unanswered TCP SYNs toward one target |
| Plaintext auth | T1040 | FTP / Telnet / HTTP-basic login observed in clear text |

Each alert stores `rule_id`, `severity`, `src/dst IP`, and `mitre_technique` in SQLite and appends a hash to the audit chain.

---

## How it works (data flow)

```text
[ Live traffic / PCAP upload / IoT telemetry ]
                 |
                 v
   +--------------------------+
   | Scapy packet decoder     |
   +--------------------------+
                 |
                 v
   +--------------------------+
   | Detection engine (5 rules)|
   +--------------------------+
                 |
        +--------+--------+
        v                 v
 +-------------+   +----------------+
 | SQLite DB   |   | SHA-256 chain  |
 | alerts,     |   | hash-linked    |
 | packets,    |   | audit blocks   |
 | incidents   |   | + Merkle root  |
 +-------------+   +----------------+
        |                 |
        +--------+--------+
                 v
   +--------------------------+
   | Dashboard + REST API     |
   | :8765  +  PDF/TXT export |
   +--------------------------+
```

OSI mapping: L2 (Ethernet/ARP) → `arp_spoof.py`, L3 (IP/ICMP) → `topology.py` + `scanner.py`, L4 (TCP/UDP) → `syn_flood.py` + `port_scan.py`, L7 (DNS/HTTP/MQTT/FTP) → `dns_tunnel.py` + `plaintext_auth.py` + `iot_monitor.py`. See `docs/ARCHITECTURE.md` for diagrams and viva Q&A.

---

## Quickstart

### 1. Run the app

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:8765
```

The server binds to `0.0.0.0` by default (cloud-friendly). Override locally if needed:

```powershell
$env:HOST="127.0.0.1"; $env:PORT="8765"; python app.py
```

### 2. Feed it IoT data (hardware-free demo)

In a second terminal while `app.py` is running:

```powershell
python simulator.py
```

This sends 5 synthetic telemetry samples (including one rogue overheating device) to `/api/iot/telemetry`, which then appear under **IoT Monitor**.

### 3. Run the tests

```powershell
python -m pytest tests/ -v
```

Covers detection rules, SQLite persistence, and chain integrity (`test_detection.py`, `test_db.py`, `test_chain.py`).

### 4. Docker

```powershell
docker-compose up --build
```

App is available at `http://127.0.0.1:8765`. The image installs `libpcap-dev` + `tcpdump` so Scapy parsing works inside the container.

---

## REST API cheat sheet

**GET**

| Endpoint | Returns |
| --- | --- |
| `/` | Dashboard (`public/index.html`) |
| `/api/threats` | Curated threat feed |
| `/api/alerts?severity=HIGH` | Detection alerts (latest 50) |
| `/api/packets` | Protocol breakdown + top talkers |
| `/api/topology` | Discovered nodes / OS guesses |
| `/api/chain` | Full audit chain |
| `/api/chain/verify` | Integrity status + Merkle root |
| `/api/iot/telemetry` | Recent device telemetry |
| `/api/incidents` | Incident list |
| `/api/audit/report` | Consolidated audit JSON |
| `/api/incidents/export-pdf` | Styled incident PDF (use `?format=txt` for text) |
| `/api/audit/export-pdf` | Styled audit PDF |
| `/audit-report` | Printable web audit report (HTML) |

**POST** (JSON body)

| Endpoint | Purpose |
| --- | --- |
| `/api/pcap/upload` | Raw `.pcap` bytes → decoded summary |
| `/api/detection/run` | Run rules over `{packets: [...]}` |
| `/api/scan` | Private-target port scan |
| `/api/vulns` | CVE/keyword lookup |
| `/api/phishing` | Message/URL phishing check |
| `/api/logs` | Log pattern analysis |
| `/api/traceroute` | ICMP traceroute for `{target}` |
| `/api/iot/telemetry` | Ingest one telemetry sample |
| `/api/incidents` | Create incident `{title, severity, status, notes}` |
| `/api/auth/login` | Session login `{password}` |

All JSON errors return `{error: ...}` with HTTP 400/500 — the dashboard never crashes on bad input.

---

## Deploy it live (Render, free tier)

This repo is deployment-ready: `HOST`/`PORT` come from the environment and `render.yaml` targets the Dockerfile.

1. Push to GitHub (already configured as `origin`).
2. Go to **render.com → New → Web Service → Deploy from repo**.
3. Choose **Docker** runtime. Render reads `render.yaml` automatically (`PORT=10000`, `HOST=0.0.0.0`, health check `/api/threats`).
4. Open the issued `https://<your-app>.onrender.com` URL.

> Note: raw-socket capture, ARP sweeps, and traceroute are restricted in cloud sandboxes. PCAP upload, detection, IoT telemetry, chain verification, and PDF export all work normally online.

---

## Project structure

```text
app.py                  # Launcher -> soc_toolkit.server:run_server
simulator.py            # Synthetic IoT telemetry sender (no hardware needed)
Dockerfile              # python:3.11-slim + libpcap + tcpdump, exposes 8765
docker-compose.yml      # Local container run (mounts repo, sets PORT)
render.yaml             # One-click Render deploy (Docker, health check)
requirements.txt        # scapy, paho-mqtt, reportlab, pytest
soc_toolkit/
  server.py             # ThreadingHTTPServer routes + static file serving
  config.py             # HOST/PORT env handling, paths, port labels
  db.py                 # SQLite: alerts, packets, incidents, audit log
  packet_analyzer.py    # Scapy decoder + PCAP parser + aggregation
  detection/            # port_scan, arp_spoof, dns_tunnel, syn_flood, plaintext_auth + engine
  topology.py           # ARP sweep, traceroute, TTL OS fingerprint
  chain.py              # SHA-256 hash chain + Merkle verification
  iot_monitor.py        # Telemetry ingest, whitelist, anomaly flags
  scanner.py            # Private-range port scanner
  threat_intel.py       # Threat feed provider
  vulnerabilities.py    # CVE lookup
  log_analysis.py       # Log pattern summarizer
  phishing.py           # Heuristic phishing scorer
  pdf_export.py         # ReportLab incident/audit PDFs + text fallback
  auth.py               # Session login handler
public/                 # Dashboard: index.html, app.js, style.css
docs/ARCHITECTURE.md    # OSI mapping, DFDs, viva Q&A
tests/                  # pytest: detection, db, chain
```

---

## Tech choices (why so simple?)

- **Stdlib HTTP server** instead of Flask/FastAPI: zero framework to learn, easy to read in a viva, no hidden magic.
- **SQLite + raw SQL** instead of an ORM: the schema is visible in `db.py` and the `.db` file stays git-ignored.
- **Rule-based detection** instead of ML: every alert is explainable and maps to a MITRE technique.
- **Hash chain** instead of a blockchain node: demonstrates tamper-evidence without mining or peers.

---

## Safety & lab scope

Strictly for **education on owned devices, private networks, and authorized evaluations**. Do not scan public IPs or networks you don't own. Cloud deployments intentionally run with reduced raw-socket privileges.

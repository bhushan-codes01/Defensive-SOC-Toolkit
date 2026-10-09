<div align="center">

# 🛡️ Defensive SOC Toolkit

**Network Analyzer & Security Toolkit — packet analysis, detection, audit chain, and IoT monitoring in one local dashboard.**

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-scapy_mqtt_reportlabpytest-brightgreen)
![Runs](https://img.shields.io/badge/runs-local_docker_render-informational)
![Purpose](https://img.shields.io/badge/purpose-defensive%20only-blue)

</div>

---

## 📖 Overview

Defensive SOC Toolkit is a **local-first mini SOC lab** for learning computer networks and threat detection. It decodes traffic, runs explainable rule-based detections mapped to MITRE ATT&CK, keeps a tamper-evident SHA-256 audit trail, monitors IoT telemetry, and exports styled incident reports.

It is built for **students, learners, and home-lab users** — aligned with the **Mumbai University B.Tech CSE (IoT & Cybersecurity with Blockchain), NEP 2020** curriculum — who want to see how packet analysis, detection engineering, and incident response fit together.

<!-- Add a screenshot after you take one: -->
<!-- ![Dashboard screenshot](docs/screenshot.png) -->

## ✨ Features

| Tool | What it does |
|---|---|
| 🔎 **Network Scanner** | TCP port checks on private/local hosts you own, with service labels and low/medium/high risk ratings |
| 🐞 **Vulnerability Checker** | Searches the NVD CVE API by product, vendor, keyword, or CVE ID, shows CVSS scores, and flags CISA KEV entries |
| 📜 **Log Analysis** | Detects failed logins, privilege use, encoded PowerShell, lateral-movement tools, suspicious file types, and scan activity in pasted logs |
| 🎣 **Phishing Detector** | Applies URL and message heuristics and checks links against URLhaus |
| 🌐 **Threat Intelligence** | Shows live CISA KEV entries, CISA advisories, and recent malicious URLs |
| 🚨 **Incident Response** | Step-by-step triage checklist, incident tracking, and one-click **PDF / TXT / web audit** exports |
| 📦 **Packet Analyzer** | Scapy decoder (`Ethernet → IP → TCP/UDP/ICMP/ARP/DNS`) + offline `.pcap/.pcapng` upload, protocol breakdown, top talkers |
| 🧠 **Detection Engine** | 5 transparent rules: port scan (T1046), ARP spoofing (T1557.002), DNS tunneling (T1071.004), SYN flood (T1498.001), plaintext auth (T1040) |
| 🗺️ **Topology & OS Fingerprinting** | Subnet ARP sweep, ICMP traceroute hops, TTL-based OS estimation |
| 🔗 **Audit Chain** | SHA-256 hash-linked blocks + Merkle-root verification (`/api/chain/verify`) |
| 📡 **IoT Monitor** | MQTT-style telemetry ingest, device whitelist, rogue/thermal anomaly flags — plus a hardware-free `simulator.py` |

## 🚀 Quick Start

**Requirements:** Python 3.11+.

```bash
git clone https://github.com/bhushan-codes01/Network-Analyzer-and-Security-Toolkit.git
cd Network-Analyzer-and-Security-Toolkit
python -m pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:8765** in your browser.

To use a different host/port, set env vars:

```bash
# Linux / macOS
PORT=9000 HOST=127.0.0.1 python app.py

# Windows PowerShell
$env:PORT=9000; $env:HOST="127.0.0.1"; python app.py
```

> Default bind is `0.0.0.0:$PORT` (cloud-friendly; Render/Railway need this). `PORT` defaults to `8765` locally, `10000` on Render via `render.yaml`.

### Feed it IoT data (hardware-free demo)

In a second terminal while `app.py` is running:

```bash
python simulator.py
```

Sends synthetic telemetry (including one rogue overheating device) to `/api/iot/telemetry`. Watch it appear under the **IoT Monitor** tab.

### Run the tests

```bash
python -m pytest tests/ -v
```

Covers detection rules, SQLite persistence, and chain integrity.

### Docker

```bash
docker-compose up --build
```

App lands on `http://127.0.0.1:8765`. The image installs `libpcap-dev` + `tcpdump` so Scapy parsing works in-container.

## 🧪 Try It Out

**Log Analysis:** paste this into the Logs tab:

```text
Oct 09 10:01:12 server sshd[1021]: Failed password for invalid user admin from 203.0.113.7 port 52211 ssh2
Oct 09 10:01:15 server sshd[1021]: Failed password for root from 203.0.113.7 port 52213 ssh2
Oct 09 10:03:40 host powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
Oct 09 10:05:02 host psexec \\10.0.0.12 -u admin cmd.exe
```

**Vulnerability Checker:** search for `CVE-2023-38606` or a product such as `openssl`.

**Network Scanner:** scan `127.0.0.1` or your own LAN host, for example `192.168.1.1`.

**Packet Analyzer:** upload any Wireshark `.pcap`, then click **Run Detection Rules Now** in the Detection tab.

## 📡 Live Data Sources

| Source | Used for |
|---|---|
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited-in-the-wild context for CVEs and the threat dashboard |
| [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | Latest advisory feed (RSS) |
| [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVE search and CVSS scoring |
| [abuse.ch URLhaus](https://urlhaus.abuse.ch/) | Recent malicious URLs and URL lookups |

> If your network blocks a feed or a provider limits requests, the app keeps running and shows the sections that are available.

## 🧱 Architecture

```text
Browser (public/)
   │  fetch /api/*  +  PCAP upload
   ▼
soc_toolkit/server.py ──► scanner · vulns · threat_intel · phishing · logs
                           packet_analyzer · detection/ · topology
                           chain · iot_monitor · db · pdf_export
   │
   ▼
SQLite (alerts/packets/incidents) + SHA-256 chain + public defensive feeds
```

| API route | Method | Purpose |
|---|---|---|
| `/api/scan` | POST | Port scan of authorized private targets |
| `/api/vulns` | POST | CVE lookup |
| `/api/phishing` | POST | URL and message analysis |
| `/api/logs` | POST | Log pattern detection |
| `/api/threats` | GET | Live threat-intel feeds |
| `/api/packets` | GET | Protocol breakdown + top talkers |
| `/api/pcap/upload` | POST | Raw `.pcap` bytes → decoded summary |
| `/api/detection/run` | POST | Run detection rules |
| `/api/topology` | GET | Discovered nodes / OS guesses |
| `/api/traceroute` | POST | ICMP traceroute |
| `/api/chain` · `/api/chain/verify` | GET | Audit chain + integrity check |
| `/api/iot/telemetry` | GET/POST | Telemetry stream / ingest |
| `/api/incidents` | GET/POST | Incident list / create |
| `/api/incidents/export-pdf` | GET | Incident PDF (`?format=txt` for text) |
| `/api/audit/export-pdf` · `/audit-report` | GET | Audit PDF / printable web report |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for OSI mapping, DFDs, and viva Q&A.

## 📁 Project Structure

```text
Network-Analyzer-and-Security-Toolkit/
├── app.py                  # Server entry point -> soc_toolkit.server:run_server
├── simulator.py            # Synthetic IoT telemetry sender (no hardware needed)
├── Dockerfile              # python:3.11-slim + libpcap + tcpdump, exposes 8765
├── docker-compose.yml      # Local container run
├── render.yaml             # One-click Render deploy (Docker, health check)
├── requirements.txt        # scapy, paho-mqtt, reportlab, pytest
├── soc_toolkit/
│   ├── server.py           # ThreadingHTTPServer + API routes + static files
│   ├── config.py           # HOST/PORT env handling, paths, port labels
│   ├── db.py               # SQLite: alerts, packets, incidents, audit log
│   ├── packet_analyzer.py  # Scapy decoder + PCAP parser + aggregation
│   ├── detection/          # port_scan, arp_spoof, dns_tunnel, syn_flood, plaintext_auth + engine
│   ├── topology.py         # ARP sweep, traceroute, TTL OS fingerprint
│   ├── chain.py            # SHA-256 hash chain + Merkle verification
│   ├── iot_monitor.py      # Telemetry ingest, whitelist, anomaly flags
│   ├── scanner.py          # Authorized network port scanning
│   ├── vulnerabilities.py  # NVD + CISA KEV lookups
│   ├── threat_intel.py     # CISA and URLhaus feeds
│   ├── phishing.py         # URL/message heuristics + URLhaus
│   ├── log_analysis.py     # Pattern-based log triage
│   ├── pdf_export.py       # ReportLab incident/audit PDFs + text fallback
│   ├── auth.py             # Session login handler
│   └── http_client.py      # Cached HTTP helper
├── public/                 # Dashboard (index.html, app.js, style.css)
├── docs/ARCHITECTURE.md    # Architecture notes + viva guide
└── tests/                  # pytest: detection, db, chain
```

## ☁️ Deploy it live (Render, free tier)

1. Push to GitHub.
2. Go to **render.com → New → Web Service → Deploy from repo**.
3. Choose **Docker** runtime (reads `render.yaml`: `HOST=0.0.0.0`, `PORT=10000`, health check `/api/threats`).
4. Open the issued `https://<your-app>.onrender.com` URL.

> Raw-socket capture, ARP sweeps, and traceroute are restricted in cloud sandboxes. PCAP upload, detection, IoT telemetry, chain verification, and PDF export work normally online.

## 🔒 Safety & Responsible Use

This project is **for defense, learning, and authorized testing only**.

- The scanner **rejects public IP ranges** and only accepts private, loopback, and link-local targets.
- Scans are capped at **64 hosts** and **30 ports** per request.
- Only scan systems you own or have **written permission** to test.
- The phishing checker sends URLs you analyze to abuse.ch (URLhaus). Don't paste sensitive links.

The authors are not responsible for misuse.

## ⚠️ Limitations

- Detection is **rule-based** (heuristics + Shannon entropy). It is a learning tool, not a replacement for a SIEM, EDR, or professional scanner.
- Live capture / ARP sweep / traceroute need raw-socket privileges — limited on Windows without Npcap and in cloud sandboxes. **PCAP upload always works.**
- Public APIs may rate-limit or require keys, so some feeds can be empty.

## 🗺️ Roadmap

- [x] Unit tests (`tests/`: detection, db, chain)
- [x] MITRE ATT&CK mapping for detections
- [x] Export reports (PDF / TXT / web audit)
- [ ] Threshold-based detections (e.g. brute force per IP over time)
- [ ] MITRE mapping for log findings
- [ ] Optional AI-assisted triage summaries

## 🤝 Contributing

Issues and pull requests are welcome. For larger changes, please open an issue first to discuss what you'd like to change.

## 📄 License

No license has been added yet. Add a `LICENSE` file (for example MIT) to let others use and contribute to the project.

---

<div align="center">
Built by <a href="https://github.com/bhushan-codes01">@bhushan-codes01</a> · If this helped you, consider giving it a ⭐
</div>

# Defensive SOC Toolkit

A working cybersecurity research model that combines six defensive capabilities in one local dashboard with an animated cyber-lab UI.

- Network scanner for private/local systems you own or are authorized to test.
- Vulnerability checker using the NVD CVE API and CISA Known Exploited Vulnerabilities context.
- Log analysis for common suspicious patterns.
- Phishing detector with message heuristics and URLhaus lookup.
- Threat intelligence dashboard using public CISA and abuse.ch feeds.
- Incident response checklist for triage and recovery steps.

## Run

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:8765
```

## Live Data Sources

The model is designed to use real public defensive data:

- CISA Known Exploited Vulnerabilities catalog
- CISA cybersecurity advisories RSS feed
- NVD CVE 2.0 API
- abuse.ch URLhaus recent malicious URL feed and URL lookup API

If your network blocks one of these feeds, the app keeps running and shows the parts that are available.

## Project Structure

```text
app.py                  local server entry point
soc_toolkit/            backend modules
public/                 animated web dashboard
docs/ARCHITECTURE.md    architecture notes
requirements.txt        dependency note
```

## Safety Scope

Use this only for owned devices, private networks, lab systems, or environments where you have written permission. The scanner rejects public IP ranges and limits host and port counts.

# Architecture

The toolkit is intentionally small and dependency-light so students can read every layer.

## Runtime Flow

```text
Browser UI
  |
  | fetch /api/*
  v
soc_toolkit.server
  |
  | routes requests
  v
Feature modules
  |-- scanner.py
  |-- vulnerabilities.py
  |-- threat_intel.py
  |-- phishing.py
  |-- log_analysis.py
  |
  v
Public defensive data sources or local analysis
```

## Modules

- `app.py` starts the local server.
- `soc_toolkit/server.py` exposes API routes and serves the UI.
- `soc_toolkit/scanner.py` performs authorized private/local network port checks.
- `soc_toolkit/vulnerabilities.py` searches NVD and annotates known exploited CVEs when CISA data is available.
- `soc_toolkit/threat_intel.py` loads public CISA and URLhaus feeds.
- `soc_toolkit/phishing.py` checks URL and message phishing indicators.
- `soc_toolkit/log_analysis.py` detects suspicious patterns in pasted logs.
- `public/` contains the animated dashboard UI.

## Safety Choices

- Network scanning is limited to private, loopback, and link-local targets.
- Scans are capped to 64 hosts and 30 ports per request.
- Public feed failures do not break the app; unavailable feeds return empty dashboard sections.

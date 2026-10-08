from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, parse_qs
import json
import mimetypes
import os
import time

from .config import DEFAULT_PORT, HOST, PUBLIC_DIR
from .db import init_db, get_alerts, get_incidents, insert_incident, get_packets_summary
from .log_analysis import analyze_logs
from .phishing import phishing_check
from .scanner import scan_network
from .threat_intel import threat_feed
from .vulnerabilities import vulnerability_lookup
from .packet_analyzer import aggregate_packet_data, analyze_pcap_bytes
from .detection import run_detection
from .topology import discover_topology, run_traceroute
from .chain import audit_chain
from .iot_monitor import get_recent_telemetry, process_telemetry_payload
from .auth import authenticate_user, validate_session
from .pdf_export import (
    generate_incident_report_text,
    generate_incident_report_pdf_bytes,
    generate_audit_report_pdf_bytes,
    collect_report_data,
)

def json_response(handler, payload, status=200):
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

def read_raw_body(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    return handler.rfile.read(length) if length else b""

def read_json(handler):
    raw = read_raw_body(handler).decode("utf-8", errors="ignore")
    return json.loads(raw or "{}")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        if path == "/":
            return self._serve_file("index.html")

        # API Routes
        if path == "/api/threats":
            return self._safe_json(lambda: threat_feed())
        if path == "/api/alerts":
            severity = query.get("severity", [None])[0]
            return self._safe_json(lambda: get_alerts(limit=50, severity=severity))
        if path == "/api/packets":
            return self._safe_json(lambda: aggregate_packet_data())
        if path == "/api/topology":
            return self._safe_json(lambda: discover_topology())
        if path == "/api/chain":
            return self._safe_json(lambda: audit_chain.get_chain())
        if path == "/api/chain/verify":
            return self._safe_json(lambda: audit_chain.verify_integrity())
        if path == "/api/iot/telemetry":
            return self._safe_json(lambda: get_recent_telemetry())
        if path == "/api/incidents":
            return self._safe_json(lambda: get_incidents())
        if path == "/api/audit/report":
            return self._safe_json(lambda: collect_report_data())
        if path == "/api/incidents/export-txt":
            report_text = generate_incident_report_text()
            body = report_text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="Incident_Report.txt"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/incidents/export-pdf":
            fmt = query.get("format", ["pdf"])[0].lower()
            if fmt == "txt":
                report_text = generate_incident_report_text()
                body = report_text.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="Incident_Report.txt"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            try:
                pdf_bytes = generate_incident_report_pdf_bytes()
                try:
                    audit_chain.add_block({"event": "INCIDENT_PDF_EXPORT", "bytes": len(pdf_bytes)})
                except Exception:
                    pass
            except Exception as exc:
                return json_response(self, {"error": f"PDF generation failed: {exc}"}, 500)
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", 'attachment; filename="SOC_Incident_Report.pdf"')
            self.send_header("Content-Length", str(len(pdf_bytes)))
            self.end_headers()
            self.wfile.write(pdf_bytes)
            return
        if path == "/api/audit/export-pdf":
            try:
                pdf_bytes = generate_audit_report_pdf_bytes()
                try:
                    audit_chain.add_block({"event": "AUDIT_PDF_EXPORT", "bytes": len(pdf_bytes)})
                except Exception:
                    pass
            except Exception as exc:
                return json_response(self, {"error": f"PDF generation failed: {exc}"}, 500)
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", 'attachment; filename="SOC_Audit_Report.pdf"')
            self.send_header("Content-Length", str(len(pdf_bytes)))
            self.end_headers()
            self.wfile.write(pdf_bytes)
            return
        if path == "/audit-report":
            return self._serve_audit_html()

        return self._serve_file(path.lstrip("/"))

    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/api/pcap/upload":
            raw_data = read_raw_body(self)
            return self._safe_json(lambda: analyze_pcap_bytes(raw_data))

        post_routes = {
            "/api/scan": lambda p: scan_network(p),
            "/api/vulns": lambda p: vulnerability_lookup(p),
            "/api/phishing": lambda p: phishing_check(p),
            "/api/logs": lambda p: analyze_logs(p),
            "/api/detection/run": lambda p: run_detection(p.get("packets", get_packets_summary())),
            "/api/traceroute": lambda p: run_traceroute(p.get("target", "8.8.8.8")),
            "/api/iot/telemetry": lambda p: process_telemetry_payload(p.get("device_id", "UNKNOWN"), p),
            "/api/incidents": lambda p: {"incident_id": insert_incident(p.get("title", "New Incident"), p.get("severity", "MEDIUM"), p.get("status", "OPEN"), p.get("notes", ""))},
            "/api/auth/login": lambda p: {"token": authenticate_user(p.get("password", ""))}
        }

        if path not in post_routes:
            return json_response(self, {"error": "Not found"}, 404)

        payload = read_json(self)
        return self._safe_json(lambda: post_routes[path](payload))

    def _safe_json(self, fn):
        try:
            json_response(self, fn())
        except (ValueError, HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            json_response(self, {"error": str(exc)}, 400)
        except Exception as exc:
            json_response(self, {"error": f"Unexpected error: {exc}"}, 500)

    def _serve_file(self, name):
        path = (PUBLIC_DIR / name).resolve()
        public_root = PUBLIC_DIR.resolve()
        if not str(path).startswith(str(public_root)) or not path.exists():
            return json_response(self, {"error": "Not found"}, 404)

        body = path.read_bytes()
        ext = path.suffix.lower()
        mapping = {
            ".html": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
            ".svg": "image/svg+xml",
            ".json": "application/json",
        }
        mime = mapping.get(ext, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_audit_html(self):
        import html as _html
        try:
            data = collect_report_data()
        except Exception as exc:
            return json_response(self, {"error": f"Audit report failed: {exc}"}, 500)
        v = data.get("verification", {})
        totals = data.get("totals", {})
        status = v.get("status", "UNKNOWN")
        status_color = "#2E7D32" if v.get("is_valid") else "#C62828"

        def esc(x):
            return _html.escape(str(x if x is not None else ""))

        inc_rows = "".join(
            f"<tr><td>#{esc(i.get('id'))}</td><td>{esc(i.get('title'))}</td>"
            f"<td><span class='badge {esc(str(i.get('severity','')).lower())}'>{esc(i.get('severity'))}</span></td>"
            f"<td>{esc(i.get('status'))}</td><td>{esc(i.get('assigned_to',''))}</td></tr>"
            for i in data.get("incidents", [])
        ) or "<tr><td colspan='5'>No incidents recorded.</td></tr>"

        alert_rows = "".join(
            f"<tr><td><span class='badge {esc(str(a.get('severity','')).lower())}'>{esc(a.get('severity'))}</span></td>"
            f"<td>{esc(a.get('title'))}</td><td><code>{esc(a.get('rule_id'))}</code></td>"
            f"<td><code>{esc(a.get('mitre_technique'))}</code></td>"
            f"<td>{esc(a.get('src_ip'))} → {esc(a.get('dst_ip'))}</td></tr>"
            for a in data.get("alerts", [])[:30]
        ) or "<tr><td colspan='5'>No alerts.</td></tr>"

        pkt = data.get("packet_stats", {})
        chain_rows = "".join(
            f"<tr><td>#{esc(b.get('block_index'))}</td>"
            f"<td><code>{esc(str(b.get('block_hash',''))[:24])}…</code></td>"
            f"<td><code>{esc(str(b.get('prev_hash',''))[:24])}…</code></td>"
            f"<td><code>{esc(str(b.get('payload_json',''))[:80])}</code></td></tr>"
            for b in data.get("chain", [])[-25:]
        )

        tel_rows = "".join(
            f"<tr><td>{esc(t.get('device_id'))}</td><td>{esc(t.get('temperature'))} °C</td>"
            f"<td>{esc(t.get('humidity'))} %</td><td>{esc(t.get('status'))}</td></tr>"
            for t in data.get("telemetry", [])[-15:]
        ) or "<tr><td colspan='4'>No telemetry. Run python simulator.py</td></tr>"

        nodes = data.get("topology", {}).get("nodes", [])
        topo_rows = "".join(
            f"<tr><td>{esc(n.get('label'))}</td><td>{esc(n.get('ip'))}</td><td>{esc(n.get('os'))}</td></tr>"
            for n in nodes
        )

        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC Audit Report — {esc(data.get('generated_at'))}</title>
<style>
body{{font-family:Inter,system-ui,Arial,sans-serif;background:#06090f;color:#e8eef5;margin:0;padding:32px}}
.wrap{{max-width:1100px;margin:0 auto}}
.hdr{{background:linear-gradient(135deg,#0b1c2c,#123);border:1px solid #00e5ff33;border-radius:14px;padding:28px;margin-bottom:20px}}
.hdr h1{{margin:4px 0 6px}} .muted{{color:#8ca0ba}} .kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:16px 0}}
.kpi{{background:#0f1520;border:1px solid #1e2d42;border-radius:10px;padding:14px;text-align:center}} .kpi b{{font-size:26px;display:block}}
.card{{background:#0d1420;border:1px solid #1e2d42;border-radius:12px;padding:20px;margin:16px 0}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th{{text-align:left;color:#8ca0ba;padding:8px;border-bottom:1px solid #233}}
td{{padding:8px;border-bottom:1px solid #16202e}} code{{background:#111a28;padding:2px 6px;border-radius:4px;font-size:12px}}
.badge{{padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;background:#334155;color:#fff}}
.badge.critical{{background:#c62828}} .badge.high{{background:#ef6c00}} .badge.medium{{background:#8d6e00}} .badge.low{{background:#2e7d32}}
.btns{{display:flex;gap:10px;margin:14px 0;flex-wrap:wrap}} a.btn{{text-decoration:none;padding:10px 16px;border-radius:8px;font-weight:700}}
.btn.p{{background:#00e676;color:#000}} .btn.s{{background:#10202f;color:#9fd;border:1px solid #234}}
@media print{{body{{background:#fff;color:#111;padding:0}} .hdr,.card,.kpi{{border:1px solid #ccc;background:#fff}} .btns{{display:none}}}}
</style></head><body><div class="wrap">
<div class="hdr"><div class="muted">DEFENSIVE SOC TOOLKIT • CONFIDENTIAL</div>
<h1>Web Audit Report — {esc(data.get('generated_at'))}</h1>
<div class="muted">{esc(data.get('scope'))} • {esc(data.get('curriculum'))}</div>
<div style="margin-top:10px;font-weight:800;color:{status_color}">● {esc(status)} — {esc(v.get('total_blocks'))} blocks — Merkle <code>{esc(v.get('merkle_root',''))}</code></div>
<div class="btns"><a class="btn p" href="/api/incidents/export-pdf">Download Incident PDF</a>
<a class="btn p" href="/api/audit/export-pdf">Download Audit PDF</a>
<a class="btn s" href="/api/audit/report" target="_blank">Open JSON</a>
<a class="btn s" href="#" onclick="window.print();return false">Print</a></div></div>
<div class="kpis">
<div class="kpi"><b>{totals.get('incidents',0)}</b>Incidents</div>
<div class="kpi"><b>{totals.get('alerts',0)}</b>Alerts</div>
<div class="kpi"><b>{totals.get('packets',0)}</b>Packets</div>
<div class="kpi"><b>{totals.get('chain_blocks',0)}</b>Chain blocks</div>
<div class="kpi"><b>{totals.get('telemetry',0)}</b>Telemetry</div></div>
<div class="card"><h2>1 — Incidents</h2><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Assignee</th></tr>{inc_rows}</table></div>
<div class="card"><h2>2 — Detection Alerts (MITRE)</h2><table><tr><th>Sev</th><th>Title</th><th>Rule</th><th>MITRE</th><th>Flow</th></tr>{alert_rows}</table></div>
<div class="card"><h2>3 — Packets</h2><p>Total <b>{esc(pkt.get('total_packets',0))}</b> packets / <b>{esc(pkt.get('total_bytes',0))}</b> bytes • Breakdown <code>{esc(pkt.get('protocol_breakdown',{}))}</code></p></div>
<div class="card"><h2>4 — Topology</h2><table><tr><th>Device</th><th>IP</th><th>OS</th></tr>{topo_rows}</table></div>
<div class="card"><h2>5 — IoT Telemetry</h2><table><tr><th>Device</th><th>Temp</th><th>Hum</th><th>Status</th></tr>{tel_rows}</table></div>
<div class="card"><h2>6 — Audit Chain (SHA-256)</h2><table><tr><th>Idx</th><th>Block hash</th><th>Prev hash</th><th>Payload</th></tr>{chain_rows}</table></div>
<p class="muted">End of report — generated locally. Lab scope: owned devices / private networks only.</p>
</div></body></html>"""
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run_server(host=HOST, port=None):
    init_db()
    selected_port = int(port or os.environ.get("PORT", DEFAULT_PORT))
    server = ThreadingHTTPServer((host, selected_port), Handler)
    print(f"Defensive SOC Toolkit running at http://{host}:{selected_port}")
    server.serve_forever()

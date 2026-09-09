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
from .pdf_export import generate_incident_report_text

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
        if path == "/api/incidents/export-pdf":
            report_text = generate_incident_report_text()
            body = report_text.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="Incident_Report.txt"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

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

def run_server(host=HOST, port=None):
    init_db()
    selected_port = int(port or os.environ.get("PORT", DEFAULT_PORT))
    server = ThreadingHTTPServer((host, selected_port), Handler)
    print(f"Defensive SOC Toolkit running at http://{host}:{selected_port}")
    server.serve_forever()

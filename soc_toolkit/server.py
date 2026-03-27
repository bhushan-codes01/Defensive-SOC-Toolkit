from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
import json
import mimetypes
import os

from .config import DEFAULT_PORT, HOST, PUBLIC_DIR
from .log_analysis import analyze_logs
from .phishing import phishing_check
from .scanner import scan_network
from .threat_intel import threat_feed
from .vulnerabilities import vulnerability_lookup


def json_response(handler, payload, status=200):
    body = json.dumps(payload, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length).decode("utf-8") if length else "{}"
    return json.loads(raw or "{}")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self._serve_file("index.html")
        if path == "/api/threats":
            return self._safe_json(lambda: threat_feed())
        return self._serve_file(path.lstrip("/"))

    def do_POST(self):
        routes = {
            "/api/scan": scan_network,
            "/api/vulns": vulnerability_lookup,
            "/api/phishing": phishing_check,
            "/api/logs": analyze_logs,
        }
        path = urlparse(self.path).path
        if path not in routes:
            return json_response(self, {"error": "Not found"}, 404)
        payload = read_json(self)
        return self._safe_json(lambda: routes[path](payload))

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
    selected_port = int(port or os.environ.get("PORT", DEFAULT_PORT))
    server = ThreadingHTTPServer((host, selected_port), Handler)
    print(f"Defensive SOC Toolkit running at http://{host}:{selected_port}")
    server.serve_forever()

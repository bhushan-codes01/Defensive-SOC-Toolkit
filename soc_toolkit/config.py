from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PUBLIC_DIR = ROOT / "public"

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
USER_AGENT = "Mozilla/5.0 StudentDefensiveSOC/1.0"
CACHE_TTL_SECONDS = 900

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 3389, 5900, 8080, 8443]
PORT_LABELS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

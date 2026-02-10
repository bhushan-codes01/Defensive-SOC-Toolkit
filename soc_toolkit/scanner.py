import concurrent.futures
import ipaddress
import socket
import time

from .config import COMMON_PORTS, PORT_LABELS


def _allowed_ip(ip):
    parsed = ipaddress.ip_address(ip)
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def _expand_targets(target):
    target = (target or "127.0.0.1").strip()
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        if not (network.is_private or network.is_loopback or network.is_link_local):
            raise ValueError("Only private, loopback, and link-local ranges are allowed.")
        return [str(host) for host in list(network.hosts())[:64]]

    ip = ipaddress.ip_address(socket.gethostbyname(target))
    if not _allowed_ip(ip):
        raise ValueError("Only private, loopback, and link-local targets are allowed.")
    return [str(ip)]


def _port_risk(port):
    if port in [23, 445, 3389, 5900]:
        return "high"
    if port in [21, 25, 139, 389, 8080, 8443]:
        return "medium"
    return "low"


def _scan_port(host, port, timeout):
    started = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
    if result != 0:
        return None
    return {
        "port": port,
        "service": PORT_LABELS.get(port, "unknown"),
        "latencyMs": round((time.time() - started) * 1000),
        "risk": _port_risk(port),
    }


def scan_network(payload):
    hosts = _expand_targets(payload.get("target"))
    ports = payload.get("ports") or COMMON_PORTS
    ports = [int(port) for port in ports[:30] if 1 <= int(port) <= 65535]
    timeout = min(max(float(payload.get("timeout", 0.45)), 0.1), 1.5)
    results = {host: [] for host in hosts}

    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as pool:
        futures = {pool.submit(_scan_port, host, port, timeout): host for host in hosts for port in ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                item = future.result()
                if item:
                    results[futures[future]].append(item)
            except OSError:
                pass

    devices = [
        {"host": host, "openPorts": sorted(open_ports, key=lambda port: port["port"])}
        for host, open_ports in results.items()
        if open_ports
    ]
    return {"targetCount": len(hosts), "scannedPorts": ports, "devices": devices}

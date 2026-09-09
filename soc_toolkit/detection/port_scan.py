from collections import defaultdict
from typing import List, Dict, Any
from .base import BaseDetectionRule

class PortScanDetectionRule(BaseDetectionRule):
    rule_id = "PORT_SCAN"
    title = "Network Port Scan Detected"
    severity = "HIGH"
    mitre_technique = "T1046"

    def __init__(self, port_threshold: int = 15):
        self.port_threshold = port_threshold

    def analyze(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        # Group unique ports hit per (src_ip, dst_ip)
        scans = defaultdict(set)
        
        for p in packets:
            src = p.get("src_ip")
            dst = p.get("dst_ip")
            dst_port = p.get("dst_port")
            if src and dst and dst_port:
                scans[(src, dst)].add(dst_port)
        
        for (src, dst), ports in scans.items():
            if len(ports) >= self.port_threshold:
                port_sample = sorted(list(ports))[:10]
                alerts.append({
                    "rule_id": self.rule_id,
                    "title": self.title,
                    "severity": self.severity,
                    "description": f"Source IP {src} probed {len(ports)} unique destination ports on target {dst}.",
                    "evidence": f"Unique ports target count: {len(ports)}. Port sample: {port_sample}...",
                    "mitre_technique": self.mitre_technique,
                    "src_ip": src,
                    "dst_ip": dst
                })
        return alerts

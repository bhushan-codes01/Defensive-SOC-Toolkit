from collections import defaultdict
from typing import List, Dict, Any
from .base import BaseDetectionRule

class SYNFloodDetectionRule(BaseDetectionRule):
    rule_id = "SYN_FLOOD"
    title = "SYN Flood Denial of Service (DoS)"
    severity = "HIGH"
    mitre_technique = "T1498.001"

    def __init__(self, threshold: int = 20):
        self.threshold = threshold

    def analyze(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        syn_counts = defaultdict(int)

        for p in packets:
            if p.get("protocol") in ["TCP", "HTTP", "HTTPS"]:
                info = p.get("info", "")
                if "[S]" in info or "SYN" in info:
                    src = p.get("src_ip")
                    dst = p.get("dst_ip")
                    if src and dst:
                        syn_counts[(src, dst)] += 1

        for (src, dst), count in syn_counts.items():
            if count >= self.threshold:
                alerts.append({
                    "rule_id": self.rule_id,
                    "title": self.title,
                    "severity": self.severity,
                    "description": f"Target {dst} received {count} incomplete TCP SYN handshake requests from {src}.",
                    "evidence": f"SYN packet count: {count} without corresponding ACK completion.",
                    "mitre_technique": self.mitre_technique,
                    "src_ip": src,
                    "dst_ip": dst
                })
        return alerts

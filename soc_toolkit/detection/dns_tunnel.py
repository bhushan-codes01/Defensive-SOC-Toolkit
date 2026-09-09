import math
from typing import List, Dict, Any
from .base import BaseDetectionRule

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        p_x = float(data.count(char)) / length
        entropy -= p_x * math.log2(p_x)
    return entropy

class DNSTunnelDetectionRule(BaseDetectionRule):
    rule_id = "DNS_TUNNEL"
    title = "High-Entropy DNS Tunneling / Exfiltration"
    severity = "HIGH"
    mitre_technique = "T1071.004"

    def __init__(self, max_subdomain_len: int = 30, max_entropy: float = 4.2):
        self.max_subdomain_len = max_subdomain_len
        self.max_entropy = max_entropy

    def analyze(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        for p in packets:
            if p.get("protocol") == "DNS":
                info = p.get("info", "")
                if "Query" in info:
                    domain = info.replace("DNS Query ", "").strip()
                    entropy = calculate_shannon_entropy(domain)
                    if len(domain) > self.max_subdomain_len or entropy > self.max_entropy:
                        alerts.append({
                            "rule_id": self.rule_id,
                            "title": self.title,
                            "severity": self.severity,
                            "description": f"Abnormally high entropy or long query name detected in DNS request from {p.get('src_ip')}.",
                            "evidence": f"Domain: '{domain}', Length: {len(domain)}, Entropy: {entropy:.2f}",
                            "mitre_technique": self.mitre_technique,
                            "src_ip": p.get("src_ip"),
                            "dst_ip": p.get("dst_ip")
                        })
        return alerts

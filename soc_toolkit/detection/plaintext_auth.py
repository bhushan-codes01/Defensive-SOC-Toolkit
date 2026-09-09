from typing import List, Dict, Any
from .base import BaseDetectionRule

class PlaintextAuthDetectionRule(BaseDetectionRule):
    rule_id = "PLAINTEXT_AUTH"
    title = "Unencrypted Plaintext Protocol Warning"
    severity = "MEDIUM"
    mitre_technique = "T1040"

    def analyze(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        alerts = []
        seen = set()

        for p in packets:
            proto = p.get("protocol")
            src = p.get("src_ip")
            dst = p.get("dst_ip")
            dst_port = p.get("dst_port")

            if proto in ["FTP", "TELNET"] or dst_port in [21, 23]:
                key = (src, dst, proto)
                if key not in seen:
                    seen.add(key)
                    alerts.append({
                        "rule_id": self.rule_id,
                        "title": self.title,
                        "severity": self.severity,
                        "description": f"Unencrypted {proto or 'Plaintext'} protocol traffic observed between {src} and {dst}.",
                        "evidence": f"Protocol: {proto or dst_port}. Plaintext authentication credentials are vulnerable to packet sniffing.",
                        "mitre_technique": self.mitre_technique,
                        "src_ip": src,
                        "dst_ip": dst
                    })
        return alerts

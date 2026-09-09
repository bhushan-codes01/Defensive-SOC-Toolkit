from typing import List, Dict, Any
from .port_scan import PortScanDetectionRule
from .arp_spoof import ARPSpoofDetectionRule
from .dns_tunnel import DNSTunnelDetectionRule
from .syn_flood import SYNFloodDetectionRule
from .plaintext_auth import PlaintextAuthDetectionRule
from ..db import insert_alert, get_alerts

class DetectionEngine:
    def __init__(self):
        self.rules = [
            PortScanDetectionRule(),
            ARPSpoofDetectionRule(),
            DNSTunnelDetectionRule(),
            SYNFloodDetectionRule(),
            PlaintextAuthDetectionRule()
        ]

    def run_on_packets(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        all_alerts = []
        for rule in self.rules:
            try:
                rule_alerts = rule.analyze(packets)
                for alert in rule_alerts:
                    # Persist alert to database
                    insert_alert(
                        rule_id=alert["rule_id"],
                        severity=alert["severity"],
                        title=alert["title"],
                        description=alert["description"],
                        evidence=alert["evidence"],
                        mitre_technique=alert["mitre_technique"],
                        src_ip=alert.get("src_ip"),
                        dst_ip=alert.get("dst_ip")
                    )
                    all_alerts.append(alert)
            except Exception as e:
                print(f"Error running detection rule {rule.rule_id}: {e}")
        return all_alerts

engine = DetectionEngine()

def run_detection(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return engine.run_on_packets(packets)

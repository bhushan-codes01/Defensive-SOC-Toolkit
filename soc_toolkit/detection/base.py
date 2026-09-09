from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseDetectionRule(ABC):
    rule_id: str = "BASE_RULE"
    title: str = "Base Detection Rule"
    severity: str = "LOW"
    mitre_technique: str = "T1000"

    @abstractmethod
    def analyze(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze a list of packet dicts and return a list of alert dicts.
        Each alert dict should contain:
        {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "description": str,
            "evidence": str,
            "mitre_technique": self.mitre_technique,
            "src_ip": str,
            "dst_ip": str
        }
        """
        pass

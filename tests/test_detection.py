import pytest
from soc_toolkit.detection.port_scan import PortScanDetectionRule
from soc_toolkit.detection.dns_tunnel import DNSTunnelDetectionRule
from soc_toolkit.detection.syn_flood import SYNFloodDetectionRule
from soc_toolkit.detection.plaintext_auth import PlaintextAuthDetectionRule

def test_port_scan_rule():
    rule = PortScanDetectionRule(port_threshold=5)
    packets = [
        {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": p, "protocol": "TCP"}
        for p in range(1, 10)
    ]
    alerts = rule.analyze(packets)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "PORT_SCAN"
    assert alerts[0]["severity"] == "HIGH"

def test_dns_tunnel_rule():
    rule = DNSTunnelDetectionRule(max_subdomain_len=15)
    packets = [
        {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "protocol": "DNS", "info": "DNS Query a1b2c3d4e5f6g7h8j9k0l1.tunnel.com"}
    ]
    alerts = rule.analyze(packets)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "DNS_TUNNEL"

def test_syn_flood_rule():
    rule = SYNFloodDetectionRule(threshold=5)
    packets = [
        {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "protocol": "TCP", "info": "TCP 44321 -> 80 [SYN]"}
        for _ in range(6)
    ]
    alerts = rule.analyze(packets)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SYN_FLOOD"

def test_plaintext_auth_rule():
    rule = PlaintextAuthDetectionRule()
    packets = [
        {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "protocol": "TELNET", "dst_port": 23}
    ]
    alerts = rule.analyze(packets)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "PLAINTEXT_AUTH"

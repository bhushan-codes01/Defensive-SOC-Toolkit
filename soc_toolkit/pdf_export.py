import json
import time
from typing import List, Dict, Any
from .db import get_incidents, get_alerts

def generate_incident_report_text() -> str:
    incidents = get_incidents()
    alerts = get_alerts(limit=10)
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    report = []
    report.append("================================================================================")
    report.append("                   DEFENSIVE SOC TOOLKIT — INCIDENT REPORT                      ")
    report.append("================================================================================")
    report.append(f"Generated At  : {now_str}")
    report.append(f"System Scope  : Private Network Monitoring & Threat Detection System")
    report.append(f"Curriculum    : Computer Networks (CN) & Cybersecurity Lab Evaluation")
    report.append("--------------------------------------------------------------------------------\n")

    report.append("1. ACTIVE INCIDENTS OVERVIEW")
    report.append("--------------------------------------------------------------------------------")
    if not incidents:
        report.append("No active security incidents recorded.\n")
    else:
        for inc in incidents:
            report.append(f"Incident ID   : #{inc['id']}")
            report.append(f"Title         : {inc['title']}")
            report.append(f"Severity      : [{inc['severity']}]")
            report.append(f"Status        : {inc['status']}")
            report.append(f"Assigned To   : {inc['assigned_to']}")
            report.append(f"Notes         : {inc['notes']}")
            report.append("--------------------------------------------------------------------------------")
    report.append("\n2. RECENT DETECTED ALERTS SUMMARY")
    report.append("--------------------------------------------------------------------------------")
    for a in alerts:
        report.append(f"[{a['severity']}] {a['title']} (Rule: {a['rule_id']} / MITRE: {a['mitre_technique']})")
        report.append(f"  Source: {a['src_ip']} -> Destination: {a['dst_ip']}")
        report.append(f"  Details: {a['description']}")
        report.append("--------------------------------------------------------------------------------")

    report.append("\n================================================================================")
    report.append("END OF INCIDENT REPORT — CONFIDENTIAL SOC EVALUATION DOCUMENT")
    report.append("================================================================================")

    return "\n".join(report)

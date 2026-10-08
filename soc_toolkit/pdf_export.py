import io
import time
from collections import Counter
from typing import Dict, Any

from .db import get_incidents, get_alerts, get_packets_summary


def _now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def collect_report_data() -> Dict[str, Any]:
    """Gather everything needed for incident + audit reports."""
    from .chain import audit_chain
    from .topology import discover_topology
    from .packet_analyzer import aggregate_packet_data
    try:
        from .iot_monitor import get_recent_telemetry
        telemetry = get_recent_telemetry(limit=50)
    except Exception:
        telemetry = []

    incidents = get_incidents()
    alerts = get_alerts(limit=100)
    packets_raw = get_packets_summary(limit=200)
    packet_stats = aggregate_packet_data(packets_raw)
    topology = discover_topology()
    chain = audit_chain.get_chain()
    verification = audit_chain.verify_integrity()

    sev_counts = dict(Counter(a.get("severity", "UNKNOWN") for a in alerts))
    rule_counts = dict(Counter(a.get("rule_id", "UNKNOWN") for a in alerts))

    return {
        "generated_at": _now_str(),
        "generated_epoch": time.time(),
        "scope": "Private Network Monitoring & Threat Detection System",
        "curriculum": "Computer Networks (CN) & Cybersecurity Lab Evaluation (NEP 2020)",
        "incidents": incidents,
        "alerts": alerts,
        "packets": packets_raw[:50],
        "packet_stats": packet_stats,
        "topology": topology,
        "telemetry": telemetry,
        "chain": chain,
        "verification": verification,
        "severity_counts": sev_counts,
        "rule_counts": rule_counts,
        "totals": {
            "incidents": len(incidents),
            "alerts": len(alerts),
            "packets": packet_stats.get("total_packets", 0),
            "bytes": packet_stats.get("total_bytes", 0),
            "chain_blocks": verification.get("total_blocks", len(chain)),
            "telemetry": len(telemetry),
        },
    }


def generate_incident_report_text() -> str:
    data = collect_report_data()
    incidents = data["incidents"]
    alerts = data["alerts"]
    verification = data["verification"]

    report = []
    report.append("================================================================================")
    report.append("                   DEFENSIVE SOC TOOLKIT — INCIDENT REPORT                      ")
    report.append("================================================================================")
    report.append(f"Generated At  : {data['generated_at']}")
    report.append(f"System Scope  : {data['scope']}")
    report.append(f"Curriculum    : {data['curriculum']}")
    report.append(f"Audit Chain   : {verification.get('status')} | Blocks={verification.get('total_blocks')} | Merkle={verification.get('merkle_root','')[:16]}...")
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
            report.append(f"Assigned To   : {inc.get('assigned_to','')}")
            report.append(f"Notes         : {inc.get('notes','')}")
            report.append("--------------------------------------------------------------------------------")
    report.append("\n2. RECENT DETECTED ALERTS SUMMARY")
    report.append("--------------------------------------------------------------------------------")
    for a in alerts[:20]:
        report.append(f"[{a['severity']}] {a['title']} (Rule: {a['rule_id']} / MITRE: {a['mitre_technique']})")
        report.append(f"  Source: {a.get('src_ip')} -> Destination: {a.get('dst_ip')}")
        report.append(f"  Details: {a.get('description')}")
        report.append("--------------------------------------------------------------------------------")

    report.append("\n3. AUDIT CHAIN INTEGRITY")
    report.append("--------------------------------------------------------------------------------")
    report.append(f"Status        : {verification.get('status')}")
    report.append(f"Total Blocks  : {verification.get('total_blocks')}")
    report.append(f"Merkle Root   : {verification.get('merkle_root')}")
    report.append(f"Broken Indices: {verification.get('broken_indices')}")

    report.append("\n================================================================================")
    report.append("END OF INCIDENT REPORT — CONFIDENTIAL SOC EVALUATION DOCUMENT")
    report.append("================================================================================")

    return "\n".join(report)


# ---------------------------------------------------------------------------
# PDF generation (reportlab)
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "CRITICAL": "#C62828",
    "HIGH": "#EF6C00",
    "MEDIUM": "#F9A825",
    "LOW": "#2E7D32",
}

_DARK_BG = "#0F1520"
_ACCENT = "#00E5FF"


def _pdf_styles():
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.lib.colors import HexColor

    ss = getSampleStyleSheet()
    title = ParagraphStyle("SOC_Title", parent=ss["Title"], fontSize=22, leading=26,
                           textColor=HexColor("#0B1C2C"), alignment=TA_CENTER, spaceAfter=4)
    subtitle = ParagraphStyle("SOC_Sub", parent=ss["Normal"], fontSize=10, leading=14,
                              textColor=HexColor("#455A64"), alignment=TA_CENTER, spaceAfter=8)
    h1 = ParagraphStyle("SOC_H1", parent=ss["Heading1"], fontSize=14, leading=17,
                        textColor=HexColor("#0B1C2C"), spaceBefore=14, spaceAfter=8,
                        borderPadding=(0, 0, 4, 0))
    h2 = ParagraphStyle("SOC_H2", parent=ss["Heading2"], fontSize=11, leading=14,
                        textColor=HexColor("#1565C0"), spaceBefore=10, spaceAfter=6)
    body = ParagraphStyle("SOC_Body", parent=ss["Normal"], fontSize=9, leading=13,
                          textColor=HexColor("#263238"), alignment=TA_LEFT)
    small = ParagraphStyle("SOC_Small", parent=ss["Normal"], fontSize=7.5, leading=10,
                           textColor=HexColor("#546E7A"))
    cell = ParagraphStyle("SOC_Cell", parent=ss["Normal"], fontSize=8, leading=10,
                          textColor=HexColor("#263238"))
    cell_small = ParagraphStyle("SOC_CellSmall", parent=ss["Normal"], fontSize=7, leading=9,
                                textColor=HexColor("#37474F"), fontName="Courier")
    badge = ParagraphStyle("SOC_Badge", parent=ss["Normal"], fontSize=8, leading=10,
                           textColor=HexColor("#FFFFFF"), alignment=TA_CENTER)
    return {"title": title, "subtitle": subtitle, "h1": h1, "h2": h2,
            "body": body, "small": small, "cell": cell,
            "cell_small": cell_small, "badge": badge}


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColorRGB(0.35, 0.45, 0.55)
    canvas.drawString(40, 30, "Defensive SOC Toolkit — Confidential SOC Evaluation Document")
    canvas.drawRightString(555, 30, f"Page {doc.page}")
    canvas.setStrokeColorRGB(0.0, 0.9, 1.0)
    canvas.setLineWidth(2)
    canvas.line(40, 815, 555, 815)
    canvas.restoreState()


def _cover_header(story, styles, heading: str, subheading: str, data: Dict[str, Any]):
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.colors import HexColor

    story.append(Paragraph("DEFENSIVE SOC TOOLKIT", styles["subtitle"]))
    story.append(Paragraph(heading, styles["title"]))
    story.append(Paragraph(subheading, styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=HexColor("#00E5FF"), spaceAfter=10))

    meta = [
        ["Generated At", data["generated_at"]],
        ["System Scope", data["scope"]],
        ["Curriculum", data["curriculum"]],
        ["Audit Chain", f"{data['verification'].get('status')}  |  Blocks={data['verification'].get('total_blocks')}  |  Merkle={str(data['verification'].get('merkle_root',''))[:24]}..."],
    ]
    t = Table(meta, colWidths=[130, 375])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#0B1C2C")),
        ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#FFFFFF")),
        ("BACKGROUND", (1, 0), (1, -1), HexColor("#ECEFF1")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#B0BEC5")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))


def _kpi_cards(story, styles, data: Dict[str, Any]):
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.colors import HexColor

    totals = data["totals"]
    cards = [
        [Paragraph(f"<b><font size=16>{totals['incidents']}</font></b><br/>Incidents", styles["body"]),
         Paragraph(f"<b><font size=16>{totals['alerts']}</font></b><br/>Alerts", styles["body"]),
         Paragraph(f"<b><font size=16>{totals['packets']}</font></b><br/>Packets", styles["body"]),
         Paragraph(f"<b><font size=16>{totals['chain_blocks']}</font></b><br/>Chain Blocks", styles["body"])],
    ]
    t = Table(cards, colWidths=[126, 126, 126, 126])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#E1F5FE")),
        ("BOX", (0, 0), (-1, -1), 1, HexColor("#0288D1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#B3E5FC")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t)
    story.append(Spacer(1, 4))
    sev_line = "  |  ".join(f"{k}: {v}" for k, v in sorted(data["severity_counts"].items())) or "No alerts"
    story.append(Paragraph(f"<b>Severity breakdown:</b> {sev_line}", styles["small"]))
    story.append(Paragraph(f"<b>Rules triggered:</b> {', '.join(f'{k}×{v}' for k, v in sorted(data['rule_counts'].items())) or '—'}", styles["small"]))


def _styled_table(headers, rows, col_widths, styles, sev_col: int = -1):
    from reportlab.platypus import Table, TableStyle, Paragraph
    from reportlab.lib.colors import HexColor

    header_row = [Paragraph(f"<b>{h}</b>", styles["cell"]) for h in headers]
    body = [header_row]
    for r in rows:
        body.append([Paragraph(str(c), styles["cell"]) if i != sev_col else c for i, c in enumerate(r)])

    t = Table(body, colWidths=col_widths, repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0B1C2C")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, HexColor("#B0BEC5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), HexColor("#F5F7FA")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    t.setStyle(TableStyle(style_cmds))
    return t


def _sev_badge(sev: str, styles):
    from reportlab.platypus import Paragraph
    color = _SEV_COLORS.get(sev.upper(), "#455A64")
    return Paragraph(f'<font color="{color}"><b>[{sev}]</b></font>', styles["cell"])


def build_pdf(kind: str = "incident") -> bytes:
    """Build a styled PDF. kind = 'incident' or 'audit'."""
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    HRFlowable, PageBreak, KeepTogether)
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import mm

    data = collect_report_data()
    styles = _pdf_styles()
    buf = io.BytesIO()

    is_audit = (kind == "audit")
    title = "AUDIT & INTEGRITY REPORT" if is_audit else "INCIDENT RESPONSE REPORT"
    subtitle = ("Tamper-evident SHA-256 audit chain • Merkle verification • Full telemetry"
                if is_audit else
                "Network monitoring • Threat detection • Incident evaluation")

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=40, rightMargin=40,
                            topMargin=50, bottomMargin=40,
                            title=f"Defensive SOC Toolkit — {title}",
                            author="Defensive SOC Toolkit")
    story = []
    _cover_header(story, styles, title, subtitle, data)
    _kpi_cards(story, styles, data)

    # --- Incidents ---
    story.append(Paragraph("1 &nbsp;—&nbsp; Incidents Overview", styles["h1"]))
    if not data["incidents"]:
        story.append(Paragraph("No active security incidents recorded.", styles["body"]))
    else:
        rows = []
        for inc in data["incidents"]:
            rows.append([
                f"#{inc.get('id')}",
                str(inc.get("title", ""))[:70],
                _sev_badge(str(inc.get("severity", "")), styles),
                str(inc.get("status", "")),
                str(inc.get("assigned_to", ""))[:18],
            ])
        story.append(_styled_table(
            ["ID", "Title", "Severity", "Status", "Assignee"],
            rows, [35, 220, 70, 90, 90], styles, sev_col=2))
        story.append(Spacer(1, 6))
        for inc in data["incidents"][:6]:
            story.append(Paragraph(
                f"<b>#{inc.get('id')} {inc.get('title')}</b> — {inc.get('notes','')}", styles["small"]))

    # --- Alerts ---
    story.append(Paragraph("2 &nbsp;—&nbsp; Detection Alerts (MITRE-mapped)", styles["h1"]))
    if not data["alerts"]:
        story.append(Paragraph("No alerts generated.", styles["body"]))
    else:
        rows = []
        for a in data["alerts"][:25]:
            rows.append([
                _sev_badge(str(a.get("severity", "")), styles),
                str(a.get("title", ""))[:42],
                str(a.get("rule_id", "")),
                str(a.get("mitre_technique", "")),
                f"{a.get('src_ip','')} → {a.get('dst_ip','')}"[:30],
            ])
        story.append(_styled_table(
            ["Sev", "Title", "Rule", "MITRE", "Src → Dst"],
            rows, [45, 175, 80, 70, 135], styles, sev_col=0))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            f"Showing {min(25, len(data['alerts']))} of {len(data['alerts'])} alerts. "
            f"Full list available via <font face='Courier'>GET /api/alerts</font>.", styles["small"]))

    # --- Packets ---
    ps = data["packet_stats"]
    story.append(Paragraph("3 &nbsp;—&nbsp; Packet Analysis Summary", styles["h1"]))
    story.append(Paragraph(
        f"Total packets: <b>{ps.get('total_packets', 0)}</b> &nbsp;|&nbsp; "
        f"Total bytes: <b>{ps.get('total_bytes', 0)}</b> &nbsp;|&nbsp; "
        f"Protocols: <b>{ps.get('protocol_breakdown', {})}</b>", styles["body"]))
    talkers = ps.get("top_talkers", [])
    if talkers:
        rows = [[t.get("ip"), str(t.get("count"))] for t in talkers[:8]]
        story.append(Spacer(1, 6))
        story.append(_styled_table(["Top Talker IP", "Count"], rows, [300, 205], styles))
    if data["packets"]:
        rows = []
        for p in data["packets"][:20]:
            ports = f"{p.get('src_port','-')}→{p.get('dst_port','-')}" if p.get("src_port") else "—"
            rows.append([str(p.get("protocol", ""))[:10], str(p.get("src_ip", ""))[:18],
                         str(p.get("dst_ip", ""))[:18], ports[:16], str(p.get("packet_size", ""))])
        story.append(Spacer(1, 6))
        story.append(Paragraph("Recent decoded packets (sample of 20):", styles["h2"]))
        story.append(_styled_table(["Proto", "Src IP", "Dst IP", "Ports", "Size"],
                                   rows, [70, 130, 130, 90, 85], styles))

    # --- Topology ---
    topo = data.get("topology", {})
    story.append(Paragraph("4 &nbsp;—&nbsp; Network Topology & OS Fingerprinting", styles["h1"]))
    nodes = topo.get("nodes", [])
    if nodes:
        rows = [[n.get("label", "")[:44], n.get("ip", ""), n.get("os", "")[:34]] for n in nodes]
        story.append(_styled_table(["Device", "IP", "OS (TTL heuristic)"],
                                   rows, [220, 110, 175], styles))
    links = topo.get("links", [])
    if links:
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "Links: " + "; ".join(f"{l.get('source')}→{l.get('target')} ({l.get('rtt_ms')}ms)" for l in links[:8]),
            styles["small"]))

    # --- IoT ---
    story.append(Paragraph("5 &nbsp;—&nbsp; IoT Telemetry (last 15)", styles["h1"]))
    tel = data.get("telemetry", [])[-15:]
    if not tel:
        story.append(Paragraph("No telemetry received. Run <font face='Courier'>python simulator.py</font>.", styles["body"]))
    else:
        rows = []
        for t in tel:
            rows.append([str(t.get("device_id", ""))[:20], str(t.get("temperature", "")),
                         str(t.get("humidity", "")), str(t.get("status", ""))[:16]])
        story.append(_styled_table(["Device", "Temp °C", "Hum %", "Status"],
                                   rows, [180, 90, 90, 145], styles))

    # --- Audit chain ---
    v = data["verification"]
    story.append(Paragraph("6 &nbsp;—&nbsp; Tamper-Evident Audit Chain (SHA-256)", styles["h1"]))
    color = "#2E7D32" if v.get("is_valid") else "#C62828"
    story.append(Paragraph(
        f"<b>Status:</b> <font color=\"{color}\"><b>{v.get('status')}</b></font> &nbsp;|&nbsp; "
        f"<b>Blocks:</b> {v.get('total_blocks')} &nbsp;|&nbsp; "
        f"<b>Broken:</b> {v.get('broken_indices') or 'none'}", styles["body"]))
    story.append(Paragraph(f"<b>Merkle root:</b> <font face='Courier' size=7>{v.get('merkle_root')}</font>", styles["small"]))
    chain_rows = []
    for b in data["chain"][-20:]:
        chain_rows.append([str(b.get("block_index")), str(b.get("block_hash", ""))[:18] + "…",
                           str(b.get("prev_hash", ""))[:18] + "…",
                           str(b.get("payload_json", ""))[:44]])
    if chain_rows:
        story.append(Spacer(1, 6))
        story.append(_styled_table(["Idx", "Block Hash", "Prev Hash", "Payload (trunc)"],
                                   chain_rows, [40, 130, 130, 205], styles))

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#B0BEC5")))
    story.append(Paragraph(
        "END OF REPORT — Confidential SOC evaluation document. Generated locally by Defensive SOC Toolkit. "
        "Lab scope: owned devices / private networks only.", styles["small"]))

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return buf.getvalue()


def generate_incident_report_pdf_bytes() -> bytes:
    return build_pdf(kind="incident")


def generate_audit_report_pdf_bytes() -> bytes:
    return build_pdf(kind="audit")

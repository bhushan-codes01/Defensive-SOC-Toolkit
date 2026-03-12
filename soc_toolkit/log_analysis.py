import re


PATTERNS = [
    ("failed_login", re.compile(r"failed password|authentication failure|invalid user|4625", re.I), "Repeated failed login evidence"),
    ("privilege", re.compile(r"sudo|administrator|privilege|elevation|4672", re.I), "Privilege or admin activity"),
    ("encoded_command", re.compile(r"powershell.*-enc|encodedcommand|frombase64string", re.I), "Possible encoded command execution"),
    ("lateral", re.compile(r"psexec|wmic|winrm|remote service|admin\$", re.I), "Possible lateral movement pattern"),
    ("malware_ext", re.compile(r"\.(exe|scr|js|vbs|ps1|bat|dll)(\s|$)", re.I), "Executable or script artifact"),
    ("scan", re.compile(r"port scan|nmap|masscan|multiple connection attempts", re.I), "Scanning activity"),
]


def analyze_logs(payload):
    content = payload.get("logs", "")
    lines = content.splitlines()
    counts = {}
    examples = {}

    for index, line in enumerate(lines, start=1):
        for key, pattern, label in PATTERNS:
            if pattern.search(line):
                counts[key] = counts.get(key, 0) + 1
                examples.setdefault(key, {"line": index, "text": line[:220], "label": label})

    ip_counts = {}
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content):
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    indicators = [{
        "type": key,
        "label": examples[key]["label"],
        "count": count,
        "exampleLine": examples[key]["line"],
        "example": examples[key]["text"],
        "severity": "high" if key in ["encoded_command", "lateral"] else "medium",
    } for key, count in counts.items()]

    return {
        "lineCount": len(lines),
        "indicators": indicators,
        "topIps": sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:10],
    }

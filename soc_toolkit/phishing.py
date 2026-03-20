from urllib.parse import urlencode, urlparse
import re

from .http_client import fetch_json


URLHAUS_LOOKUP_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def _check_urlhaus(url):
    try:
        return fetch_json(
            URLHAUS_LOOKUP_URL,
            method="POST",
            data=urlencode({"url": url}),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            ttl=600,
        )
    except Exception as exc:
        return {"query_status": "lookup_error", "message": str(exc)}


def phishing_check(payload):
    text = payload.get("text", "")
    urls = re.findall(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", text, re.I)
    findings = []

    for raw in urls[:10]:
        url = raw if raw.startswith(("http://", "https://")) else "http://" + raw
        parsed = urlparse(url)
        host = parsed.hostname or ""
        rules = []

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            rules.append("URL uses a raw IP address")
        if host.count("-") >= 3:
            rules.append("Domain has unusual hyphenation")
        if any(short in host for short in ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]):
            rules.append("Uses a link shortener")
        if "@" in url:
            rules.append("URL contains @, which can hide the true destination")
        if host.startswith("xn--"):
            rules.append("Punycode domain may indicate lookalike characters")
        if parsed.scheme != "https":
            rules.append("Does not use HTTPS")

        abuse = _check_urlhaus(url)
        if abuse.get("query_status") == "ok":
            rules.append(f"Matched URLhaus as {abuse.get('threat', 'malicious')}")

        findings.append({
            "url": url,
            "host": host,
            "risk": "high" if abuse.get("query_status") == "ok" or len(rules) >= 3 else "medium" if rules else "low",
            "rules": rules or ["No obvious phishing indicator found"],
            "urlhausStatus": abuse.get("query_status"),
            "urlhausReference": abuse.get("urlhaus_reference"),
        })

    message_findings = []
    for phrase in ["urgent action required", "verify your account", "password expires", "gift card", "wire transfer", "login immediately"]:
        if phrase in text.lower():
            message_findings.append(f"Message contains pressure phrase: {phrase}")

    return {"urls": findings, "messageFindings": message_findings}

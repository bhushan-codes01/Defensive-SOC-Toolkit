from urllib.parse import urlparse
import re

from .http_client import fetch_json, fetch_text


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_ADVISORIES_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"


def latest_kev(limit=12):
    data = fetch_json(CISA_KEV_URL)
    vulns = data.get("vulnerabilities", [])
    vulns.sort(key=lambda item: item.get("dateAdded", ""), reverse=True)
    return vulns[:limit]


def _cisa_advisories(limit=10):
    xml = fetch_text(CISA_ADVISORIES_URL)
    advisories = []
    for entry in re.findall(r"<item>(.*?)</item>", xml, re.S)[:limit]:
        title = re.search(r"<title><!\[CDATA\[(.*?)\]\]></title>|<title>(.*?)</title>", entry, re.S)
        link = re.search(r"<link>(.*?)</link>", entry, re.S)
        date = re.search(r"<pubDate>(.*?)</pubDate>", entry, re.S)
        advisories.append({
            "title": (title.group(1) or title.group(2)).strip() if title else "CISA advisory",
            "link": link.group(1).strip() if link else "https://www.cisa.gov/news-events/cybersecurity-advisories",
            "date": date.group(1).strip() if date else "",
        })
    return advisories


def _recent_urlhaus(limit=10):
    data = fetch_json(URLHAUS_RECENT_URL, ttl=600)
    rows = []
    for _, row in list(data.items())[:limit]:
        rows.append({
            "url": row.get("url"),
            "host": urlparse(row.get("url", "")).netloc,
            "threat": row.get("threat"),
            "dateAdded": row.get("dateadded"),
            "urlhaus": row.get("urlhaus_reference"),
        })
    return rows


def threat_feed():
    try:
        kev = latest_kev(10)
    except Exception:
        kev = []
    try:
        advisories = _cisa_advisories()
    except Exception:
        advisories = []
    try:
        malicious_urls = _recent_urlhaus()
    except Exception:
        malicious_urls = []
    return {"kev": kev, "advisories": advisories, "maliciousUrls": malicious_urls}

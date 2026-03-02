from urllib.parse import urlencode
import re

from .http_client import fetch_json
from .threat_intel import latest_kev


NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cve_score(cve):
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key)
        if values:
            data = values[0].get("cvssData", {})
            return {"score": data.get("baseScore"), "severity": data.get("baseSeverity", values[0].get("baseSeverity"))}
    return {"score": None, "severity": "UNKNOWN"}


def vulnerability_lookup(payload):
    keyword = (payload.get("keyword") or "").strip()
    if not keyword:
        raise ValueError("Enter a product, vendor, CVE ID, or keyword.")

    params = {"resultsPerPage": 12, "noRejected": ""}
    if re.match(r"^CVE-\d{4}-\d{4,}$", keyword, re.I):
        params["cveId"] = keyword.upper()
    else:
        params["keywordSearch"] = keyword

    data = fetch_json(NVD_CVES_URL + "?" + urlencode(params))
    try:
        kev_ids = {item.get("cveID") for item in latest_kev(2000)}
    except Exception:
        kev_ids = set()

    items = []
    for row in data.get("vulnerabilities", []):
        cve = row.get("cve", {})
        cve_id = cve.get("id")
        description = next((desc.get("value") for desc in cve.get("descriptions", []) if desc.get("lang") == "en"), "")
        score = _cve_score(cve)
        items.append({
            "id": cve_id,
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
            "description": description[:500],
            "score": score.get("score"),
            "severity": score.get("severity"),
            "knownExploited": cve_id in kev_ids,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    return {"total": data.get("totalResults", 0), "items": items}

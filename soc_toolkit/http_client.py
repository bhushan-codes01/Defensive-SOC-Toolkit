from urllib.request import Request, urlopen
import json
import time

from .config import CACHE_TTL_SECONDS, USER_AGENT


_CACHE = {}


def cached_fetch(url, method="GET", data=None, headers=None, ttl=CACHE_TTL_SECONDS):
    key = (method, url, data or "")
    now = time.time()
    if key in _CACHE and now - _CACHE[key]["time"] < ttl:
        return _CACHE[key]["value"]

    body = data.encode("utf-8") if isinstance(data, str) else data
    default_headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/xml,text/html,*/*"}
    request = Request(url, data=body, method=method, headers={**default_headers, **(headers or {})})
    with urlopen(request, timeout=15) as response:
        text = response.read().decode("utf-8", errors="replace")

    _CACHE[key] = {"time": now, "value": text}
    return text


def fetch_json(url, **kwargs):
    return json.loads(cached_fetch(url, **kwargs))


def fetch_text(url, **kwargs):
    return cached_fetch(url, **kwargs)

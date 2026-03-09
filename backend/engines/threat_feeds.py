"""
Threat Intelligence Feed Aggregator — Free API lookups for ScamGate L0.

Checks URLs and domains against multiple free/freemium threat intelligence
APIs with built-in rate limiting and TTL caching.

Free (no key):
  - URLhaus (abuse.ch) — malware URL + host lookup
  - PhishTank — phishing URL database

Freemium (key required):
  - Google Safe Browsing — malware, social engineering, unwanted software
  - VirusTotal — multi-engine scan (4 req/min free tier)
  - IP Quality Score — fraud/phishing scoring

All stdlib. No third-party deps.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("chetana.threat_feeds")

# ---------------------------------------------------------------------------
# Secrets loader — local Keychain-backed resolver, MirrorDNA lib, or env vars
# ---------------------------------------------------------------------------
try:
    from engines.secrets_loader import get_secret
except ImportError:
    try:
        from .secrets_loader import get_secret
    except ImportError:
        try:
            sys.path.insert(0, str(Path.home() / ".mirrordna" / "lib"))
            from secrets_loader import get_secret
        except ImportError:
            def get_secret(name: str) -> str:
                return os.environ.get(name, "")


# ---------------------------------------------------------------------------
# SSL context (permissive for API calls, not for browsing)
# ---------------------------------------------------------------------------
_ssl_ctx = ssl.create_default_context()


# ---------------------------------------------------------------------------
# TTL cache — in-memory, 1-hour expiry
# ---------------------------------------------------------------------------
_CACHE_TTL = 3600  # seconds

_cache: dict[str, tuple[float, "ThreatFeedResult"]] = {}


def _cache_key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def _cache_get(url: str) -> Optional["ThreatFeedResult"]:
    key = _cache_key(url)
    if key in _cache:
        ts, result = _cache[key]
        if time.time() - ts < _CACHE_TTL:
            result.cached = True
            return result
        del _cache[key]
    return None


def _cache_set(url: str, result: "ThreatFeedResult") -> None:
    _cache[_cache_key(url)] = (time.time(), result)


# ---------------------------------------------------------------------------
# Rate limiter — per-API minimum interval tracking
# ---------------------------------------------------------------------------
_rate_limits: dict[str, float] = {}  # api_name -> last_request_time


def _rate_ok(api_name: str, min_interval: float) -> bool:
    """Return True if enough time has passed since last request to this API."""
    now = time.time()
    last = _rate_limits.get(api_name, 0.0)
    if now - last < min_interval:
        return False
    _rate_limits[api_name] = now
    return True


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------
_DEFAULT_TIMEOUT = 8  # seconds


def _post_form(url: str, data: dict, timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict]:
    """POST form-encoded data, return parsed JSON or None."""
    try:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=encoded,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.debug("POST %s failed: %s", url, exc)
        return None


def _post_json(url: str, payload: dict, headers: Optional[dict] = None,
               timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict]:
    """POST JSON payload, return parsed JSON or None."""
    try:
        body = json.dumps(payload).encode("utf-8")
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=body, headers=hdrs)
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.debug("POST JSON %s failed: %s", url, exc)
        return None


def _get_json(url: str, headers: Optional[dict] = None,
              timeout: int = _DEFAULT_TIMEOUT) -> Optional[dict]:
    """GET request, return parsed JSON or None."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.debug("GET %s failed: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class ThreatFeedResult:
    is_threat: bool
    threat_types: list[str]          # malware, phishing, scam, unwanted, etc.
    confidence: float                # 0.0–1.0
    feed_results: dict               # per-API raw results
    feeds_checked: list[str]
    cached: bool = False


# ---------------------------------------------------------------------------
# Individual feed functions
# ---------------------------------------------------------------------------

def check_urlhaus_url(url: str) -> Optional[dict]:
    """Check a URL against URLhaus (abuse.ch). Free, no key."""
    if not _rate_ok("urlhaus_url", 1.0):
        return None
    resp = _post_form("https://urlhaus-api.abuse.ch/v1/url/", {"url": url})
    if resp and resp.get("query_status") == "listed":
        return {
            "listed": True,
            "threat": resp.get("threat", "unknown"),
            "tags": resp.get("tags", []),
            "url_status": resp.get("url_status", ""),
            "date_added": resp.get("date_added", ""),
        }
    if resp and resp.get("query_status") == "no_results":
        return {"listed": False}
    return None


def check_urlhaus_host(domain: str) -> Optional[dict]:
    """Check a host/domain against URLhaus (abuse.ch). Free, no key."""
    if not _rate_ok("urlhaus_host", 1.0):
        return None
    resp = _post_form("https://urlhaus-api.abuse.ch/v1/host/", {"host": domain})
    if resp and resp.get("query_status") == "listed":
        url_count = resp.get("url_count", 0)
        urls_online = resp.get("urls_online", 0)
        return {
            "listed": True,
            "url_count": url_count,
            "urls_online": urls_online,
        }
    if resp and resp.get("query_status") in ("no_results", "invalid_host"):
        return {"listed": False}
    return None


def check_phishtank(url: str) -> Optional[dict]:
    """Check a URL against PhishTank. Free, no key needed for basic lookups."""
    if not _rate_ok("phishtank", 1.0):
        return None
    resp = _post_form(
        "https://checkurl.phishtank.com/checkurl/",
        {"url": url, "format": "json"},
    )
    if resp and "results" in resp:
        results = resp["results"]
        in_db = results.get("in_database", False)
        is_phish = results.get("valid", False) if in_db else False
        return {
            "in_database": in_db,
            "is_phish": is_phish,
            "phish_id": results.get("phish_id", ""),
        }
    return None


def check_google_safe_browsing(url: str) -> Optional[dict]:
    """Check URL via Google Safe Browsing API v4. Requires API key."""
    api_key = get_secret("GOOGLE_SAFE_BROWSING_KEY") or get_secret("GEMINI_KEY")
    if not api_key:
        return None
    if not _rate_ok("google_sb", 0.5):
        return None

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "chetana-scamgate",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    resp = _post_json(endpoint, payload)
    if resp is not None:
        matches = resp.get("matches", [])
        if matches:
            threat_types = list({m.get("threatType", "") for m in matches})
            return {"is_threat": True, "threat_types": threat_types}
        return {"is_threat": False, "threat_types": []}
    return None


def check_virustotal(url: str) -> Optional[dict]:
    """Check URL via VirusTotal API v3. Requires API key. 4 req/min free tier."""
    api_key = get_secret("VIRUSTOTAL_API_KEY")
    if not api_key:
        return None
    # 4 requests/min = 1 request per 15 seconds minimum
    if not _rate_ok("virustotal", 15.0):
        logger.debug("VirusTotal rate-limited (4/min), skipping")
        return None

    # url_id = base64url of the URL, no padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    resp = _get_json(endpoint, headers={"x-apikey": api_key})
    if resp and "data" in resp:
        attrs = resp["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1
        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "score": (malicious + suspicious) / max(total, 1),
            "categories": attrs.get("categories", {}),
        }
    # URL not yet scanned — try submitting it
    if resp is None:
        # Check if it was a 404 (not found) vs network error
        # Either way, result is inconclusive
        return None
    return None


def check_ipqualityscore(url: str) -> Optional[dict]:
    """Check URL via IP Quality Score. Requires API key."""
    api_key = get_secret("IPQUALITYSCORE_KEY")
    if not api_key:
        return None
    if not _rate_ok("ipqualityscore", 1.0):
        return None

    encoded_url = urllib.parse.quote(url, safe="")
    endpoint = f"https://www.ipqualityscore.com/api/json/url/{api_key}/{encoded_url}"
    resp = _get_json(endpoint)
    if resp and resp.get("success", False):
        return {
            "unsafe": resp.get("unsafe", False),
            "phishing": resp.get("phishing", False),
            "malware": resp.get("malware", False),
            "suspicious": resp.get("suspicious", False),
            "risk_score": resp.get("risk_score", 0),
            "domain_age_days": resp.get("domain_age", {}).get("human", ""),
        }
    return None


# ---------------------------------------------------------------------------
# Aggregation — threat type mapping
# ---------------------------------------------------------------------------
_GOOGLE_SB_TYPE_MAP = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted",
    "POTENTIALLY_HARMFUL_APPLICATION": "malware",
}


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname or parsed.netloc or url


# ---------------------------------------------------------------------------
# Master check function
# ---------------------------------------------------------------------------
def check_url(url: str) -> ThreatFeedResult:
    """Check a URL against all available free threat feeds.

    Always checks URLhaus and PhishTank (free, no key).
    Checks Google Safe Browsing, VirusTotal, IP Quality Score if keys available.
    Results are cached for 1 hour.

    Returns aggregated ThreatFeedResult.
    """
    # Check cache first
    cached = _cache_get(url)
    if cached is not None:
        return cached

    feed_results: dict = {}
    feeds_checked: list[str] = []
    threat_types: list[str] = []
    is_threat = False

    domain = _extract_domain(url)

    # --- Free feeds (always run) ---

    # URLhaus URL lookup
    uh_url = check_urlhaus_url(url)
    if uh_url is not None:
        feeds_checked.append("urlhaus_url")
        feed_results["urlhaus_url"] = uh_url
        if uh_url.get("listed"):
            is_threat = True
            threat = uh_url.get("threat", "malware")
            threat_types.append(threat if threat else "malware")

    # URLhaus host lookup
    if domain:
        uh_host = check_urlhaus_host(domain)
        if uh_host is not None:
            feeds_checked.append("urlhaus_host")
            feed_results["urlhaus_host"] = uh_host
            if uh_host.get("listed") and uh_host.get("urls_online", 0) > 0:
                is_threat = True
                if "malware" not in threat_types:
                    threat_types.append("malware")

    # PhishTank
    pt = check_phishtank(url)
    if pt is not None:
        feeds_checked.append("phishtank")
        feed_results["phishtank"] = pt
        if pt.get("is_phish"):
            is_threat = True
            if "phishing" not in threat_types:
                threat_types.append("phishing")

    # --- Keyed feeds (run if key available) ---

    # Google Safe Browsing
    gsb = check_google_safe_browsing(url)
    if gsb is not None:
        feeds_checked.append("google_safe_browsing")
        feed_results["google_safe_browsing"] = gsb
        if gsb.get("is_threat"):
            is_threat = True
            for gt in gsb.get("threat_types", []):
                mapped = _GOOGLE_SB_TYPE_MAP.get(gt, gt.lower())
                if mapped not in threat_types:
                    threat_types.append(mapped)

    # VirusTotal
    vt = check_virustotal(url)
    if vt is not None:
        feeds_checked.append("virustotal")
        feed_results["virustotal"] = vt
        if vt.get("score", 0) > 0.1:
            is_threat = True
            if "malware" not in threat_types:
                threat_types.append("malware")

    # IP Quality Score
    ipqs = check_ipqualityscore(url)
    if ipqs is not None:
        feeds_checked.append("ipqualityscore")
        feed_results["ipqualityscore"] = ipqs
        if ipqs.get("unsafe") or ipqs.get("phishing") or ipqs.get("malware"):
            is_threat = True
            if ipqs.get("phishing") and "phishing" not in threat_types:
                threat_types.append("phishing")
            if ipqs.get("malware") and "malware" not in threat_types:
                threat_types.append("malware")
            if ipqs.get("unsafe") and "scam" not in threat_types:
                threat_types.append("scam")

    # --- Confidence calculation ---
    # Base: proportion of feeds that flagged it as threat
    feeds_with_opinion = len(feeds_checked)
    feeds_flagged = sum(1 for name in feeds_checked if _feed_flagged(name, feed_results))
    if feeds_with_opinion == 0:
        confidence = 0.0
    elif is_threat:
        # At least one feed flagged — scale by how many agree
        confidence = min(0.5 + (feeds_flagged / max(feeds_with_opinion, 1)) * 0.5, 1.0)
    else:
        confidence = 0.0

    # Deduplicate threat_types
    threat_types = list(dict.fromkeys(threat_types))

    result = ThreatFeedResult(
        is_threat=is_threat,
        threat_types=threat_types,
        confidence=round(confidence, 3),
        feed_results=feed_results,
        feeds_checked=feeds_checked,
        cached=False,
    )

    _cache_set(url, result)
    return result


def _feed_flagged(name: str, feed_results: dict) -> bool:
    """Determine if a specific feed flagged the URL as a threat."""
    r = feed_results.get(name)
    if r is None:
        return False
    if name in ("urlhaus_url", "urlhaus_host"):
        return r.get("listed", False)
    if name == "phishtank":
        return r.get("is_phish", False)
    if name == "google_safe_browsing":
        return r.get("is_threat", False)
    if name == "virustotal":
        return r.get("score", 0) > 0.1
    if name == "ipqualityscore":
        return r.get("unsafe", False) or r.get("phishing", False) or r.get("malware", False)
    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    target = sys.argv[1] if len(sys.argv) > 1 else "http://malware-test.example.com"
    print(f"Checking: {target}")
    result = check_url(target)
    print(json.dumps(asdict(result), indent=2, default=str))

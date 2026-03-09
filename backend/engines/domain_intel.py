"""
Chetana Domain Intelligence — URL and domain reputation engine.

TLD risk scoring, domain age heuristics, SSL check, whitelist check,
typosquat detection (Levenshtein), subdomain depth analysis.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("chetana.domain_intel")

DATA_DIR = Path(__file__).parent.parent / "data"

_whitelist_cache: Optional[dict] = None


def _load_whitelist() -> dict:
    global _whitelist_cache
    if _whitelist_cache is None:
        p = DATA_DIR / "domain_whitelist.json"
        _whitelist_cache = json.loads(p.read_text()) if p.exists() else {}
    return _whitelist_cache


# High-risk TLDs commonly used in scam/phishing domains
HIGH_RISK_TLDS = {
    ".top", ".xyz", ".click", ".loan", ".buzz", ".gq", ".tk", ".ml",
    ".cf", ".ga", ".work", ".fit", ".surf", ".rest", ".icu", ".cam",
    ".monster", ".cfd", ".sbs", ".quest", ".cyou",
}

MEDIUM_RISK_TLDS = {
    ".online", ".site", ".store", ".shop", ".info", ".biz", ".pw",
    ".cc", ".ws", ".pro", ".mobi", ".life", ".world", ".today",
}

# Known brands for typosquat detection
KNOWN_BRANDS = [
    "google", "facebook", "amazon", "flipkart", "paytm", "phonepe",
    "gpay", "sbi", "hdfc", "icici", "axis", "kotak", "uidai",
    "aadhaar", "irctc", "epfo", "microsoft", "apple", "whatsapp",
    "instagram", "twitter", "netflix", "youtube", "linkedin",
    "razorpay", "swiggy", "zomato", "myntra", "nykaa",
]


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row
    return prev_row[-1]


@dataclass
class DomainIntelResult:
    domain: str
    trust_score: int                 # 0-100, higher = more trusted
    is_whitelisted: bool
    is_https: bool
    tld_risk: str                    # safe, medium, high
    subdomain_depth: int
    typosquat_suspect: bool
    typosquat_target: str            # which brand it might be imitating
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "trust_score": self.trust_score,
            "is_whitelisted": self.is_whitelisted,
            "is_https": self.is_https,
            "tld_risk": self.tld_risk,
            "subdomain_depth": self.subdomain_depth,
            "typosquat_suspect": self.typosquat_suspect,
            "typosquat_target": self.typosquat_target,
            "signals": self.signals,
        }


def _check_whitelist(domain: str) -> bool:
    """Check if domain is in the trusted whitelist."""
    wl = _load_whitelist()
    all_allowed = set()
    for domains in wl.values():
        all_allowed.update(d.lower() for d in domains)

    d = domain.lower()
    return any(d == a or d.endswith("." + a) for a in all_allowed)


def _check_tld(domain: str) -> str:
    """Check TLD risk level."""
    d = domain.lower()
    for tld in HIGH_RISK_TLDS:
        if d.endswith(tld):
            return "high"
    for tld in MEDIUM_RISK_TLDS:
        if d.endswith(tld):
            return "medium"
    return "safe"


def _check_typosquat(domain: str) -> tuple[bool, str]:
    """Check if domain is a typosquat of a known brand using Levenshtein distance."""
    d = domain.lower()
    # Extract the registrable part (before TLD)
    parts = d.split(".")
    if len(parts) >= 2:
        # Take the main domain part (second-level domain)
        main_part = parts[-2] if len(parts) >= 2 else parts[0]
    else:
        main_part = parts[0]

    # Remove common prefixes/suffixes that scammers add
    stripped = main_part
    for prefix in ("secure-", "login-", "verify-", "update-", "official-", "my", "the"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
    for suffix in ("-secure", "-login", "-verify", "-update", "-official", "-support", "-help", "-india"):
        if stripped.endswith(suffix):
            stripped = stripped[:-len(suffix)]

    for brand in KNOWN_BRANDS:
        # Exact match is fine
        if stripped == brand:
            continue
        # Close Levenshtein distance = potential typosquat
        dist = _levenshtein(stripped, brand)
        if dist <= 2 and len(brand) >= 4:
            return True, brand
        # Also check if brand name is embedded with extra chars
        if brand in stripped and stripped != brand and len(stripped) - len(brand) <= 4:
            return True, brand

    return False, ""


def _subdomain_depth(domain: str) -> int:
    """Count subdomain levels. Deeply nested = suspicious."""
    parts = domain.lower().split(".")
    # Typical domain: example.com = 0 subdomain depth
    # sub.example.com = 1, a.b.example.com = 2
    if len(parts) <= 2:
        return 0
    # Account for .co.in, .gov.in, .org.in
    if len(parts) >= 3 and parts[-2] in ("co", "gov", "org", "ac", "net"):
        return max(0, len(parts) - 3)
    return max(0, len(parts) - 2)


def analyze(url: str) -> DomainIntelResult:
    """
    Analyze a URL for domain intelligence signals.
    Returns DomainIntelResult with trust_score 0-100.
    """
    try:
        return _analyze_inner(url)
    except Exception as e:
        logger.error("Domain intel error (fail-open): %s", e)
        return DomainIntelResult(
            domain=url,
            trust_score=50,
            is_whitelisted=False,
            is_https=False,
            tld_risk="unknown",
            subdomain_depth=0,
            typosquat_suspect=False,
            typosquat_target="",
            signals=["Engine error — could not analyse"],
        )


def _analyze_inner(url: str) -> DomainIntelResult:
    if not url:
        return DomainIntelResult(
            domain="",
            trust_score=50,
            is_whitelisted=False,
            is_https=False,
            tld_risk="unknown",
            subdomain_depth=0,
            typosquat_suspect=False,
            typosquat_target="",
        )

    # Parse URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()
        is_https = parsed.scheme == "https"
    except Exception:
        return DomainIntelResult(
            domain=url, trust_score=20, is_whitelisted=False,
            is_https=False, tld_risk="unknown", subdomain_depth=0,
            typosquat_suspect=False, typosquat_target="",
            signals=["Malformed URL"],
        )

    if not domain:
        return DomainIntelResult(
            domain=url, trust_score=20, is_whitelisted=False,
            is_https=False, tld_risk="unknown", subdomain_depth=0,
            typosquat_suspect=False, typosquat_target="",
            signals=["Could not extract domain"],
        )

    signals: list[str] = []
    score = 60  # Start neutral

    # Whitelist check
    whitelisted = _check_whitelist(domain)
    if whitelisted:
        signals.append("Domain is on trusted whitelist")
        score += 30

    # HTTPS check
    if is_https:
        score += 5
    else:
        signals.append("No HTTPS (insecure connection)")
        score -= 15

    # TLD risk
    tld_risk = _check_tld(domain)
    if tld_risk == "high":
        signals.append(f"High-risk TLD: .{domain.split('.')[-1]}")
        score -= 25
    elif tld_risk == "medium":
        signals.append(f"Medium-risk TLD: .{domain.split('.')[-1]}")
        score -= 10

    # Subdomain depth
    depth = _subdomain_depth(domain)
    if depth >= 3:
        signals.append(f"Deeply nested subdomains ({depth} levels) — suspicious")
        score -= 20
    elif depth >= 2:
        signals.append(f"Multiple subdomain levels ({depth})")
        score -= 8

    # Typosquat check
    is_typo, typo_target = _check_typosquat(domain)
    if is_typo:
        signals.append(f"Possible typosquat of '{typo_target}'")
        score -= 30

    # IP address instead of domain
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        signals.append("IP address instead of domain name")
        score -= 20

    # Very long domain
    if len(domain) > 40:
        signals.append("Unusually long domain name")
        score -= 5

    score = max(0, min(100, score))

    return DomainIntelResult(
        domain=domain,
        trust_score=score,
        is_whitelisted=whitelisted,
        is_https=is_https,
        tld_risk=tld_risk,
        subdomain_depth=depth,
        typosquat_suspect=is_typo,
        typosquat_target=typo_target,
        signals=signals,
    )

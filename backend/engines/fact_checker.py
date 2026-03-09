"""
Chetana Fact Checker — News and claim credibility engine.

Source credibility scoring, claim extraction, manipulation language
detection, news freshness heuristics. Deterministic, no LLM needed.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("chetana.fact_checker")

DATA_DIR = Path(__file__).parent.parent / "data"

_credibility_cache: Optional[dict] = None


def _load_credibility() -> dict:
    global _credibility_cache
    if _credibility_cache is None:
        p = DATA_DIR / "source_credibility.json"
        _credibility_cache = json.loads(p.read_text()) if p.exists() else {}
    return _credibility_cache


def reload_credibility():
    global _credibility_cache
    _credibility_cache = None


# --- Manipulation patterns ---

CLICKBAIT_PATTERNS = [
    re.compile(r"\byou\s+won'?t\s+believe\b", re.I),
    re.compile(r"\bshocking\s+(?:truth|revelation|news)\b", re.I),
    re.compile(r"\bthis\s+(?:one\s+)?(?:trick|hack|secret)\b", re.I),
    re.compile(r"\bwhat\s+happens\s+next\s+will\b", re.I),
    re.compile(r"\bdoctors?\s+(?:hate|don'?t\s+want)\b", re.I),
    re.compile(r"\b(?:number|reason)\s+\d+\s+will\s+(?:shock|surprise|blow)\b", re.I),
    re.compile(r"\bgoing\s+viral\b", re.I),
    re.compile(r"\bbefore\s+it'?s?\s+(?:too\s+late|deleted|removed)\b", re.I),
    re.compile(r"\b(?:exposed|busted|revealed|uncovered)\b", re.I),
    re.compile(r"\bbreaking\s*:?\s", re.I),
]

EMOTIONAL_MANIPULATION = [
    re.compile(r"\b(?:outrage|outraged|outrageous)\b", re.I),
    re.compile(r"\b(?:disgusting|appalling|horrifying|terrifying)\b", re.I),
    re.compile(r"\b(?:destroy|destroyed|destroying)\s+(?:our|the|your)\b", re.I),
    re.compile(r"\b(?:wake\s+up|open\s+your\s+eyes)\b", re.I),
    re.compile(r"\b(?:they\s+don'?t\s+want\s+you\s+to\s+know)\b", re.I),
    re.compile(r"\b(?:mainstream\s+media\s+(?:won'?t|refuses?\s+to))\b", re.I),
    re.compile(r"\b(?:big\s+pharma|deep\s+state|global\s+elite)\b", re.I),
    re.compile(r"\b(?:cover[\s-]?up|conspiracy)\b", re.I),
    re.compile(r"\b(?:banned|censored|suppressed)\s+(?:information|truth|video)\b", re.I),
]

FALSE_URGENCY = [
    re.compile(r"\b(?:share\s+(?:before|now|immediately|this))\b", re.I),
    re.compile(r"\b(?:forward\s+(?:to|this|immediately))\b", re.I),
    re.compile(r"\b(?:spread\s+the\s+word|tell\s+everyone)\b", re.I),
    re.compile(r"\b(?:this\s+is\s+(?:very\s+)?urgent)\b", re.I),
    re.compile(r"\b(?:time\s+is\s+running\s+out)\b", re.I),
]

ABSOLUTE_CLAIMS = [
    re.compile(r"\b(?:always|never|every\s+single|100\s*%|all\s+of\s+them)\b", re.I),
    re.compile(r"\b(?:proven\s+(?:fact|beyond|conclusively))\b", re.I),
    re.compile(r"\b(?:no\s+one\s+(?:can|will|has))\b", re.I),
    re.compile(r"\b(?:scientifically\s+(?:proven|impossible))\b", re.I),
]

# Claim extraction patterns
STAT_CLAIM_RE = re.compile(
    r"(?:\d+(?:\.\d+)?(?:\s*%|\s+(?:percent|crore|lakh|million|billion|thousand|hundred)))",
    re.I,
)
QUOTE_RE = re.compile(r'"([^"]{10,200})"')
ATTRIBUTION_RE = re.compile(
    r"(?:according\s+to|said|stated|reported\s+by|as\s+per|sources?\s+(?:say|said|told))\s+(.{5,80})",
    re.I,
)
DATE_RE = re.compile(
    r"\b(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2}|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})\b",
    re.I,
)


@dataclass
class FactCheckResult:
    credibility_score: int           # 0-100, higher = more credible
    source_tier: str                 # trusted, caution, unreliable, unknown
    source_category: str             # e.g. "news_tier1", "social", "unknown"
    claim_count: int
    verified_claims: int             # claims with attributions/sources
    unverified_claims: int           # claims without backing
    manipulation_signals: list[str] = field(default_factory=list)
    claims_found: list[str] = field(default_factory=list)
    dates_found: list[str] = field(default_factory=list)
    attributions_found: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "credibility_score": self.credibility_score,
            "source_tier": self.source_tier,
            "source_category": self.source_category,
            "claim_count": self.claim_count,
            "verified_claims": self.verified_claims,
            "unverified_claims": self.unverified_claims,
            "manipulation_signals": self.manipulation_signals,
            "claims_found": self.claims_found,
            "dates_found": self.dates_found,
            "attributions_found": self.attributions_found,
        }


def _domain_from_url(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        # Strip www.
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def _score_source(domain: str) -> tuple[str, str, int]:
    """Score a source domain. Returns (tier, category, score_adjustment)."""
    cred = _load_credibility()

    for category, domains in cred.get("trusted", {}).items():
        if domain in domains or any(domain.endswith("." + d) for d in domains):
            return "trusted", category, 30

    for category, domains in cred.get("caution", {}).items():
        if domain in domains or any(domain.endswith("." + d) for d in domains):
            return "caution", category, 0

    for category, domains in cred.get("unreliable", {}).items():
        if domain in domains or any(domain.endswith("." + d) for d in domains):
            return "unreliable", category, -30

    return "unknown", "unknown", -10


def _detect_manipulation(text: str) -> list[str]:
    """Detect manipulation language patterns."""
    signals = []
    t = text or ""

    clickbait_hits = sum(1 for p in CLICKBAIT_PATTERNS if p.search(t))
    if clickbait_hits >= 2:
        signals.append(f"Clickbait language ({clickbait_hits} patterns)")
    elif clickbait_hits == 1:
        signals.append("Mild clickbait language")

    emotional_hits = sum(1 for p in EMOTIONAL_MANIPULATION if p.search(t))
    if emotional_hits >= 2:
        signals.append(f"Emotional manipulation ({emotional_hits} patterns)")
    elif emotional_hits == 1:
        signals.append("Emotional language detected")

    urgency_hits = sum(1 for p in FALSE_URGENCY if p.search(t))
    if urgency_hits >= 1:
        signals.append(f"False urgency / pressure to share ({urgency_hits} patterns)")

    absolute_hits = sum(1 for p in ABSOLUTE_CLAIMS if p.search(t))
    if absolute_hits >= 2:
        signals.append(f"Absolute/unqualified claims ({absolute_hits} patterns)")
    elif absolute_hits == 1:
        signals.append("Contains absolute claim")

    # All-caps check (more than 20% caps in a long text is a signal)
    if len(t) > 100:
        caps_ratio = sum(1 for c in t if c.isupper()) / max(len(t), 1)
        if caps_ratio > 0.3:
            signals.append("Excessive capitalisation (shouting)")
        elif caps_ratio > 0.2:
            signals.append("High capitalisation")

    # Exclamation density
    excl_count = t.count("!")
    if excl_count >= 5:
        signals.append(f"Excessive exclamation marks ({excl_count})")
    elif excl_count >= 3:
        signals.append("Multiple exclamation marks")

    return signals


def _extract_claims(text: str) -> tuple[list[str], list[str], list[str]]:
    """Extract statistical claims, quotes, and attributions."""
    claims = []
    attributions = []
    dates = []

    # Statistical claims
    for m in STAT_CLAIM_RE.finditer(text):
        start = max(0, m.start() - 40)
        end = min(len(text), m.end() + 40)
        context = text[start:end].strip()
        claims.append(context)

    # Quoted claims
    for m in QUOTE_RE.finditer(text):
        claims.append(m.group(0))

    # Attributions
    for m in ATTRIBUTION_RE.finditer(text):
        attributions.append(m.group(0).strip())

    # Dates
    for m in DATE_RE.finditer(text):
        dates.append(m.group(0))

    return claims[:20], attributions[:10], dates[:10]


def check(text: str, url: str = "") -> FactCheckResult:
    """
    Fact-check a piece of text (article, claim, news snippet).
    Optionally provide the source URL for credibility scoring.
    Returns FactCheckResult with credibility_score 0-100.
    """
    try:
        return _check_inner(text, url)
    except Exception as e:
        logger.error("Fact check error (fail-open): %s", e)
        return FactCheckResult(
            credibility_score=50,
            source_tier="unknown",
            source_category="unknown",
            claim_count=0,
            verified_claims=0,
            unverified_claims=0,
            manipulation_signals=["Engine error — could not analyse"],
        )


def _check_inner(text: str, url: str) -> FactCheckResult:
    if not (text or "").strip():
        return FactCheckResult(
            credibility_score=50,
            source_tier="unknown",
            source_category="unknown",
            claim_count=0,
            verified_claims=0,
            unverified_claims=0,
        )

    # Source credibility
    domain = _domain_from_url(url) if url else ""
    source_tier, source_category, source_adj = _score_source(domain) if domain else ("unknown", "unknown", -5)

    # Manipulation detection
    manipulation_signals = _detect_manipulation(text)

    # Claim extraction
    claims, attributions, dates = _extract_claims(text)
    claim_count = len(claims)
    verified = min(len(attributions), claim_count)
    unverified = max(claim_count - verified, 0)

    # Score calculation: start at 60 (neutral), adjust
    score = 60

    # Source adjustment
    score += source_adj

    # Manipulation penalty
    manipulation_penalty = len(manipulation_signals) * 8
    score -= manipulation_penalty

    # Attribution bonus: verified claims boost credibility
    if claim_count > 0:
        verification_ratio = verified / max(claim_count, 1)
        score += int(verification_ratio * 15)
        # Penalty for many unverified claims
        if unverified > 3:
            score -= 10

    # Date presence is a positive signal (timely, specific)
    if dates:
        score += 5

    # Length heuristic: very short text with strong claims is suspicious
    word_count = len(text.split())
    if word_count < 50 and claim_count >= 2:
        score -= 10
        manipulation_signals.append("Short text with multiple claims")

    # Clamp
    score = max(0, min(100, score))

    return FactCheckResult(
        credibility_score=score,
        source_tier=source_tier,
        source_category=source_category,
        claim_count=claim_count,
        verified_claims=verified,
        unverified_claims=unverified,
        manipulation_signals=manipulation_signals,
        claims_found=claims[:10],
        dates_found=dates,
        attributions_found=attributions,
    )

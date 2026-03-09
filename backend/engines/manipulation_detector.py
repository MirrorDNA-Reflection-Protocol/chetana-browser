"""
Chetana Manipulation Detector — Dark pattern and psychological manipulation engine.

Detects urgency tricks, social proof manipulation, authority spoofing,
fear tactics, hidden costs, cookie consent dark patterns, fake reviews.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger("chetana.manipulation_detector")


@dataclass
class ManipulationResult:
    manipulation_score: int          # 0-100, higher = more manipulative
    pattern_count: int
    patterns: list[dict] = field(default_factory=list)
    # Each pattern: {"category": str, "description": str, "severity": str, "matched": str}

    def to_dict(self) -> dict:
        return {
            "manipulation_score": self.manipulation_score,
            "pattern_count": self.pattern_count,
            "patterns": self.patterns,
        }


# --- Pattern definitions ---
# Each entry: (compiled_regex, category, description, severity, weight)

_PATTERNS: list[tuple] = []


def _p(pattern: str, category: str, description: str, severity: str, weight: int):
    """Register a manipulation pattern."""
    _PATTERNS.append((
        re.compile(pattern, re.I),
        category,
        description,
        severity,
        weight,
    ))


# Urgency tricks
_p(r"\blimited\s+time\s+(?:only|offer|deal)\b", "urgency", "Limited time pressure", "medium", 10)
_p(r"\bact\s+now\b", "urgency", "Act now pressure", "medium", 8)
_p(r"\bhurry\b", "urgency", "Hurry pressure", "low", 5)
_p(r"\b(?:only|just)\s+\d+\s+(?:left|remaining|available)\b", "urgency", "Scarcity claim (limited quantity)", "medium", 12)
_p(r"\b(?:offer|deal|price)\s+(?:expires?|ends?|valid)\s+(?:in|at|on|today)\b", "urgency", "Expiring offer", "medium", 10)
_p(r"\bcountdown\b", "urgency", "Countdown timer reference", "medium", 10)
_p(r"\b(?:don'?t|do\s+not)\s+miss\s+(?:out|this)\b", "urgency", "Fear of missing out", "medium", 8)
_p(r"\blast\s+chance\b", "urgency", "Last chance pressure", "medium", 10)
_p(r"\b(?:ends?\s+)?today\s+only\b", "urgency", "Today-only pressure", "medium", 10)
_p(r"\bwhile\s+(?:stocks?|supplies?)\s+last\b", "urgency", "Stock scarcity pressure", "medium", 8)

# Social proof manipulation
_p(r"\b\d+(?:\s*[,k+]?\s*)?(?:people|users?|customers?|buyers?)\s+(?:just\s+)?(?:bought|ordered|signed\s+up|joined|purchased)\b",
   "social_proof", "Social proof claim (X people bought this)", "medium", 12)
_p(r"\bsomeone\s+(?:just\s+)?(?:bought|ordered|purchased)\b", "social_proof", "Live purchase notification", "medium", 10)
_p(r"\btrending\s+now\b", "social_proof", "Trending claim", "low", 5)
_p(r"\b(?:best|top)\s+(?:seller|selling|rated)\b", "social_proof", "Best seller claim", "low", 3)
_p(r"\b(?:most\s+popular|everyone'?s?\s+(?:buying|choosing|favourite))\b",
   "social_proof", "Popularity manipulation", "medium", 8)
_p(r"\b\d+\s+(?:reviews?|ratings?)\b", "social_proof", "Review count prominence", "low", 3)

# Authority spoofing
_p(r"\b(?:official\s+(?:notice|notification|warning|communication|letter))\b",
   "authority", "Official notice spoofing", "high", 15)
_p(r"\b(?:government|govt|ministry)\s+(?:approved|certified|endorsed)\b",
   "authority", "Government endorsement claim", "high", 15)
_p(r"\b(?:verified\s+by|approved\s+by|endorsed\s+by|recommended\s+by)\s+(?:rbi|sebi|govt|government)\b",
   "authority", "Regulatory body endorsement claim", "high", 18)
_p(r"\b(?:as\s+seen\s+on\s+(?:tv|news|bbc|ndtv|times))\b",
   "authority", "Media endorsement claim", "medium", 10)
_p(r"\b(?:doctor|expert|scientist)s?\s+(?:recommend|approve|endorse)\b",
   "authority", "Expert endorsement claim", "medium", 8)

# Fear tactics
_p(r"\b(?:your\s+(?:account|subscription|service|access))\s+(?:will\s+be|has\s+been)\s+(?:suspended|blocked|terminated|closed|deactivated)\b",
   "fear", "Account suspension threat", "high", 15)
_p(r"\b(?:you\s+(?:will|may)\s+(?:lose|miss|forfeit))\b",
   "fear", "Loss aversion trigger", "medium", 10)
_p(r"\b(?:failure\s+to\s+(?:act|respond|comply|verify))\s+(?:will|may)\s+result\b",
   "fear", "Consequence threat", "high", 12)
_p(r"\b(?:legal\s+(?:action|notice|proceedings))\b",
   "fear", "Legal action threat", "high", 15)
_p(r"\b(?:your\s+(?:data|information|identity)\s+(?:is|has\s+been)\s+(?:compromised|leaked|stolen|at\s+risk))\b",
   "fear", "Data compromise scare", "high", 15)
_p(r"\b(?:warning|alert|attention|caution)\s*[!:]\b",
   "fear", "Alert/warning banner", "low", 5)

# Hidden costs / fine print
_p(r"\b(?:free\s+trial)\b.*\b(?:cancel|charge|bill|renew)\b",
   "hidden_cost", "Free trial with auto-charge", "medium", 10)
_p(r"\b(?:no\s+(?:hidden|extra|additional)\s+(?:fees?|charges?|costs?))\b",
   "hidden_cost", "No hidden fees claim (often deceptive)", "low", 5)
_p(r"\b(?:processing|handling|convenience|service)\s+(?:fee|charge)\b",
   "hidden_cost", "Additional fee mentioned", "medium", 8)
_p(r"\b(?:terms?\s+(?:and|&)\s+conditions?\s+apply)\b",
   "hidden_cost", "Terms and conditions caveat", "low", 3)
_p(r"\b(?:auto[\s-]?renew|recurring\s+(?:charge|payment|billing))\b",
   "hidden_cost", "Auto-renewal / recurring charge", "medium", 10)

# Cookie consent dark patterns
_p(r"\b(?:accept\s+all\s+cookies?)\b", "dark_pattern", "Accept all cookies prominence", "low", 3)
_p(r"\b(?:by\s+(?:continuing|browsing|using)\s+(?:this|our)\s+(?:site|website).*you\s+(?:agree|consent))\b",
   "dark_pattern", "Implied consent by browsing", "medium", 8)
_p(r"\b(?:we\s+(?:use|collect)\s+(?:your\s+)?(?:data|cookies?|information))\b",
   "dark_pattern", "Data collection notice", "low", 3)

# Fake review indicators
_p(r"\b(?:i\s+(?:was|am)\s+(?:skeptical|doubtful)\s+(?:at\s+first|but)\b)",
   "fake_review", "Skeptic-then-convert pattern (common in fake reviews)", "medium", 8)
_p(r"\b(?:changed?\s+my\s+life|life[\s-]?changing|game[\s-]?changer)\b",
   "fake_review", "Hyperbolic review language", "low", 5)
_p(r"\b(?:5\s*(?:out\s+of\s+5|/5)\s+stars?|five\s+stars?)\b",
   "fake_review", "Perfect rating claim", "low", 3)
_p(r"\b(?:must[\s-]?(?:have|buy)|highly\s+recommend)\b",
   "fake_review", "Strong recommendation language", "low", 3)

# Subscription traps
_p(r"\b(?:(?:un)?subscribe|opt[\s-]?out)\b.*\b(?:difficult|hard|impossible|hidden)\b",
   "subscription_trap", "Difficult unsubscribe reference", "medium", 10)
_p(r"\b(?:free\s+(?:for|trial)\s+\d+\s+(?:days?|months?))\b",
   "subscription_trap", "Time-limited free offer", "low", 5)


def detect(text: str) -> ManipulationResult:
    """
    Detect manipulation and dark patterns in page/text content.
    Returns ManipulationResult with manipulation_score 0-100.
    """
    try:
        return _detect_inner(text)
    except Exception as e:
        logger.error("Manipulation detection error (fail-open): %s", e)
        return ManipulationResult(
            manipulation_score=0,
            pattern_count=0,
            patterns=[{"category": "error", "description": "Engine error — fail-open",
                        "severity": "low", "matched": ""}],
        )


def _detect_inner(text: str) -> ManipulationResult:
    if not (text or "").strip():
        return ManipulationResult(manipulation_score=0, pattern_count=0)

    patterns_found: list[dict] = []
    total_weight = 0

    for regex, category, description, severity, weight in _PATTERNS:
        m = regex.search(text)
        if m:
            patterns_found.append({
                "category": category,
                "description": description,
                "severity": severity,
                "matched": m.group(0)[:100],
            })
            total_weight += weight

    # Category concentration bonus: hitting multiple categories is worse
    categories_hit = {p["category"] for p in patterns_found}
    if len(categories_hit) >= 4:
        total_weight += 15
    elif len(categories_hit) >= 3:
        total_weight += 10
    elif len(categories_hit) >= 2:
        total_weight += 5

    # High-severity bonus
    high_severity_count = sum(1 for p in patterns_found if p["severity"] == "high")
    total_weight += high_severity_count * 5

    score = min(100, total_weight)

    return ManipulationResult(
        manipulation_score=score,
        pattern_count=len(patterns_found),
        patterns=patterns_found,
    )

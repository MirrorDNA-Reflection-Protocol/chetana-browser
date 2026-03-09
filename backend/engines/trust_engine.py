"""
Chetana Trust Engine — Master trust scorer.

Combines signals from all sub-engines into a unified 0-100 trust score
(NOT risk score — trust score, where 100 = fully trusted).

Aggregates: scam detection + fact checking + domain intelligence +
manipulation detection + form analysis. Fail-open on all sub-engines.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from . import scam_detector
from . import fact_checker
from . import domain_intel
from . import manipulation_detector
from . import security_gate
from .scamgate import ScamGate

logger = logging.getLogger("chetana.trust_engine")

# Singleton ScamGate instance (L0 pattern + L1 local LLM + L2 cloud)
_scamgate: ScamGate | None = None


def _get_scamgate() -> ScamGate:
    global _scamgate
    if _scamgate is None:
        _scamgate = ScamGate(auto_escalate=True, max_tier=2)
    return _scamgate


@dataclass
class TrustVerdict:
    trust_score: int              # 0-100, higher = more trusted
    risk_level: str               # SAFE, CAUTION, WARNING, DANGER
    signals: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    fact_check: Optional[dict] = None
    scam_check: Optional[dict] = None
    domain_intel: Optional[dict] = None
    manipulation_check: Optional[dict] = None
    security_gate: Optional[dict] = None
    processing_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "signals": self.signals,
            "recommendations": self.recommendations,
            "fact_check": self.fact_check,
            "scam_check": self.scam_check,
            "domain_intel": self.domain_intel,
            "manipulation_check": self.manipulation_check,
            "security_gate": self.security_gate,
            "processing_ms": self.processing_ms,
        }


def _safe_call(fn, *args, **kwargs):
    """Call a function, return None on any error (fail-open)."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.error("Sub-engine error (fail-open) in %s: %s", fn.__name__, e)
        return None


def analyze_page(
    url: str = "",
    text: str = "",
    title: str = "",
    meta_description: str = "",
    form_fields: Optional[list[str]] = None,
) -> TrustVerdict:
    """
    Full page analysis. Combines all sub-engines into unified trust score.

    Args:
        url: The page URL
        text: Visible page text / content
        title: Page title
        meta_description: Meta description tag content
        form_fields: List of form field names/labels found on the page

    Returns:
        TrustVerdict with aggregated trust_score 0-100
    """
    t0 = time.perf_counter()

    # Combine all text for analysis
    full_text = "\n".join(filter(None, [title, meta_description, text]))

    # --- Run all sub-engines ---

    # 1. ScamGate (primary) — 3-tier scam/threat detection
    gate = _get_scamgate()
    scamgate_verdict = _safe_call(gate.scan, full_text, url)

    # 1b. Legacy scam detector (deterministic fallback)
    scam_result = _safe_call(scam_detector.detect, full_text)
    scam_dict = scam_result.to_dict() if scam_result else None
    if scamgate_verdict:
        # Merge ScamGate verdict into scam_dict
        sg = scamgate_verdict.to_dict()
        scam_dict = scam_dict or {}
        scam_dict["scamgate"] = {
            "trust_score": sg["trust_score"],
            "risk_level": sg["risk_level"],
            "verdict": sg["verdict"],
            "confidence": sg["confidence"],
            "signals": sg["signals"],
            "categories": sg["categories"],
            "tiers_used": sg["tiers_used"],
            "processing_ms": sg["processing_ms"],
        }
        # Use ScamGate's risk score if higher (stronger signal)
        sg_risk = 100 - sg["trust_score"]
        if scam_result and sg_risk > scam_result.risk_score:
            scam_result = scam_detector.ScamResult(
                risk_level=sg["risk_level"].replace("DANGER", "CRITICAL").replace("SAFE", "SAFE"),
                risk_score=sg_risk,
                signals=sg["signals"][:8],
                advice=sg.get("recommendations", [])[:5],
                categories_hit=sg["categories"][:10],
            )

    # 2. Fact checking (if text is substantial)
    fact_result = None
    if len(full_text) > 100:
        fact_result = _safe_call(fact_checker.check, full_text, url)
    fact_dict = fact_result.to_dict() if fact_result else None

    # 3. Domain intelligence (if URL provided)
    domain_result = None
    if url:
        domain_result = _safe_call(domain_intel.analyze, url)
    domain_dict = domain_result.to_dict() if domain_result else None

    # 4. Manipulation detection
    manip_result = _safe_call(manipulation_detector.detect, full_text)
    manip_dict = manip_result.to_dict() if manip_result else None

    # 5. Security gate (input check on the text)
    gate_result = _safe_call(security_gate.input_gate, full_text)
    gate_dict = gate_result.to_dict() if gate_result else None

    # --- Aggregate trust score ---
    trust_score = _aggregate_trust(
        scam_result=scam_result,
        fact_result=fact_result,
        domain_result=domain_result,
        manip_result=manip_result,
        form_fields=form_fields,
    )

    # --- Collect signals ---
    signals = _collect_signals(scam_result, fact_result, domain_result, manip_result, form_fields)

    # --- Risk level ---
    risk_level = _risk_level(trust_score)

    # --- Recommendations ---
    recommendations = _build_recommendations(
        trust_score, risk_level, scam_result, fact_result, domain_result, manip_result, form_fields,
    )

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return TrustVerdict(
        trust_score=trust_score,
        risk_level=risk_level,
        signals=signals,
        recommendations=recommendations,
        fact_check=fact_dict,
        scam_check=scam_dict,
        domain_intel=domain_dict,
        manipulation_check=manip_dict,
        security_gate=gate_dict,
        processing_ms=round(elapsed_ms, 1),
    )


def analyze_text(text: str) -> TrustVerdict:
    """Quick text-only analysis (no URL, no domain intel)."""
    return analyze_page(url="", text=text)


def analyze_url(url: str) -> TrustVerdict:
    """URL-only reputation check (domain intel + minimal text analysis)."""
    t0 = time.perf_counter()

    domain_result = _safe_call(domain_intel.analyze, url)
    domain_dict = domain_result.to_dict() if domain_result else None

    # Domain-only trust
    if domain_result:
        trust_score = domain_result.trust_score
    else:
        trust_score = 50

    risk_level = _risk_level(trust_score)
    signals = domain_result.signals if domain_result else []
    recommendations = []
    if trust_score < 40:
        recommendations.append("This domain has low trust indicators. Be cautious.")
    if domain_result and domain_result.typosquat_suspect:
        recommendations.append(f"This domain may be imitating '{domain_result.typosquat_target}'. Verify the URL carefully.")
    if domain_result and not domain_result.is_https:
        recommendations.append("This site does not use HTTPS. Avoid entering sensitive information.")

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return TrustVerdict(
        trust_score=trust_score,
        risk_level=risk_level,
        signals=signals,
        recommendations=recommendations,
        domain_intel=domain_dict,
        processing_ms=round(elapsed_ms, 1),
    )


def _aggregate_trust(
    scam_result: Optional[scam_detector.ScamResult],
    fact_result: Optional[fact_checker.FactCheckResult],
    domain_result: Optional[domain_intel.DomainIntelResult],
    manip_result: Optional[manipulation_detector.ManipulationResult],
    form_fields: Optional[list[str]],
) -> int:
    """
    Aggregate sub-engine results into a unified trust score (0-100).
    Trust = inverse of risk. We weight each engine and combine.
    """
    # Start with a neutral trust score
    trust = 70.0
    weights_applied = 0

    # Scam detection: invert risk_score to trust
    if scam_result:
        # risk_score 0 -> +30 trust, risk_score 100 -> -60 trust
        scam_adj = 30 - (scam_result.risk_score * 0.9)
        trust += scam_adj
        weights_applied += 1

    # Fact checking: credibility directly contributes
    if fact_result:
        # credibility_score is 0-100, adjust trust relative to neutral (60)
        fact_adj = (fact_result.credibility_score - 60) * 0.3
        trust += fact_adj
        weights_applied += 1

    # Domain intelligence: domain trust directly contributes
    if domain_result:
        # domain trust_score 0-100, adjust relative to neutral (60)
        domain_adj = (domain_result.trust_score - 60) * 0.4
        trust += domain_adj
        weights_applied += 1

    # Manipulation detection: reduces trust
    if manip_result:
        # manipulation_score 0-100 reduces trust
        manip_adj = -(manip_result.manipulation_score * 0.3)
        trust += manip_adj
        weights_applied += 1

    # Form analysis: sensitive form fields reduce trust
    if form_fields:
        sensitive_fields = _check_sensitive_forms(form_fields)
        if sensitive_fields:
            trust -= len(sensitive_fields) * 5
            # If page also has low domain trust, penalise harder
            if domain_result and domain_result.trust_score < 50:
                trust -= 15

    # Clamp
    return max(0, min(100, int(trust)))


def _check_sensitive_forms(form_fields: list[str]) -> list[str]:
    """Identify sensitive form fields that might be phishing."""
    sensitive_keywords = [
        "password", "passwd", "otp", "pin", "cvv", "card number",
        "credit card", "debit card", "aadhaar", "aadhar", "pan",
        "bank account", "ifsc", "routing", "ssn", "social security",
        "mother maiden", "secret question", "upi pin",
    ]
    sensitive = []
    for field_name in form_fields:
        f = field_name.lower()
        for kw in sensitive_keywords:
            if kw in f:
                sensitive.append(field_name)
                break
    return sensitive


def _risk_level(trust_score: int) -> str:
    """Map trust score to risk level."""
    if trust_score >= 75:
        return "SAFE"
    if trust_score >= 50:
        return "CAUTION"
    if trust_score >= 25:
        return "WARNING"
    return "DANGER"


def _collect_signals(
    scam_result: Optional[scam_detector.ScamResult],
    fact_result: Optional[fact_checker.FactCheckResult],
    domain_result: Optional[domain_intel.DomainIntelResult],
    manip_result: Optional[manipulation_detector.ManipulationResult],
    form_fields: Optional[list[str]],
) -> list[str]:
    """Collect human-readable signals from all engines."""
    signals = []

    if scam_result:
        for s in scam_result.signals[:5]:
            signals.append(f"[scam] {s}")

    if fact_result:
        for s in fact_result.manipulation_signals[:3]:
            signals.append(f"[credibility] {s}")
        if fact_result.source_tier == "unreliable":
            signals.append(f"[credibility] Source is marked as unreliable ({fact_result.source_category})")
        elif fact_result.source_tier == "trusted":
            signals.append(f"[credibility] Trusted source ({fact_result.source_category})")
        if fact_result.unverified_claims > 3:
            signals.append(f"[credibility] {fact_result.unverified_claims} unverified claims found")

    if domain_result:
        for s in domain_result.signals[:4]:
            signals.append(f"[domain] {s}")

    if manip_result and manip_result.patterns:
        categories = {p["category"] for p in manip_result.patterns}
        for cat in sorted(categories):
            count = sum(1 for p in manip_result.patterns if p["category"] == cat)
            signals.append(f"[manipulation] {cat.replace('_', ' ').title()} ({count} pattern{'s' if count > 1 else ''})")

    if form_fields:
        sensitive = _check_sensitive_forms(form_fields)
        if sensitive:
            signals.append(f"[form] Sensitive fields detected: {', '.join(sensitive[:5])}")

    return signals


def _build_recommendations(
    trust_score: int,
    risk_level: str,
    scam_result: Optional[scam_detector.ScamResult],
    fact_result: Optional[fact_checker.FactCheckResult],
    domain_result: Optional[domain_intel.DomainIntelResult],
    manip_result: Optional[manipulation_detector.ManipulationResult],
    form_fields: Optional[list[str]],
) -> list[str]:
    """Build actionable recommendations based on findings."""
    recs = []

    if risk_level == "DANGER":
        recs.append("This page shows multiple high-risk indicators. Avoid sharing any personal information.")

    if scam_result and scam_result.risk_level in ("CRITICAL", "HIGH_RISK"):
        recs.extend(scam_result.advice[:3])

    if domain_result:
        if domain_result.typosquat_suspect:
            recs.append(
                f"This domain may be imitating '{domain_result.typosquat_target}'. "
                f"Check the URL carefully before proceeding."
            )
        if not domain_result.is_https:
            recs.append("This site does not use HTTPS. Do not enter passwords or payment information.")
        if domain_result.tld_risk == "high":
            recs.append("This domain uses a high-risk TLD commonly associated with scam sites.")

    if fact_result:
        if fact_result.source_tier == "unreliable":
            recs.append("This source has been flagged as unreliable. Cross-check claims with trusted news sources.")
        if fact_result.unverified_claims > 3:
            recs.append("This article contains multiple unverified claims. Look for corroboration from other sources.")
        if fact_result.manipulation_signals:
            recs.append("Manipulation language detected. Read critically and verify key claims.")

    if manip_result and manip_result.manipulation_score >= 30:
        high_patterns = [p for p in manip_result.patterns if p["severity"] == "high"]
        if high_patterns:
            recs.append("This page uses high-severity manipulation tactics. Take time before acting.")
        elif manip_result.manipulation_score >= 50:
            recs.append("Significant dark pattern activity detected on this page.")

    if form_fields:
        sensitive = _check_sensitive_forms(form_fields)
        if sensitive and domain_result and not domain_result.is_whitelisted:
            recs.append(
                f"This page asks for sensitive information ({', '.join(sensitive[:3])}) "
                f"but is not on a trusted domain. Verify the URL."
            )

    if risk_level == "SAFE" and not recs:
        recs.append("No significant concerns detected. Standard browsing precautions apply.")

    # Deduplicate
    seen = set()
    unique_recs = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            unique_recs.append(r)

    return unique_recs[:8]

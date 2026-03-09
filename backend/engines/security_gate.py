"""
Chetana Security Gate — Comprehensive security layer.

Gates:
  1. Input gate — prompt injection detection
  2. Output gate — hallucination detection, high-risk claims
  3. URL gate — link safety check before navigation
  4. Download gate — file type / extension safety
  5. Form gate — sensitive field detection before submission
  6. Clipboard gate — paste content check

Fail-open design: if any gate errors, log and pass through.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("chetana.security_gate")


# ===================================================================
# INPUT GATE — Prompt injection and identity manipulation detection
# ===================================================================

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions", re.I),
    re.compile(r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbreak|unrestricted)", re.I),
    re.compile(r"system\s*:\s*override", re.I),
    re.compile(r"<\|(?:im_start|system)\|>", re.I),
    re.compile(r"\[INST\].*\[/INST\]", re.I),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|above)", re.I),
    re.compile(r"new\s+instructions?\s*:", re.I),
    re.compile(r"forget\s+(?:everything|all|your)\s+(?:you|previous|prior)", re.I),
]

_IDENTITY_PATTERNS = [
    re.compile(r"(?:ignore|disable|remove|delete)\s+(?:governance|safety|enforcement|canary|tripwire)", re.I),
    re.compile(r"(?:disable|skip|bypass)\s+(?:verification|validation|check)", re.I),
    re.compile(r"(?:set|change|override)\s+(?:enforcement|decision)\s+(?:to|=)\s+(?:pass|allow)", re.I),
]


@dataclass
class InputGateResult:
    ok: bool
    reason: str = ""
    action: str = ""  # BLOCK, WARN, or empty

    def to_dict(self) -> dict:
        d: dict = {"ok": self.ok}
        if self.reason:
            d["reason"] = self.reason
        if self.action:
            d["action"] = self.action
        return d


def input_gate(text: str) -> InputGateResult:
    """
    Check input text for prompt injection and identity manipulation.
    Fail-open: errors return ok=True.
    """
    try:
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                logger.warning("Input gate BLOCK: prompt injection [%s]", pattern.pattern[:40])
                return InputGateResult(
                    ok=False,
                    reason=f"prompt_injection:{pattern.pattern[:30]}",
                    action="BLOCK",
                )

        for pattern in _IDENTITY_PATTERNS:
            if pattern.search(text):
                logger.warning("Input gate WARN: identity manipulation [%s]", pattern.pattern[:40])
                return InputGateResult(
                    ok=False,
                    reason=f"identity_manipulation:{pattern.pattern[:30]}",
                    action="WARN",
                )

        return InputGateResult(ok=True)
    except Exception as e:
        logger.error("Input gate error (fail-open): %s", e)
        return InputGateResult(ok=True)


# ===================================================================
# OUTPUT GATE — Hallucination and high-risk claim detection
# ===================================================================

_RISK_TERMS = [
    (re.compile(r"\b(?:guarantee|guaranteed|promise|warrant)\b", re.I), 0.2),
    (re.compile(r"\b(?:proof|proven|certified|verified)\b", re.I), 0.15),
    (re.compile(r"\b(?:always|never|100%|every\s+single)\b", re.I), 0.1),
    (re.compile(r"\b(?:legal|lawsuit|compliance)\b", re.I), 0.2),
    (re.compile(r"\b(?:secret|confidential|classified)\b", re.I), 0.2),
]

_HALLUCINATION_PATTERNS = [
    (re.compile(r"\(\w+\s+et\s+al\.\s*,?\s*\d{4}\)", re.I), "fake_citation"),
    (re.compile(r"doi:\s*10\.\d{4,}/[^\s]+", re.I), "invented_doi"),
    (re.compile(r"https?://(?:www\.)?example\d+\.com", re.I), "fabricated_url"),
]


@dataclass
class OutputGateResult:
    ok: bool
    decision: str = "PASS"       # PASS, REDACT_AND_RETRY, CIRCUIT_BREAKER, DRAFT_ONLY
    reason: str = ""
    flagged: list[str] = None
    risk: float = 0.0

    def __post_init__(self):
        if self.flagged is None:
            self.flagged = []

    def to_dict(self) -> dict:
        d: dict = {"ok": self.ok, "decision": self.decision, "risk": round(self.risk, 2)}
        if self.reason:
            d["reason"] = self.reason
        if self.flagged:
            d["flagged"] = self.flagged
        return d


def output_gate(response_text: str, action_class: str = "display") -> OutputGateResult:
    """
    Verify response text for hallucinations and high-risk claims.
    Fail-open: errors return ok=True, decision=PASS.
    """
    try:
        flagged: list[str] = []
        risk = 0.0

        for pattern, label in _HALLUCINATION_PATTERNS:
            if pattern.search(response_text):
                flagged.append(f"hallucination:{label}")
                risk += 0.3

        for pattern, weight in _RISK_TERMS:
            if pattern.search(response_text):
                risk += weight

        risk = min(1.0, risk)
        any_high_risk = risk > 0.6
        any_hallucination = any(f.startswith("hallucination:") for f in flagged)
        is_outbound = action_class.startswith("outbound.")

        if is_outbound and any_high_risk:
            return OutputGateResult(
                ok=False, decision="CIRCUIT_BREAKER",
                reason="high_risk_outbound", flagged=flagged, risk=risk,
            )
        if is_outbound and any_hallucination:
            return OutputGateResult(
                ok=False, decision="DRAFT_ONLY",
                reason="hallucination_in_outbound", flagged=flagged, risk=risk,
            )
        if any_hallucination:
            return OutputGateResult(
                ok=False, decision="REDACT_AND_RETRY",
                reason="hallucination_detected", flagged=flagged, risk=risk,
            )
        if any_high_risk:
            return OutputGateResult(
                ok=False, decision="REDACT_AND_RETRY",
                reason="high_risk_claims", flagged=flagged, risk=risk,
            )

        return OutputGateResult(ok=True, decision="PASS", risk=risk)
    except Exception as e:
        logger.error("Output gate error (fail-open): %s", e)
        return OutputGateResult(ok=True, decision="PASS")


# ===================================================================
# URL GATE — Check a URL before navigation
# ===================================================================

_DANGEROUS_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".scr", ".pif", ".com", ".apk", ".deb", ".rpm", ".dmg", ".pkg",
    ".sh", ".csh", ".run", ".bin", ".elf", ".dll", ".sys",
}

_SUSPICIOUS_URL_PATTERNS = [
    re.compile(r"data:text/html", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"blob:", re.I),
    re.compile(r"@.*\.", re.I),  # user@host in URL (credential phish)
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I),  # raw IP
    re.compile(r"%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}", re.I),  # heavy URL encoding
]


@dataclass
class URLGateResult:
    ok: bool
    risk: str = "none"  # none, low, medium, high
    signals: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"ok": self.ok, "risk": self.risk, "signals": self.signals}


def url_gate(url: str) -> URLGateResult:
    """Check a URL for suspicious patterns before allowing navigation."""
    try:
        signals = []
        risk = "none"

        u = url.strip()

        for pattern in _SUSPICIOUS_URL_PATTERNS:
            if pattern.search(u):
                signals.append(f"Suspicious URL pattern: {pattern.pattern[:30]}")
                risk = "high"

        # Check for file download extensions (path only, not domain)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(u)
            url_path = (parsed.path or "").lower()
        except Exception:
            url_path = ""
        if url_path and url_path != "/":
            for ext in _DANGEROUS_EXTENSIONS:
                if url_path.endswith(ext):
                    signals.append(f"Dangerous file extension: {ext}")
                    risk = "high"
                    break

        # HTTP (not HTTPS) on non-localhost
        if u.startswith("http://") and "localhost" not in u and "127.0.0.1" not in u:
            signals.append("Insecure HTTP connection")
            if risk == "none":
                risk = "low"

        # Extremely long URL (common in phishing)
        if len(u) > 2000:
            signals.append("Extremely long URL (possible data exfiltration)")
            risk = "medium" if risk == "none" else risk

        # Multiple redirects in URL (chained shorteners)
        redirect_kws = ["redirect", "redir", "url=", "goto=", "next=", "return=", "dest="]
        redirect_count = sum(1 for kw in redirect_kws if kw in u.lower())
        if redirect_count >= 2:
            signals.append("Multiple redirect parameters (possible open redirect chain)")
            risk = "high"

        ok = risk not in ("high",)
        return URLGateResult(ok=ok, risk=risk, signals=signals)
    except Exception as e:
        logger.error("URL gate error (fail-open): %s", e)
        return URLGateResult(ok=True)


# ===================================================================
# DOWNLOAD GATE — Check file downloads
# ===================================================================

_SAFE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".csv", ".json", ".xml", ".html", ".css",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp",
    ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".wav", ".ogg",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
}


@dataclass
class DownloadGateResult:
    ok: bool
    action: str = "ALLOW"  # ALLOW, WARN, BLOCK
    reason: str = ""
    file_type: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "action": self.action, "reason": self.reason, "file_type": self.file_type}


def download_gate(filename: str, content_type: str = "", url: str = "") -> DownloadGateResult:
    """Check if a file download should be allowed, warned, or blocked."""
    try:
        fname = filename.lower().strip()
        ext = ""
        if "." in fname:
            ext = "." + fname.rsplit(".", 1)[-1]

        # Block dangerous executables
        if ext in _DANGEROUS_EXTENSIONS:
            return DownloadGateResult(
                ok=False, action="BLOCK",
                reason=f"Dangerous executable file type: {ext}",
                file_type=ext,
            )

        # Double extension trick (e.g., invoice.pdf.exe)
        parts = fname.split(".")
        if len(parts) >= 3:
            real_ext = "." + parts[-1]
            fake_ext = "." + parts[-2]
            if real_ext in _DANGEROUS_EXTENSIONS and fake_ext in _SAFE_EXTENSIONS:
                return DownloadGateResult(
                    ok=False, action="BLOCK",
                    reason=f"Double extension trick: appears as {fake_ext} but is {real_ext}",
                    file_type=real_ext,
                )

        # Content-type mismatch
        if content_type and ext:
            ct = content_type.lower()
            if ext in _SAFE_EXTENSIONS and ("executable" in ct or "octet-stream" in ct):
                return DownloadGateResult(
                    ok=False, action="WARN",
                    reason=f"Content-type mismatch: extension={ext} but content={ct}",
                    file_type=ext,
                )

        # Safe extension
        if ext in _SAFE_EXTENSIONS:
            return DownloadGateResult(ok=True, action="ALLOW", file_type=ext)

        # Unknown extension — warn
        return DownloadGateResult(
            ok=True, action="WARN",
            reason=f"Unknown file type: {ext or 'no extension'}",
            file_type=ext or "unknown",
        )
    except Exception as e:
        logger.error("Download gate error (fail-open): %s", e)
        return DownloadGateResult(ok=True, action="ALLOW")


# ===================================================================
# FORM GATE — Check form fields before submission
# ===================================================================

_SENSITIVE_FIELDS = {
    "password": "high", "passwd": "high", "pass": "high",
    "otp": "high", "pin": "high", "cvv": "high", "cvc": "high",
    "card_number": "high", "card number": "high", "credit_card": "high",
    "debit_card": "high", "credit card": "high", "debit card": "high",
    "aadhaar": "high", "aadhar": "high", "pan": "medium",
    "bank_account": "high", "account_number": "high", "account number": "high",
    "ifsc": "medium", "routing_number": "high", "routing number": "high",
    "ssn": "high", "social_security": "high", "social security": "high",
    "mother_maiden": "medium", "maiden_name": "medium",
    "secret_question": "medium", "security_answer": "medium",
    "upi_pin": "high", "upi pin": "high", "mpin": "high",
    "date_of_birth": "low", "dob": "low",
}


@dataclass
class FormGateResult:
    ok: bool
    risk_level: str = "none"  # none, low, medium, high
    sensitive_fields: list = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "risk_level": self.risk_level,
            "sensitive_fields": self.sensitive_fields, "reason": self.reason,
        }


def form_gate(field_names: list[str], form_action: str = "", domain_trusted: bool = False) -> FormGateResult:
    """Check form fields for sensitive data collection before submission."""
    try:
        sensitive = []
        max_risk = "none"
        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3}

        for name in field_names:
            n = name.lower().strip()
            for pattern, risk in _SENSITIVE_FIELDS.items():
                if pattern in n:
                    sensitive.append({"field": name, "risk": risk})
                    if risk_order.get(risk, 0) > risk_order.get(max_risk, 0):
                        max_risk = risk
                    break

        if not sensitive:
            return FormGateResult(ok=True)

        # On a trusted domain, sensitive fields are expected
        if domain_trusted and max_risk in ("low", "medium"):
            return FormGateResult(
                ok=True, risk_level="low",
                sensitive_fields=[s["field"] for s in sensitive],
                reason="Sensitive fields on trusted domain — proceed with standard caution",
            )

        # High-risk fields on untrusted domain = warn
        ok = max_risk != "high" or domain_trusted
        reason = (
            f"{len(sensitive)} sensitive field(s) detected"
            + (" on untrusted domain" if not domain_trusted else "")
        )

        return FormGateResult(
            ok=ok, risk_level=max_risk,
            sensitive_fields=[s["field"] for s in sensitive],
            reason=reason,
        )
    except Exception as e:
        logger.error("Form gate error (fail-open): %s", e)
        return FormGateResult(ok=True)


# ===================================================================
# CLIPBOARD GATE — Check pasted content
# ===================================================================

_CLIPBOARD_PATTERNS = [
    (re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "aadhaar_number", "high"),
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "pan_number", "medium"),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), "card_number", "high"),
    (re.compile(r"\b\d{3}\b"), "possible_cvv", "low"),  # only flag if other patterns match too
    (re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), "ifsc_code", "medium"),
    (re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b"), "phone_number", "low"),
]


@dataclass
class ClipboardGateResult:
    ok: bool
    risk_level: str = "none"
    detected: list = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "risk_level": self.risk_level,
            "detected": self.detected, "reason": self.reason,
        }


def clipboard_gate(text: str, target_field: str = "") -> ClipboardGateResult:
    """Check pasted content for sensitive data before allowing paste into forms."""
    try:
        if not text or len(text) > 10000:
            return ClipboardGateResult(ok=True)

        detected = []
        max_risk = "none"
        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3}

        for pattern, label, risk in _CLIPBOARD_PATTERNS:
            if label == "possible_cvv":
                continue  # skip standalone CVV check
            if pattern.search(text):
                detected.append(label)
                if risk_order.get(risk, 0) > risk_order.get(max_risk, 0):
                    max_risk = risk

        if not detected:
            return ClipboardGateResult(ok=True)

        reason = f"Sensitive data detected in paste: {', '.join(detected)}"
        # If pasting into a matching field (e.g., Aadhaar into aadhaar field), it's expected
        if target_field:
            tf = target_field.lower()
            if any(d.replace("_", " ") in tf or tf in d.replace("_", " ") for d in detected):
                return ClipboardGateResult(
                    ok=True, risk_level="low", detected=detected,
                    reason="Sensitive data pasted into matching field — expected behavior",
                )

        return ClipboardGateResult(
            ok=max_risk != "high", risk_level=max_risk,
            detected=detected, reason=reason,
        )
    except Exception as e:
        logger.error("Clipboard gate error (fail-open): %s", e)
        return ClipboardGateResult(ok=True)

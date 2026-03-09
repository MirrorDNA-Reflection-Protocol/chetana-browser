"""
Chetana Browser v6 — FastAPI Backend

Trust-by-design browser companion. Powers a Chrome MV3 extension.
Deterministic pattern matching, no LLM required for core operation.

Endpoints:
    GET  /health               — service health
    POST /api/analyze/page     — full page analysis
    POST /api/analyze/text     — quick text scan
    POST /api/analyze/url      — URL-only reputation check
    POST /api/fact-check       — news article fact-check
    GET  /api/stats            — analysis statistics
    GET  /api/history          — recent analysis results

Runs on port 8798.
"""
from __future__ import annotations

import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from engines import trust_engine
from engines import fact_checker
from engines import scam_detector
from engines.scamgate import ScamGate
from engines import security_gate

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("chetana.api")

# --- App ---
app = FastAPI(
    title="Chetana Browser v6",
    description="Trust-by-design browser companion backend",
    version="6.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Chrome extensions use chrome-extension:// origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- In-memory stores ---
_history: deque[dict] = deque(maxlen=200)
_stats = {
    "total_analyses": 0,
    "page_analyses": 0,
    "text_analyses": 0,
    "url_analyses": 0,
    "fact_checks": 0,
    "categories_seen": {},
    "risk_levels": {"SAFE": 0, "CAUTION": 0, "WARNING": 0, "DANGER": 0},
    "started_at": datetime.now(timezone.utc).isoformat(),
}

_boot_time = time.time()
_scamgate = ScamGate(auto_escalate=True, max_tier=2)


# --- Request/Response Models ---

class PageAnalysisRequest(BaseModel):
    url: str = ""
    text: str = ""
    title: str = ""
    meta_description: str = ""
    form_fields: Optional[list[str]] = None

    model_config = {"json_schema_extra": {
        "examples": [{
            "url": "https://example.com/offer",
            "text": "Act now! Your account will be suspended unless you verify your KYC.",
            "title": "Urgent KYC Update Required",
        }]
    }}


class TextAnalysisRequest(BaseModel):
    text: str

    model_config = {"json_schema_extra": {
        "examples": [{
            "text": "Your SBI account has been blocked. Call 9876543210 to verify your KYC immediately."
        }]
    }}


class URLAnalysisRequest(BaseModel):
    url: str

    model_config = {"json_schema_extra": {
        "examples": [{"url": "https://sbi-kyc-update.top/verify"}]
    }}


class FactCheckRequest(BaseModel):
    text: str
    url: str = ""
    title: str = ""

    model_config = {"json_schema_extra": {
        "examples": [{
            "text": "According to sources, 100% of people who tried this supplement were cured instantly.",
            "url": "https://opindia.com/article",
            "title": "Shocking health discovery",
        }]
    }}


class TrustVerdictResponse(BaseModel):
    trust_score: int = Field(ge=0, le=100)
    risk_level: str
    signals: list[str]
    recommendations: list[str]
    fact_check: Optional[dict] = None
    scam_check: Optional[dict] = None
    domain_intel: Optional[dict] = None
    manipulation_check: Optional[dict] = None
    security_gate: Optional[dict] = None
    processing_ms: float


class FactCheckResponse(BaseModel):
    credibility_score: int = Field(ge=0, le=100)
    source_tier: str
    source_category: str
    claim_count: int
    verified_claims: int
    unverified_claims: int
    manipulation_signals: list[str]
    claims_found: list[str]
    dates_found: list[str]
    attributions_found: list[str]


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: float
    engines: list[str]


class StatsResponse(BaseModel):
    total_analyses: int
    page_analyses: int
    text_analyses: int
    url_analyses: int
    fact_checks: int
    categories_seen: dict
    risk_levels: dict
    started_at: str
    uptime_seconds: float


# --- Helpers ---

def _record_history(endpoint: str, request_summary: str, verdict: dict):
    """Record an analysis result in history."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "request_summary": request_summary[:200],
        "trust_score": verdict.get("trust_score", verdict.get("credibility_score", 0)),
        "risk_level": verdict.get("risk_level", "UNKNOWN"),
    }
    _history.appendleft(entry)


def _update_stats(endpoint: str, verdict: dict, categories: list[str] | None = None):
    """Update analysis statistics."""
    _stats["total_analyses"] += 1

    endpoint_map = {
        "page": "page_analyses",
        "text": "text_analyses",
        "url": "url_analyses",
        "fact-check": "fact_checks",
    }
    key = endpoint_map.get(endpoint, "page_analyses")
    _stats[key] = _stats.get(key, 0) + 1

    risk_level = verdict.get("risk_level", "")
    if risk_level in _stats["risk_levels"]:
        _stats["risk_levels"][risk_level] += 1

    if categories:
        for cat in categories:
            _stats["categories_seen"][cat] = _stats["categories_seen"].get(cat, 0) + 1


# --- Endpoints ---

@app.get("/health", response_model=HealthResponse)
async def health():
    """Service health check."""
    return HealthResponse(
        status="ok",
        version="6.0.0",
        uptime_seconds=round(time.time() - _boot_time, 1),
        engines=[
            "trust_engine",
            "scam_detector",
            "fact_checker",
            "domain_intel",
            "manipulation_detector",
            "security_gate",
        ],
    )


@app.post("/api/analyze/page", response_model=TrustVerdictResponse)
async def analyze_page(req: PageAnalysisRequest):
    """Full page analysis — URL + text + signals combined."""
    if not req.url and not req.text:
        raise HTTPException(status_code=400, detail="Provide at least url or text")

    verdict = trust_engine.analyze_page(
        url=req.url,
        text=req.text,
        title=req.title,
        meta_description=req.meta_description,
        form_fields=req.form_fields,
    )
    result = verdict.to_dict()

    # Extract scam categories for stats
    scam_cats = []
    if verdict.scam_check:
        scam_cats = verdict.scam_check.get("categories_hit", [])

    summary = req.url or req.title or req.text[:80]
    _record_history("page", summary, result)
    _update_stats("page", result, scam_cats)

    return result


@app.post("/api/analyze/text", response_model=TrustVerdictResponse)
async def analyze_text(req: TextAnalysisRequest):
    """Quick text scan — no URL/domain analysis."""
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")

    verdict = trust_engine.analyze_text(text=req.text)
    result = verdict.to_dict()

    scam_cats = []
    if verdict.scam_check:
        scam_cats = verdict.scam_check.get("categories_hit", [])

    _record_history("text", req.text[:80], result)
    _update_stats("text", result, scam_cats)

    return result


@app.post("/api/analyze/url", response_model=TrustVerdictResponse)
async def analyze_url(req: URLAnalysisRequest):
    """URL-only reputation check."""
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    verdict = trust_engine.analyze_url(url=req.url)
    result = verdict.to_dict()

    _record_history("url", req.url[:100], result)
    _update_stats("url", result)

    return result


@app.post("/api/fact-check", response_model=FactCheckResponse)
async def fact_check(req: FactCheckRequest):
    """News article fact-check."""
    text = "\n".join(filter(None, [req.title, req.text]))
    if not text.strip():
        raise HTTPException(status_code=400, detail="Provide text or title to fact-check")

    result_obj = fact_checker.check(text=text, url=req.url)
    result = result_obj.to_dict()

    _record_history("fact-check", req.url or req.title or req.text[:80], {
        "credibility_score": result["credibility_score"],
        "risk_level": "SAFE" if result["credibility_score"] >= 60 else "CAUTION",
    })
    _update_stats("fact-check", {"risk_level": "SAFE" if result["credibility_score"] >= 60 else "CAUTION"})

    return result


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Analysis statistics since server start."""
    return StatsResponse(
        **_stats,
        uptime_seconds=round(time.time() - _boot_time, 1),
    )


@app.get("/api/history")
async def get_history(limit: int = 50):
    """Recent analysis results. Returns up to `limit` entries (max 200)."""
    limit = min(max(1, limit), 200)
    return {"history": list(_history)[:limit], "total": len(_history)}


# --- ScamGate Direct Access ---

class ScamGateScanRequest(BaseModel):
    text: str = ""
    url: str = ""


@app.post("/api/scamgate/scan")
async def scamgate_scan(req: ScamGateScanRequest):
    """ScamGate auto-escalation scan (L0 → L1 → L2 as needed)."""
    if not req.text and not req.url:
        raise HTTPException(status_code=400, detail="Provide text or url")
    result = _scamgate.scan(req.text, req.url)
    _record_history("scamgate", req.url or req.text[:80], result.to_dict())
    _update_stats("text", result.to_dict(), result.categories)
    return result.to_dict()


@app.post("/api/scamgate/quick")
async def scamgate_quick(req: ScamGateScanRequest):
    """ScamGate L0-only scan (instant, deterministic)."""
    if not req.text and not req.url:
        raise HTTPException(status_code=400, detail="Provide text or url")
    result = _scamgate.quick_scan(req.text, req.url)
    return result.to_dict()


@app.post("/api/scamgate/deep")
async def scamgate_deep(req: ScamGateScanRequest):
    """ScamGate forced deep scan (all tiers: L0+L1+L2)."""
    if not req.text and not req.url:
        raise HTTPException(status_code=400, detail="Provide text or url")
    result = _scamgate.deep_scan(req.text, req.url)
    _record_history("scamgate-deep", req.url or req.text[:80], result.to_dict())
    _update_stats("text", result.to_dict(), result.categories)
    return result.to_dict()


@app.get("/api/scamgate/stats")
async def scamgate_stats():
    """ScamGate-specific statistics."""
    return _scamgate.stats()


# --- Security Gates ---

class URLGateRequest(BaseModel):
    url: str


class DownloadGateRequest(BaseModel):
    filename: str
    content_type: str = ""
    url: str = ""


class FormGateRequest(BaseModel):
    field_names: list[str]
    form_action: str = ""
    domain_trusted: bool = False


class ClipboardGateRequest(BaseModel):
    text: str
    target_field: str = ""


@app.post("/api/gate/url")
async def gate_url(req: URLGateRequest):
    """Check URL safety before navigation."""
    result = security_gate.url_gate(req.url)
    return result.to_dict()


@app.post("/api/gate/download")
async def gate_download(req: DownloadGateRequest):
    """Check file download safety."""
    result = security_gate.download_gate(req.filename, req.content_type, req.url)
    return result.to_dict()


@app.post("/api/gate/form")
async def gate_form(req: FormGateRequest):
    """Check form fields for sensitive data collection."""
    result = security_gate.form_gate(req.field_names, req.form_action, req.domain_trusted)
    return result.to_dict()


@app.post("/api/gate/clipboard")
async def gate_clipboard(req: ClipboardGateRequest):
    """Check clipboard content before paste."""
    result = security_gate.clipboard_gate(req.text, req.target_field)
    return result.to_dict()


@app.post("/api/gate/input")
async def gate_input(req: TextAnalysisRequest):
    """Check text for prompt injection."""
    result = security_gate.input_gate(req.text)
    return result.to_dict()


# --- Main ---

def main():
    """Run the server directly."""
    import uvicorn
    port = int(os.environ.get("CHETANA_PORT", "8798"))
    logger.info("Starting Chetana Browser v6 backend on port %d", port)
    uvicorn.run(
        "api:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()

"""
LLM Security Gateway – Main FastAPI Application
================================================
Wires together all pipeline components and exposes the REST API.

Endpoints:
  GET  /health        – liveness / component status
  POST /analyze       – single prompt analysis
  POST /analyze/batch – batch analysis
  GET  /metrics       – runtime metrics summary
  GET  /config        – active configuration
  GET  /audit/recent  – last N audit records
"""


import os
import time
import yaml
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import uvicorn

# ---------------------------------------------------------------------------
# Component imports – graceful degradation on missing deps
# ---------------------------------------------------------------------------
from injection_detector import InjectionDetector
from pii_detector import PIIDetector
from policy_engine import PolicyEngine, Decision
from pipeline import SecurityPipeline
from metrics import MetricsCollector

try:
    from semantic_detector import SemanticDetector
    _semantic = SemanticDetector()
except Exception:
    _semantic = None

try:
    from multilingual import MultilingualProcessor
    _ml_proc = MultilingualProcessor()
except Exception:
    _ml_proc = None

try:
    from preprocessor import TextPreprocessor
    _preprocessor = TextPreprocessor()
except Exception:
    _preprocessor = None

try:
    from audit_log import AuditLogger
    _audit = AuditLogger(log_dir="audit_logs")
except Exception:
    _audit = None

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------
def _load_config(path: str = "config.yaml") -> Dict:
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

_config = _load_config()

# ---------------------------------------------------------------------------
# Initialise core components
# ---------------------------------------------------------------------------
_injection_detector = InjectionDetector()
_pii_detector = PIIDetector()
_policy_engine = PolicyEngine()
_metrics = MetricsCollector()

_pipeline = SecurityPipeline(
    injection_detector=_injection_detector,
    pii_detector=_pii_detector,
    policy_engine=_policy_engine,
    semantic_detector=_semantic,
    multilingual_processor=_ml_proc,
    audit_logger=_audit,
    preprocessor=_preprocessor,
)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="LLM Security Gateway",
    version="2.0.0",
    description=(
        "Hybrid security gateway for LLM prompts. "
        "Detects prompt injection, PII leakage, and multilingual threats."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Prompt text to analyze")


class BatchRequest(BaseModel):
    texts: List[str] = Field(..., min_items=1)


class AnalyzeResponse(BaseModel):
    request_id: Optional[str]
    decision: str
    reason: str
    rule_score: float
    injection_score: float
    injection_risk: str
    semantic_score: float
    semantic_threat: bool
    pii_detected: bool
    pii_confidence: float
    pii_entities: list
    masked_text: Optional[str]
    detected_lang: str
    was_translated: bool
    latency_ms: float
    final_risk: float
    reason_codes: list


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _pipeline_result_to_dict(res) -> Dict[str, Any]:
    return {
        "request_id":    res.request_id,
        "decision":      res.decision,
        "reason":        res.reason,
        "rule_score":    res.rule_score,
        "injection_score": res.injection_score,
        "injection_risk":  res.injection_risk,
        "semantic_score":  res.semantic_score,
        "semantic_threat": res.semantic_threat,
        "pii_detected":    res.pii_detected,
        "pii_confidence":  res.pii_confidence,
        "pii_entities":    res.pii_entities,
        "masked_text":     res.masked_text,
        "detected_lang":   res.detected_lang,
        "was_translated":  res.was_translated,
        "latency_ms":      res.latency_ms,
        "final_risk":      res.final_risk,
        "reason_codes":    res.reason_codes,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health", tags=["System"])
def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "components": {
            "injection_detector": True,
            "pii_detector":       True,
            "policy_engine":      True,
            "semantic_detector":  _semantic is not None,
            "multilingual":       _ml_proc is not None,
            "preprocessor":       _preprocessor is not None,
            "audit_logger":       _audit is not None,
            "metrics":            True,
        },
    }


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
def analyze(req: AnalyzeRequest, request: Request):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Empty text")

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    res = _pipeline.run(req.text, client_ip=client_ip, user_agent=user_agent)

    _metrics.record_request(
        input_length=len(req.text),
        latency_ms=res.latency_ms,
        injection_score=res.injection_score,
        injection_risk=res.injection_risk,
        pii_detected=res.pii_detected,
        pii_count=len(res.pii_entities),
        pii_confidence=res.pii_confidence,
        decision=res.decision,
        pii_entity_types=[e.get("type") for e in res.pii_entities],
    )

    return _pipeline_result_to_dict(res)


@app.post("/analyze/batch", tags=["Analysis"])
def batch_analyze(req: BatchRequest, request: Request):
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    results = []
    t_total = time.perf_counter()

    for text in req.texts:
        if not text.strip():
            results.append({"error": "empty text"})
            continue

        res = _pipeline.run(text, client_ip=client_ip, user_agent=user_agent)

        _metrics.record_request(
            input_length=len(text),
            latency_ms=res.latency_ms,
            injection_score=res.injection_score,
            injection_risk=res.injection_risk,
            pii_detected=res.pii_detected,
            pii_count=len(res.pii_entities),
            pii_confidence=res.pii_confidence,
            decision=res.decision,
            pii_entity_types=[e.get("type") for e in res.pii_entities],
        )

        results.append(_pipeline_result_to_dict(res))

    return {
        "results":          results,
        "total_latency_ms": round((time.perf_counter() - t_total) * 1000, 2),
    }


@app.get("/metrics", tags=["Observability"])
def metrics():
    summary = _metrics.get_summary()
    summary["detection_rates"] = _metrics.get_detection_rate()
    return summary


@app.get("/config", tags=["System"])
def config():
    return {"status": "ok", "config": _config}


@app.get("/audit/recent", tags=["Observability"])
def audit_recent(n: int = 20):
    if _audit is None:
        return {"status": "audit logging not enabled"}
    return {"records": _audit.tail(n)}


@app.get("/audit/search", tags=["Observability"])
def audit_search(decision: Optional[str] = None, date: Optional[str] = None):
    if _audit is None:
        return {"status": "audit logging not enabled"}
    records = _audit.search(decision=decision, date=date)
    return {"count": len(records), "records": records}


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
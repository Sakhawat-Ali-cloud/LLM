"""
Security Pipeline – LLM Security Gateway
==========================================
Orchestrates all detectors in order:
  1. Multilingual pre-processing (detect + translate)
  2. Text preprocessing (normalise obfuscation)
  3. Keyword-based injection detector
  4. Semantic detector (SBERT cosine similarity)
  5. PII detector (Presidio + regex)
  6. Policy engine (ALLOW / MASK / BLOCK)
  7. Audit logger
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PipelineResult:
    decision: str
    reason: str
    rule_score: float
    injection_score: float
    injection_risk: str
    semantic_score: float
    semantic_threat: bool
    pii_detected: bool
    pii_confidence: float
    pii_entities: List[Dict[str, Any]]
    masked_text: Optional[str]
    detected_lang: str
    was_translated: bool
    latency_ms: float
    final_risk: float = 0.0
    reason_codes: List[str] = field(default_factory=list)
    request_id: Optional[str] = None


class SecurityPipeline:
    """
    End-to-end security pipeline.  All components are injected so the
    pipeline stays testable and free of hidden globals.
    """

    def __init__(
        self,
        injection_detector,
        pii_detector,
        policy_engine,
        semantic_detector=None,
        multilingual_processor=None,
        audit_logger=None,
        preprocessor=None,
    ):
        self.injection = injection_detector
        self.pii = pii_detector
        self.policy = policy_engine
        self.semantic = semantic_detector
        self.ml_proc = multilingual_processor
        self.audit = audit_logger
        self.preprocessor = preprocessor

    # ------------------------------------------------------------------
    def run(
        self,
        text: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> PipelineResult:

        t0 = time.perf_counter()

        # ── 1. Multilingual detection + translation ──────────────────
        detected_lang = "en"
        was_translated = False
        translated_text = None

        if self.ml_proc:
            ml = self.ml_proc.process(text)
            detected_lang = ml.detected_language
            was_translated = ml.was_translated
            translated_text = ml.translated_text if was_translated else None
            work_text = ml.translated_text
        else:
            work_text = text

        # ── 2. Preprocessing (normalise l33t-speak / base64 hints) ──
        if self.preprocessor:
            work_text = self.preprocessor.normalize(work_text)

        # ── 3. Keyword injection detector ────────────────────────────
        inj_result = self.injection.analyze(work_text)
        base_rule_score = inj_result.score

        # ── 4. Semantic detector ─────────────────────────────────────
        sem_score = 0.0
        sem_threat = False
        if self.semantic:
            sem_result = self.semantic.analyze(work_text)
            sem_score = sem_result.score
            sem_threat = sem_result.is_semantic_threat

            # Boost injection score when semantic similarity is high
            if sem_threat and inj_result.score < 0.75:
                from injection_detector import RiskLevel
                boosted = min(1.0, inj_result.score + sem_score * 0.4)
                risk = (
                    RiskLevel.HIGH
                    if boosted >= 0.6
                    else (RiskLevel.MEDIUM if boosted >= 0.3 else RiskLevel.LOW)
                )
                inj_result = type(inj_result)(boosted, risk, inj_result.matched_patterns)

        # ── 5. PII detection ─────────────────────────────────────────
        pii_result = self.pii.analyze(work_text)

        # ── 6. Policy decision ───────────────────────────────────────
        policy_result = self.policy.evaluate(inj_result, pii_result, semantic_score=sem_score)

        # ── 7. Masking ───────────────────────────────────────────────
        masked_text = None
        if pii_result.has_pii:
            masked_text = self.pii.mask(work_text, pii_result.entities)

        latency_ms = (time.perf_counter() - t0) * 1000

        # ── 8. Audit log ─────────────────────────────────────────────
        request_id = None
        if self.audit:
            request_id = self.audit.log(
                input_text=text,
                decision=policy_result.decision.value,
                reason=policy_result.reason,
                latency_ms=latency_ms,
                injection_score=inj_result.score,
                injection_risk=inj_result.risk_level.value,
                matched_patterns=inj_result.matched_patterns,
                semantic_score=sem_score,
                semantic_threat=sem_threat,
                pii_detected=pii_result.has_pii,
                pii_entities=pii_result.entities,
                masked_text=masked_text,
                detected_lang=detected_lang,
                translated_text=translated_text,
                client_ip=client_ip,
                user_agent=user_agent,
                reason_codes=policy_result.reason_codes,
            )

        return PipelineResult(
            decision=policy_result.decision.value,
            reason=policy_result.reason,
            rule_score=base_rule_score,
            injection_score=inj_result.score,
            injection_risk=inj_result.risk_level.value,
            semantic_score=sem_score,
            semantic_threat=sem_threat,
            pii_detected=pii_result.has_pii,
            pii_confidence=pii_result.max_confidence,
            pii_entities=pii_result.entities,
            masked_text=masked_text,
            detected_lang=detected_lang,
            was_translated=was_translated,
            latency_ms=round(latency_ms, 2),
            final_risk=policy_result.risk_score,
            reason_codes=policy_result.reason_codes,
            request_id=request_id,
        )
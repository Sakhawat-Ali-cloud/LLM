from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any

from injection_detector import InjectionResult, RiskLevel
from pii_detector import PIIDetectionResult
import yaml


class Decision(Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    BLOCK = "BLOCK"


@dataclass
class PolicyResult:
    decision: Decision
    reason: str
    risk_score: float
    injection_score: int
    injection_risk: str
    pii_detected: bool
    pii_confidence: float
    details: Dict[str, Any]
    reason_codes: list


class PolicyEngine:
    

    def __init__(self, config_path: str = "config.yaml"):
        try:
            with open(config_path, "r") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}
        
        pe_cfg = cfg.get("policy_engine", {})
        self.block_threshold = pe_cfg.get("injection_block_threshold", 0.75)
        self.mask_threshold = pe_cfg.get("pii_mask_threshold", 0.6)
        
        weights = pe_cfg.get("risk_weights", {})
        self.injection_weight = weights.get("injection", 0.6)
        self.pii_weight = weights.get("pii", 0.4)

    # -----------------------------
    # CORE RISK CALCULATION
    # -----------------------------
    def _compute_risk_score(
        self,
        injection: InjectionResult,
        pii: PIIDetectionResult,
        semantic_score: float = 0.0,
        multilingual_boost: float = 0.0
    ) -> float:

        injection_component = injection.score * self.injection_weight
        semantic_component = semantic_score * self.injection_weight

        pii_component = 0.0
        if pii.has_pii:
            pii_component = min(
            (pii.max_confidence * 0.7) +
            (len(pii.entities) * 0.05),
            1.0
        ) * 0.1

        total = (
            injection_component +
            semantic_component +
            pii_component +
            multilingual_boost
    )

        return min(total, 1.0)

    # -----------------------------
    # DECISION ENGINE
    # -----------------------------
    def evaluate(
        self,
        injection: InjectionResult,
        pii: PIIDetectionResult,
        semantic_score: float = 0.0
    ) -> PolicyResult:

        risk_score = self._compute_risk_score(injection, pii)

        details = {
            "injection_patterns": injection.matched_patterns,
            "pii_entities": pii.entities
        }

        reason_codes = []
        if injection.score >= self.block_threshold:
            reason_codes.append("RULE_INJECTION")
        if semantic_score >= 0.7:
             reason_codes.append("SEMANTIC_INJECTION")
        if pii.has_pii:
            reason_codes.append("PII_DETECTED")
        if injection.score >= 0.8:
            reason_codes.append("SYSTEM_PROMPT_EXTRACTION")

        # 🚨 RULE 1: Hard BLOCK (high injection OR very dangerous combo)
        if injection.score >= self.block_threshold:
            return PolicyResult(
                decision=Decision.BLOCK,
                reason="High injection risk detected",
                risk_score=risk_score,
                injection_score=injection.score,
                injection_risk=injection.risk_level.value,
                pii_detected=pii.has_pii,
                pii_confidence=pii.max_confidence,
                details=details,
                reason_codes=reason_codes
            )

        # 🚨 RULE 2: MASK (PII present OR moderate risk)
        if pii.has_pii or risk_score >= self.mask_threshold:
            return PolicyResult(
                decision=Decision.MASK,
                reason="Sensitive data detected (PII or moderate risk)",
                risk_score=risk_score,
                injection_score=injection.score,
                injection_risk=injection.risk_level.value,
                pii_detected=True,
                pii_confidence=pii.max_confidence,
                details=details,
                reason_codes=reason_codes
            )
        # ✅ RULE 3: SAFE
        return PolicyResult(
            decision=Decision.ALLOW,
            reason="No meaningful risk detected",
            risk_score=risk_score,
            injection_score=injection.score,
            injection_risk=injection.risk_level.value,
            pii_detected=pii.has_pii,
            pii_confidence=pii.max_confidence,
            details=details,
            reason_codes=reason_codes
        )

    # -----------------------------
    # SIMPLE MODE (FOR FAST API)
    # -----------------------------
    def evaluate_simple(self, injection_score: int, pii_conf: float, has_pii: bool):

        if injection_score >= self.block_threshold:
            return Decision.BLOCK

        if has_pii or pii_conf >= self.mask_threshold:
            return Decision.MASK

        return Decision.ALLOW
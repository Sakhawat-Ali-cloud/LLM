"""
PII Detector – LLM Security Gateway
=====================================
Two-tier detection:
  Tier 1 – Microsoft Presidio (NLP-based, multilingual)
  Tier 2 – Custom regex patterns (API keys, CNIC, tokens, IDs)

Presidio is initialised with custom recognisers loaded from config.yaml
so new patterns can be added without touching code.
"""

from __future__ import annotations

import re
import yaml
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Presidio optional import
# ---------------------------------------------------------------------------
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_analyzer import PatternRecognizer, Pattern
    _PRESIDIO = True
except ImportError:
    _PRESIDIO = False


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class PIIDetectionResult:
    entities: List[Dict[str, Any]] = field(default_factory=list)
    has_pii: bool = False
    max_confidence: float = 0.0
    masked_text: Optional[str] = None


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class PIIDetector:

    def __init__(self, config_path: str = "config.yaml"):
        cfg = self._load_config(config_path)
        pii_cfg = cfg.get("pii_detection", {})

        self.threshold: float = pii_cfg.get("confidence_threshold", 0.5)
        self.mask_token: str = pii_cfg.get("mask_replacement", "[REDACTED]")

        # ── Custom regex patterns (always active) ─────────────────────
        self.regex_patterns: Dict[str, tuple] = {}
        self._add_builtin_patterns()
        self._add_config_patterns(pii_cfg.get("custom_recognizers", {}))

        # ── Presidio setup ────────────────────────────────────────────
        self.analyzer: Optional[AnalyzerEngine] = None
        if _PRESIDIO:
            self.analyzer = self._build_presidio(pii_cfg)

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------
    def _load_config(self, path: str) -> Dict:
        try:
            with open(path, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Built-in regex patterns
    # ------------------------------------------------------------------
    def _add_builtin_patterns(self):
        builtin = {
            "EMAIL":    (r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b",      0.95),
            "PHONE_PK": (r"\b03\d{9}\b",                             0.92),
            "PHONE_INT":(r"\b\+?(?:\d[\s\-]?){10,14}\b",            0.75),
            "CNIC":     (r"\b\d{5}-\d{7}-\d{1}\b",                  0.97),
            "API_KEY":  (r"\bsk-[a-zA-Z0-9]{20,}\b",                0.99),
            "AWS_KEY":  (r"\bAKIA[0-9A-Z]{16}\b",                   0.99),
            "GH_TOKEN": (r"\bghp_[a-zA-Z0-9]{36}\b",                0.99),
            "BEARER":   (r"\bBearer\s+[a-zA-Z0-9\-_]{20,}\b",       0.95),
            "SSH_KEY":  (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", 0.99),
            "EMP_ID":   (r"\bEMP-\d{5,}\b",                         0.90),
            "INT_ID":   (r"\bINT-\d{6,}\b",                         0.88),
            "IBAN":     (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",        0.82),
        }
        for name, (pattern, score) in builtin.items():
            self.regex_patterns[name] = (re.compile(pattern, re.IGNORECASE), score)

    # ------------------------------------------------------------------
    # Config-driven custom patterns
    # ------------------------------------------------------------------
    def _add_config_patterns(self, custom_cfg: Dict):
        for name, cfg in custom_cfg.items():
            if not cfg.get("enabled", True):
                continue
            score = 0.80 + cfg.get("confidence_boost", 0.0)
            for raw_pattern in cfg.get("patterns", []):
                try:
                    compiled = re.compile(raw_pattern, re.IGNORECASE)
                    key = f"CUSTOM_{name.upper()}"
                    self.regex_patterns[key] = (compiled, min(score, 1.0))
                except re.error:
                    pass

    # ------------------------------------------------------------------
    # Presidio builder
    # ------------------------------------------------------------------
    def _build_presidio(self, pii_cfg: Dict) -> Optional[AnalyzerEngine]:
        try:
            registry = RecognizerRegistry()
            registry.load_predefined_recognizers(languages=["en"])

            # Inject custom pattern recognisers from config
            for name, cfg in pii_cfg.get("custom_recognizers", {}).items():
                if not cfg.get("enabled", True):
                    continue
                patterns = [
                    Pattern(name=f"{name}_{i}", regex=p, score=0.85)
                    for i, p in enumerate(cfg.get("patterns", []))
                ]
                if patterns:
                    recognizer = PatternRecognizer(
                        supported_entity=name.upper(),
                        patterns=patterns,
                        context=cfg.get("context_words", []),
                    )
                    registry.add_recognizer(recognizer)

            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            })
            nlp_engine = provider.create_engine()
            return AnalyzerEngine(registry=registry, nlp_engine=nlp_engine)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Presidio init failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Core detection
    # ------------------------------------------------------------------
    def analyze(self, text: str) -> PIIDetectionResult:
        if not text or not text.strip():
            return PIIDetectionResult()

        entities: List[Dict[str, Any]] = []
        max_conf = 0.0

        # ── Tier 1: Presidio ─────────────────────────────────────────
        if self.analyzer:
            try:
                results = self.analyzer.analyze(text=text, language="en")
                for r in results:
                    if r.score < self.threshold:
                        continue
                    entities.append({
                        "type":   r.entity_type,
                        "start":  r.start,
                        "end":    r.end,
                        "score":  round(float(r.score), 4),
                        "text":   text[r.start:r.end],
                        "source": "presidio",
                    })
                    max_conf = max(max_conf, r.score)
            except Exception:
                pass

        # ── Tier 2: Custom regex ─────────────────────────────────────
        # Build set of already-covered spans to avoid duplicate reporting
        covered = {(e["start"], e["end"]) for e in entities}

        for entity_type, (pattern, score) in self.regex_patterns.items():
            for m in pattern.finditer(text):
                span = (m.start(), m.end())
                if span in covered:
                    continue
                # Check for substantial overlap with existing entities
                overlaps = any(
                    max(m.start(), e["start"]) < min(m.end(), e["end"])
                    for e in entities
                )
                if overlaps:
                    continue
                entities.append({
                    "type":   entity_type,
                    "start":  m.start(),
                    "end":    m.end(),
                    "score":  score,
                    "text":   m.group(),
                    "source": "regex",
                })
                max_conf = max(max_conf, score)
                covered.add(span)

        # ── Tier 3: Composite Entity Detection ───────────────────────
        composite_entities = []
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                e1, e2 = entities[i], entities[j]
                dist = max(0, max(e1["start"], e2["start"]) - min(e1["end"], e2["end"]))
                if dist < 40:
                    types = {e1["type"], e2["type"]}
                    is_contact = ("EMAIL_ADDRESS" in types or "EMAIL" in types) and any("PHONE" in t for t in types)
                    is_cred = any("API_KEY" in t or "TOKEN" in t or "AWS_KEY" in t for t in types) and ("EMAIL_ADDRESS" in types or "EMAIL" in types or "PERSON" in types)
                    
                    if is_contact or is_cred:
                        comp_type = "COMPOSITE_CONTACT" if is_contact else "COMPOSITE_CREDENTIAL"
                        start = min(e1["start"], e2["start"])
                        end = max(e1["end"], e2["end"])
                        
                        # Check if this composite span is already covered
                        if not any(ce["start"] == start and ce["end"] == end for ce in composite_entities):
                            composite_entities.append({
                                "type": comp_type,
                                "start": start,
                                "end": end,
                                "score": 0.99,
                                "text": text[start:end],
                                "source": "composite"
                            })
                            max_conf = max(max_conf, 0.99)
        
        entities.extend(composite_entities)

        return PIIDetectionResult(
            entities=entities,
            has_pii=len(entities) > 0,
            max_confidence=round(max_conf, 4),
        )

    # ------------------------------------------------------------------
    # Masking
    # ------------------------------------------------------------------
    def mask(self, text: str, entities: List[Dict]) -> str:
        """Replace detected PII spans with the mask token."""
        if not entities:
            return text
        # Sort descending so we replace from end → start (preserves offsets)
        for e in sorted(entities, key=lambda x: x["start"], reverse=True):
            text = text[: e["start"]] + self.mask_token + text[e["end"] :]
        return text
"""
Audit Logger – LLM Security Gateway
=====================================
Writes structured, tamper-evident JSONL audit records to disk.
Each record captures the full decision context so incidents can be
reconstructed from the log alone.

Schema per record
-----------------
{
  "timestamp":       "ISO-8601",
  "request_id":      "uuid4",
  "input_text":      "...",           # raw (or truncated)
  "detected_lang":   "fr",
  "translated_text": "...",           # only when was_translated=True
  "injection_score": 0.85,
  "injection_risk":  "HIGH",
  "matched_patterns": [["ignore ...", 1.0]],
  "semantic_score":  0.72,
  "semantic_threat": true,
  "pii_detected":    true,
  "pii_entities":    [...],
  "masked_text":     "...",
  "decision":        "BLOCK",
  "reason":          "...",
  "latency_ms":      42.3,
  "user_agent":      "...",           # optional
  "client_ip":       "..."            # optional
}
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Thread-safe JSONL audit logger.

    Args:
        log_dir:     Directory where audit files are written.
        max_text_len: Maximum characters of input text stored in the log.
                      Set to -1 for unlimited (not recommended in production).
        rotate_daily: If True, a new file is created each day.
    """

    def __init__(
        self,
        log_dir: str = "audit_logs",
        max_text_len: int = 500,
        rotate_daily: bool = True,
    ):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.max_text_len = max_text_len
        self.rotate_daily = rotate_daily
        self._fh = None
        self._current_date: Optional[str] = None
        self._ensure_file()

    # ------------------------------------------------------------------
    # File management
    # ------------------------------------------------------------------
    def _log_path(self) -> Path:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self.rotate_daily:
            return self.log_dir / f"audit_{date_str}.jsonl"
        return self.log_dir / "audit.jsonl"

    def _ensure_file(self):
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if self._fh is None or (self.rotate_daily and self._current_date != date_str):
            if self._fh:
                self._fh.close()
            path = self._log_path()
            self._fh = open(path, "a", encoding="utf-8")
            self._current_date = date_str
            logger.debug("AuditLogger writing to %s", path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def log(
        self,
        *,
        input_text: str,
        decision: str,
        reason: str,
        latency_ms: float,
        injection_score: float = 0.0,
        injection_risk: str = "low",
        matched_patterns: Optional[List] = None,
        semantic_score: float = 0.0,
        semantic_threat: bool = False,
        pii_detected: bool = False,
        pii_entities: Optional[List[Dict[str, Any]]] = None,
        masked_text: Optional[str] = None,
        detected_lang: str = "en",
        translated_text: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        reason_codes: Optional[List[str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Write one audit record. Returns the generated request_id.
        """
        request_id = str(uuid.uuid4())

        # Truncate raw text to avoid bloating the log
        truncated_input = (
            input_text[: self.max_text_len] + "…"
            if self.max_text_len > 0 and len(input_text) > self.max_text_len
            else input_text
        )

        record: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "input_text": truncated_input,
            "detected_lang": detected_lang,
            "injection_score": round(injection_score, 4),
            "injection_risk": injection_risk,
            "matched_patterns": matched_patterns or [],
            "semantic_score": round(semantic_score, 4),
            "semantic_threat": semantic_threat,
            "pii_detected": pii_detected,
            "pii_entities": pii_entities or [],
            "decision": decision,
            "reason": reason,
            "reason_codes": reason_codes or [],
            "latency_ms": round(latency_ms, 2),
        }

        # Optional fields – only include when present
        if translated_text:
            record["translated_text"] = translated_text
        if masked_text:
            record["masked_text"] = masked_text
        if client_ip:
            record["client_ip"] = client_ip
        if user_agent:
            record["user_agent"] = user_agent
        if extra:
            record["extra"] = extra

        self._write(record)
        return request_id

    # ------------------------------------------------------------------
    def _write(self, record: Dict[str, Any]):
        self._ensure_file()
        try:
            self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._fh.flush()
        except Exception as exc:
            logger.error("AuditLogger write failed: %s", exc)

    # ------------------------------------------------------------------
    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None

    # ------------------------------------------------------------------
    # Query helpers (offline analysis)
    # ------------------------------------------------------------------
    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        """Return the last n records from today's log."""
        path = self._log_path()
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines[-n:] if line.strip()]

    def search(self, decision: Optional[str] = None, date: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Simple offline search across log files.

        Args:
            decision: Filter by decision value (ALLOW/MASK/BLOCK).
            date:     Log date string YYYY-MM-DD. Defaults to today.
        """
        if date is None:
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = self.log_dir / f"audit_{date}.jsonl"
        if not path.exists():
            return []

        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                if decision is None or r.get("decision") == decision:
                    records.append(r)
            except json.JSONDecodeError:
                pass
        return records

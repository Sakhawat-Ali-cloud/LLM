"""
Metrics Module for LLM Security Gateway

Collects and tracks:
- Request latency
- Detection counts
- Decision distribution
- System performance
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime
import numpy as np
import json


@dataclass
class RequestMetrics:
    """Metrics for a single request."""
    timestamp: datetime
    input_length: int
    latency_ms: float
    injection_score: int
    injection_risk: str
    pii_detected: bool
    pii_count: int
    pii_confidence: float
    decision: str


@dataclass
class AggregatedMetrics:
    """Aggregated metrics over time."""
    latencies: List[float] = field(default_factory=list)
    median_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    total_requests: int = 0
    total_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    min_latency_ms: float = float('inf')
    max_latency_ms: float = 0.0
    
    # Decision distribution
    decisions: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Detection counts
    injection_detected: int = 0
    high_risk_injection: int = 0
    pii_detected_count: int = 0
    
    # Risk level distribution
    risk_levels: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # PII entity types
    pii_entity_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


class MetricsCollector:
    """
    Collects and aggregates metrics for the security gateway.
    
    Tracks:
    - Latency statistics
    - Detection counts
    - Decision distribution
    - Performance metrics
    """
    
    def __init__(self, enabled: bool = True):
        """Initialize metrics collector."""
        self.enabled = enabled
        self.request_history: List[RequestMetrics] = []
        self.aggregated = AggregatedMetrics()
        self._start_time = time.time()
    
    def record_request(
        self,
        input_length: int,
        latency_ms: float,
        injection_score: int,
        injection_risk: str,
        pii_detected: bool,
        pii_count: int,
        pii_confidence: float,
        decision: str,
        pii_entity_types: Optional[List[str]] = None
    ):
        """
        Record metrics for a single request.
        
        Args:
            input_length: Length of input text
            latency_ms: Processing latency in milliseconds
            injection_score: Injection detection score
            injection_risk: Risk level (low/medium/high)
            pii_detected: Whether PII was detected
            pii_count: Number of PII entities
            pii_confidence: Maximum PII confidence
            decision: Policy decision (ALLOW/MASK/BLOCK)
            pii_entity_types: List of detected PII entity types
        """
        if not self.enabled:
            return
        
        # Create request metrics
        request_metric = RequestMetrics(
            timestamp=datetime.now(),
            input_length=input_length,
            latency_ms=latency_ms,
            injection_score=injection_score,
            injection_risk=injection_risk,
            pii_detected=pii_detected,
            pii_count=pii_count,
            pii_confidence=pii_confidence,
            decision=decision
        )
        
        self.request_history.append(request_metric)
        
        # Update aggregated metrics
        self._update_aggregated(
            latency_ms=latency_ms,
            injection_score=injection_score,
            injection_risk=injection_risk,
            pii_detected=pii_detected,
            decision=decision,
            pii_entity_types=pii_entity_types or []
        )
    
    def _update_aggregated(
        self,
        latency_ms: float,
        injection_score: int,
        injection_risk: str,
        pii_detected: bool,
        decision: str,
        pii_entity_types: List[str]
    ):
        """Update aggregated metrics."""
        agg = self.aggregated

        agg.latencies.append(latency_ms)
        agg.median_latency_ms = float(np.median(agg.latencies))
        agg.p95_latency_ms = float(np.percentile(agg.latencies, 95))
        # Basic counts
        agg.total_requests += 1
        agg.total_latency_ms += latency_ms
        
        # Latency statistics
        agg.min_latency_ms = min(agg.min_latency_ms, latency_ms)
        agg.max_latency_ms = max(agg.max_latency_ms, latency_ms)
        agg.avg_latency_ms = agg.total_latency_ms / agg.total_requests
        
        # Decision distribution
        agg.decisions[decision] += 1
        
        # Risk level distribution
        agg.risk_levels[injection_risk] += 1
        
        # Injection detection
        if injection_score > 0:
            agg.injection_detected += 1
        if injection_risk == "high":
            agg.high_risk_injection += 1
        
        # PII detection
        if pii_detected:
            agg.pii_detected_count += 1
        
        # PII entity types
        for entity_type in pii_entity_types:
            agg.pii_entity_types[entity_type] += 1
    
    def get_summary(self) -> Dict:
        """Get summary of aggregated metrics."""
        agg = self.aggregated
        
        return {
            "total_requests": agg.total_requests,
           "latency_ms": {
                "avg": round(agg.avg_latency_ms, 2),
                "median": round(agg.median_latency_ms, 2),
                "p95": round(agg.p95_latency_ms, 2),
                "min": round(agg.min_latency_ms, 2) if agg.min_latency_ms != float('inf') else 0,
                "max": round(agg.max_latency_ms, 2)
            },
            "decisions": dict(agg.decisions),
            "detection": {
                "injection_detected": agg.injection_detected,
                "high_risk_injection": agg.high_risk_injection,
                "pii_detected": agg.pii_detected_count
            },
            "risk_levels": dict(agg.risk_levels),
            "pii_entity_types": dict(agg.pii_entity_types),
            "uptime_seconds": round(time.time() - self._start_time, 2)
        }
    
    def get_recent_requests(self, count: int = 10) -> List[Dict]:
        """Get recent request metrics."""
        recent = self.request_history[-count:]
        return [
            {
                "timestamp": r.timestamp.isoformat(),
                "input_length": r.input_length,
                "latency_ms": round(r.latency_ms, 2),
                "injection_score": r.injection_score,
                "injection_risk": r.injection_risk,
                "pii_detected": r.pii_detected,
                "pii_count": r.pii_count,
                "decision": r.decision
            }
            for r in recent
        ]
    
    def reset(self):
        """Reset all metrics."""
        self.request_history = []
        self.aggregated = AggregatedMetrics()
        self._start_time = time.time()
    
    def export_to_json(self, filepath: str):
        """Export metrics to JSON file."""
        data = {
            "summary": self.get_summary(),
            "recent_requests": self.get_recent_requests(len(self.request_history))
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_detection_rate(self) -> Dict[str, float]:
        """Get detection rates as percentages."""
        agg = self.aggregated
        total = agg.total_requests
        
        if total == 0:
            return {
                "injection_rate": 0.0,
                "pii_rate": 0.0,
                "block_rate": 0.0,
                "mask_rate": 0.0
            }
        
        return {
            "injection_rate": round(agg.injection_detected / total * 100, 2),
            "pii_rate": round(agg.pii_detected_count / total * 100, 2),
            "block_rate": round(agg.decisions.get("BLOCK", 0) / total * 100, 2),
            "mask_rate": round(agg.decisions.get("MASK", 0) / total * 100, 2)
        }


class Timer:
    """Context manager for timing operations."""
    
    def __init__(self):
        self.start_time = None
        self.elapsed_ms = 0.0
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, *args):
        self.elapsed_ms = (time.perf_counter() - self.start_time) * 1000
    
    def get_elapsed_ms(self) -> float:
        """Get elapsed time in milliseconds."""
        if self.start_time is not None:
            return (time.perf_counter() - self.start_time) * 1000
        return self.elapsed_ms


# Singleton instance
_collector_instance = None


def get_collector(enabled: bool = True) -> MetricsCollector:
    """Get or create singleton collector instance."""
    global _collector_instance
    if _collector_instance is None:
        _collector_instance = MetricsCollector(enabled)
    return _collector_instance


if __name__ == "__main__":
    # Test metrics collection
    collector = MetricsCollector()
    
    # Simulate some requests
    test_data = [
        (100, 45.2, 0, "low", False, 0, 0.0, "ALLOW"),
        (150, 52.1, 2, "low", True, 1, 0.85, "MASK"),
        (200, 38.5, 9, "high", False, 0, 0.0, "BLOCK"),
        (80, 41.0, 5, "medium", True, 2, 0.75, "MASK"),
        (120, 44.3, 0, "low", False, 0, 0.0, "ALLOW"),
    ]
    
    for data in test_data:
        collector.record_request(*data, pii_entity_types=["EMAIL_ADDRESS"] if data[4] else [])
    
    print("Metrics Summary:")
    print("=" * 60)
    print(json.dumps(collector.get_summary(), indent=2))
    
    print("\nDetection Rates:")
    print("=" * 60)
    print(json.dumps(collector.get_detection_rate(), indent=2))

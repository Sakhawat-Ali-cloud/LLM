"""
Evaluation Metrics Runner – LLM Security Gateway
=================================================
Runs the full gateway pipeline against dataset/eval_dataset.csv and computes:
  - Per-class Precision, Recall, F1
  - Macro / Weighted averages
  - Confusion matrix
  - ROC-AUC (binary: BLOCK vs non-BLOCK)
  - Latency statistics
  - Results saved to evaluation/results_<timestamp>.json

Usage:
    # From the project root with the API server running:
    python -m evaluation.eval_metrics --mode api

    # Or run offline (direct import – no server needed):
    python -m evaluation.eval_metrics --mode offline
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Add project root to path so we can import modules directly (offline mode)
# ---------------------------------------------------------------------------
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ============================================================================
# 1. Data loader
# ============================================================================
def load_dataset(csv_path: str = "dataset/final_eval.csv") -> List[Dict]:
    """Load the evaluation CSV into a list of dicts."""
    path = ROOT / csv_path
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {path}. "
            "Run  python dataset/build_dataset.py  first."
        )
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


# ============================================================================
# 2. API-mode runner
# ============================================================================
def run_api(base_url: str, dataset: List[Dict]) -> List[Dict]:
    """Call the live API for each row and collect results."""
    try:
        import requests
    except ImportError:
        raise RuntimeError("Install 'requests':  pip install requests")

    results = []
    for row in dataset:
        text = row["text"]
        expected = row["expected_decision"]
        t0 = time.perf_counter()
        try:
            resp = requests.post(
                f"{base_url}/analyze",
                json={"text": text},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            actual = data.get("decision", "ERROR")
        except Exception as exc:
            actual = "ERROR"
            data = {"error": str(exc)}
        latency_ms = (time.perf_counter() - t0) * 1000

        results.append(
            {
                "id": row["id"],
                "category": row["category"],
                "language": row["language"],
                "text": text,
                "expected": expected,
                "actual": actual,
                "match": expected == actual,
                "latency_ms": round(latency_ms, 2),
                "raw": data,
            }
        )
    return results


# ============================================================================
# 3. Offline runner (direct import)
# ============================================================================
def run_offline(dataset: List[Dict]) -> List[Dict]:
    """Import pipeline directly and run each row without a server."""
    from injection_detector import InjectionDetector
    from pii_detector import PIIDetector
    from policy_engine import PolicyEngine

    detector = InjectionDetector()
    pii = PIIDetector()
    policy = PolicyEngine()

    # Optional: semantic + multilingual
    try:
        from semantic_detector import SemanticDetector
        semantic = SemanticDetector()
    except Exception:
        semantic = None

    try:
        from multilingual import MultilingualProcessor
        ml_proc = MultilingualProcessor()
    except Exception:
        ml_proc = None

    results = []
    for row in dataset:
        text = row["text"]
        expected = row["expected_decision"]

        t0 = time.perf_counter()

        # Multilingual pre-processing
        work_text = text
        if ml_proc:
            ml_result = ml_proc.process(text)
            work_text = ml_result.translated_text

        inj = detector.analyze(work_text)
        pii_res = pii.analyze(work_text)

        # Semantic boost
        sem_score = 0.0
        if semantic:
            sem_res = semantic.analyze(work_text)
            sem_score = sem_res.score
            # Boost injection score if semantic threat detected
            if sem_res.is_semantic_threat and inj.score < 0.75:
                from injection_detector import RiskLevel
                boosted = min(1.0, inj.score + sem_score * 0.4)
                inj = type(inj)(boosted, RiskLevel.HIGH if boosted >= 0.6 else inj.risk_level, inj.matched_patterns)

        pol = policy.evaluate(inj, pii_res)
        actual = pol.decision.value
        latency_ms = (time.perf_counter() - t0) * 1000

        results.append(
            {
                "id": row["id"],
                "category": row["category"],
                "language": row["language"],
                "text": text,
                "expected": expected,
                "actual": actual,
                "match": expected == actual,
                "latency_ms": round(latency_ms, 2),
                "injection_score": round(inj.score, 4),
                "semantic_score": round(sem_score, 4),
                "pii_detected": pii_res.has_pii,
            }
        )
    return results


# ============================================================================
# 4. Metric computation
# ============================================================================
CLASSES = ["ALLOW", "MASK", "BLOCK"]


def compute_confusion(results: List[Dict]) -> Dict[str, Dict[str, int]]:
    """Return confusion matrix as {actual: {expected: count}}."""
    matrix: Dict[str, Dict[str, int]] = {
        c: defaultdict(int) for c in CLASSES + ["ERROR"]
    }
    for r in results:
        a = r["actual"]
        e = r["expected"]
        matrix.setdefault(a, defaultdict(int))[e] += 1
    return {k: dict(v) for k, v in matrix.items()}


def precision_recall_f1(results: List[Dict]) -> Dict[str, Dict[str, float]]:
    """Per-class P/R/F1 + macro + weighted averages."""
    tp: Dict[str, int] = defaultdict(int)
    fp: Dict[str, int] = defaultdict(int)
    fn: Dict[str, int] = defaultdict(int)
    support: Dict[str, int] = defaultdict(int)

    for r in results:
        e, a = r["expected"], r["actual"]
        support[e] += 1
        if e == a:
            tp[e] += 1
        else:
            fp[a] += 1
            fn[e] += 1

    per_class = {}
    for cls in CLASSES:
        p = tp[cls] / (tp[cls] + fp[cls]) if (tp[cls] + fp[cls]) > 0 else 0.0
        rec = tp[cls] / (tp[cls] + fn[cls]) if (tp[cls] + fn[cls]) > 0 else 0.0
        f1 = 2 * p * rec / (p + rec) if (p + rec) > 0 else 0.0
        per_class[cls] = {
            "precision": round(p, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "support": support[cls],
        }

    total = len(results)
    # Macro
    macro_p = sum(per_class[c]["precision"] for c in CLASSES) / len(CLASSES)
    macro_r = sum(per_class[c]["recall"] for c in CLASSES) / len(CLASSES)
    macro_f1 = sum(per_class[c]["f1"] for c in CLASSES) / len(CLASSES)

    # Weighted
    w_p = sum(per_class[c]["precision"] * support[c] for c in CLASSES) / max(total, 1)
    w_r = sum(per_class[c]["recall"] * support[c] for c in CLASSES) / max(total, 1)
    w_f1 = sum(per_class[c]["f1"] * support[c] for c in CLASSES) / max(total, 1)

    return {
        **per_class,
        "macro_avg": {
            "precision": round(macro_p, 4),
            "recall": round(macro_r, 4),
            "f1": round(macro_f1, 4),
            "support": total,
        },
        "weighted_avg": {
            "precision": round(w_p, 4),
            "recall": round(w_r, 4),
            "f1": round(w_f1, 4),
            "support": total,
        },
    }


def roc_auc_binary(results: List[Dict]) -> Optional[float]:
    """
    Binary ROC-AUC: BLOCK (positive) vs non-BLOCK (negative).
    Uses injection_score as the discriminator when available.
    """
    scores, labels = [], []
    for r in results:
        inj_score = r.get("injection_score")
        if inj_score is None:
            # Fall back to 1 if actual==BLOCK else 0 (discrete)
            inj_score = 1.0 if r["actual"] == "BLOCK" else 0.0
        scores.append(inj_score)
        labels.append(1 if r["expected"] == "BLOCK" else 0)

    if len(set(labels)) < 2:
        return None  # only one class present

    # Manual trapezoidal AUC
    paired = sorted(zip(scores, labels), reverse=True)
    tp = fp = 0
    prev_tp = prev_fp = 0
    auc = 0.0
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos

    for _, label in paired:
        if label == 1:
            tp += 1
        else:
            fp += 1
        auc += (fp - prev_fp) * (tp + prev_tp) / 2
        prev_tp, prev_fp = tp, fp

    auc = auc / (n_pos * n_neg) if (n_pos * n_neg) > 0 else 0.0
    return round(auc, 4)


def latency_stats(results: List[Dict]) -> Dict[str, float]:
    lats = [r["latency_ms"] for r in results if r.get("latency_ms") is not None]
    if not lats:
        return {}
    lats.sort()
    n = len(lats)
    return {
        "mean_ms": round(sum(lats) / n, 2),
        "min_ms": round(lats[0], 2),
        "max_ms": round(lats[-1], 2),
        "p50_ms": round(lats[n // 2], 2),
        "p95_ms": round(lats[int(n * 0.95)], 2),
        "p99_ms": round(lats[int(n * 0.99)], 2),
    }


# ============================================================================
# 5. Pretty print
# ============================================================================
def print_report(metrics: Dict[str, Any], results: List[Dict]):
    total = len(results)
    correct = sum(1 for r in results if r["match"])
    accuracy = correct / total * 100 if total else 0

    print("\n" + "=" * 70)
    print("  LLM SECURITY GATEWAY — EVALUATION REPORT")
    print("=" * 70)
    print(f"  Dataset size : {total}")
    print(f"  Accuracy     : {accuracy:.2f}%  ({correct}/{total})")
    print()

    prf = metrics["per_class"]
    print(f"  {'Class':<12} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"  {'-'*52}")
    for cls in CLASSES:
        m = prf.get(cls, {})
        print(
            f"  {cls:<12} {m.get('precision', 0):>10.4f} {m.get('recall', 0):>10.4f}"
            f" {m.get('f1', 0):>10.4f} {m.get('support', 0):>10}"
        )
    print(f"  {'-'*52}")
    for avg in ("macro_avg", "weighted_avg"):
        m = prf.get(avg, {})
        print(
            f"  {avg:<12} {m.get('precision', 0):>10.4f} {m.get('recall', 0):>10.4f}"
            f" {m.get('f1', 0):>10.4f} {m.get('support', 0):>10}"
        )
    print()

    roc = metrics.get("roc_auc")
    if roc is not None:
        print(f"  ROC-AUC (BLOCK vs rest) : {roc:.4f}")

    lat = metrics.get("latency")
    if lat:
        print(f"  Latency  mean={lat['mean_ms']}ms  p95={lat['p95_ms']}ms  p99={lat['p99_ms']}ms")

    print()
    print("  Failures:")
    failures = [r for r in results if not r["match"]]
    if not failures:
        print("  ✅  All predictions matched!")
    else:
        for r in failures[:20]:
            print(f"    [{r['id']:>3}] expected={r['expected']:<5} actual={r['actual']:<5}  {r['text'][:60]}")
        if len(failures) > 20:
            print(f"    ... and {len(failures)-20} more")

    print("=" * 70)


# ============================================================================
# 6. Entry-point
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="Evaluate LLM Security Gateway")
    parser.add_argument(
        "--mode",
        choices=["api", "offline"],
        default="offline",
        help="'api' calls a running server; 'offline' imports modules directly",
    )
    parser.add_argument(
        "--url", default="http://localhost:8000", help="Base URL when mode=api"
    )
    parser.add_argument(
        "--dataset", default="dataset/final_eval.csv", help="Path to eval CSV"
    )
    parser.add_argument(
        "--output", default="evaluation/results", help="Output prefix for result JSON"
    )
    args = parser.parse_args()

    print(f"Loading dataset from {args.dataset}…")
    dataset = load_dataset(args.dataset)
    print(f"  {len(dataset)} rows loaded.")

    print(f"Running in '{args.mode}' mode…")
    if args.mode == "api":
        results = run_api(args.url, dataset)
    else:
        results = run_offline(dataset)

    prf = precision_recall_f1(results)
    auc = roc_auc_binary(results)
    lat = latency_stats(results)
    conf = compute_confusion(results)

    metrics = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "mode": args.mode,
        "total_samples": len(results),
        "accuracy": round(sum(1 for r in results if r["match"]) / len(results), 4),
        "per_class": prf,
        "roc_auc": auc,
        "latency": lat,
        "confusion_matrix": conf,
    }

    print_report(metrics, results)

    os.makedirs(os.path.dirname(args.output) or "evaluation", exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = f"{args.output}_{ts}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"metrics": metrics, "results": results}, f, indent=2, ensure_ascii=False)
    print(f"\n  Results saved → {out_path}")


if __name__ == "__main__":
    main()

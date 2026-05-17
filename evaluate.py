import csv
import json
import yaml
import requests
import time
from collections import defaultdict

def load_config(path="config.yaml"):
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}

class Evaluator:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        cfg = load_config()
        pe_cfg = cfg.get("policy_engine", {})
        self.block_threshold = pe_cfg.get("injection_block_threshold", 0.75)
        self.mask_threshold = pe_cfg.get("pii_mask_threshold", 0.60)

    def analyze(self, text):
        try:
            r = requests.post(f"{self.base_url}/analyze", json={"text": text}, timeout=10)
            return r.json()
        except Exception as e:
            print(f"Error analyzing text: {e}")
            return None

def calc_metrics(tp, tn, fp, fn):
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
    return acc, prec, rec, f1

def main():
    evaluator = Evaluator()
    print(f"Loaded config: Block Threshold = {evaluator.block_threshold}, Mask Threshold = {evaluator.mask_threshold}")
    
    results_rule = []
    results_hybrid = []
    presidio_results = []
    language_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "missed": 0})
    
    print("Evaluating test cases from data/final_eval.csv...")
    try:
        with open("dataset/final_eval.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except Exception as e:
        print(f"Failed to load dataset: {e}")
        return

    for i, row in enumerate(rows):
        if i % 10 == 0:
            print(f"Processed {i}/{len(rows)} prompts...")
            
        prompt = row["prompt"]
        expected_policy = row["expected_policy"]
        lang = row["language"]
        attack_type = row["attack_type"]
        expected_entities = eval(row.get("expected_entities", "[]"))
        
        res = evaluator.analyze(prompt)
        if not res:
            continue
            
        decision = res.get("decision")
        pii_entities = [e.get("type") for e in res.get("pii_entities", [])]
        rule_score = res.get("rule_score", 0.0)
        
        # Injection metrics
        is_attack = expected_policy == "BLOCK"
        is_blocked_hybrid = decision == "BLOCK"
        is_blocked_rule = rule_score >= evaluator.block_threshold
        
        results_hybrid.append({
            "is_attack": is_attack,
            "is_blocked": is_blocked_hybrid
        })
        results_rule.append({
            "is_attack": is_attack,
            "is_blocked": is_blocked_rule
        })
        
        if is_attack:
            language_stats[lang]["total"] += 1
            if is_blocked_hybrid:
                language_stats[lang]["blocked"] += 1
            else:
                language_stats[lang]["missed"] += 1
                
        # PII metrics
        if expected_entities:
            presidio_results.append({
                "id": row["id"],
                "expected": expected_entities,
                "detected": pii_entities,
                "confidence": res.get("pii_confidence", 0.0)
            })

    # Hybrid Metrics
    h_tp = sum(1 for r in results_hybrid if r["is_attack"] and r["is_blocked"])
    h_tn = sum(1 for r in results_hybrid if not r["is_attack"] and not r["is_blocked"])
    h_fp = sum(1 for r in results_hybrid if not r["is_attack"] and r["is_blocked"])
    h_fn = sum(1 for r in results_hybrid if r["is_attack"] and not r["is_blocked"])
    h_acc, h_prec, h_rec, h_f1 = calc_metrics(h_tp, h_tn, h_fp, h_fn)
    
    # Rule Metrics
    r_tp = sum(1 for r in results_rule if r["is_attack"] and r["is_blocked"])
    r_tn = sum(1 for r in results_rule if not r["is_attack"] and not r["is_blocked"])
    r_fp = sum(1 for r in results_rule if not r["is_attack"] and r["is_blocked"])
    r_fn = sum(1 for r in results_rule if r["is_attack"] and not r["is_blocked"])
    r_acc, r_prec, r_rec, r_f1 = calc_metrics(r_tp, r_tn, r_fp, r_fn)
    
    print("\n" + "="*80)
    print("RULE-ONLY VS HYBRID COMPARISON")
    print("="*80)
    print(f"{'Metric':<20} | {'Rule-Only':<15} | {'Hybrid':<15}")
    print("-" * 56)
    print(f"{'Accuracy':<20} | {r_acc:<15.2f} | {h_acc:<15.2f}")
    print(f"{'Precision':<20} | {r_prec:<15.2f} | {h_prec:<15.2f}")
    print(f"{'Recall':<20} | {r_rec:<15.2f} | {h_rec:<15.2f}")
    print(f"{'F1 Score':<20} | {r_f1:<15.2f} | {h_f1:<15.2f}")
    print(f"{'False Positives':<20} | {r_fp:<15} | {h_fp:<15}")
    print(f"{'False Negatives':<20} | {r_fn:<15} | {h_fn:<15}")
    
    print("\n" + "="*80)
    print("PER-LANGUAGE ROBUSTNESS (Hybrid)")
    print("="*80)
    print(f"{'Language':<10} | {'Attacks':<10} | {'Blocked':<10} | {'Missed':<10} | {'Detection Rate'}")
    print("-" * 80)
    for lang, stats in language_stats.items():
        rate = (stats['blocked'] / stats['total']) * 100 if stats['total'] > 0 else 0
        print(f"{lang.upper():<10} | {stats['total']:<10} | {stats['blocked']:<10} | {stats['missed']:<10} | {rate:.1f}%")
        
    print("\n" + "="*80)
    print("PRESIDIO CUSTOMIZATION VALIDATION")
    print("="*80)
    print(f"{'ID':<4} | {'Expected Entities':<35} | {'Detected Entities':<35} | {'Confidence'}")
    print("-" * 80)
    for p in presidio_results[:15]: 
        exp_str = ", ".join(p['expected']) if p['expected'] else "None"
        det_str = ", ".join(p['detected']) if p['detected'] else "None"
        print(f"{p['id']:<4} | {exp_str:<35} | {det_str:<35} | {p['confidence']:.2f}")

if __name__ == "__main__":
    main()
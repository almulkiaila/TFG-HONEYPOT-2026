"""
evaluate_baseline.py — Standalone baseline evaluation of the
deterministic scoring engine (SO4).

Reuses the existing scoring functions from insider_profiler.py
directly — no reimplementation, no LLM, no database required.
"""

import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Reuse existing scoring functions directly ────────────────
from insider_profiler import (
    score_sophistication,
    score_efficiency,
    score_canary_intent,
    score_time_behavior,
)

CLASSIFICATION_THRESHOLD = 0.5


def compute_composite(commands, canaries_touched,
                      duration_seconds, previous_sessions):
    """
    Replicates the composite score from Equation eq:composite-impl
    but without lateral movement and web terminal dimensions,
    since those require live beacon data not available in the
    static evaluation dataset.
    Maximum attainable score here is therefore 0.75, not 1.0.
    """
    soph   = score_sophistication(commands)
    eff    = score_efficiency(commands, canaries_touched)
    can    = score_canary_intent(canaries_touched, commands)
    time_  = score_time_behavior(commands, duration_seconds)
    repeat = previous_sessions > 1

    composite = (
        soph   * 0.15
        + eff   * 0.10
        + can   * 0.35
        + time_ * 0.05
        + (0.10 if repeat else 0)
        # lateral_movement (0.15) and web_terminal (0.10) excluded:
        # no beacon data available in static dataset
    )
    return round(min(composite, 1.0), 2)


def classify(composite):
    return "malicious" if composite >= CLASSIFICATION_THRESHOLD else "negligent"


def main():
    with open(os.path.join(BASE_DIR, "test_sessions.json")) as f:
        dataset = json.load(f)

    results = []
    for session in dataset:
        composite = compute_composite(
            commands         = session["commands"],
            canaries_touched = session["canaries_touched"],
            duration_seconds = session["duration_seconds"],
            previous_sessions= session.get("previous_sessions", 0),
        )
        predicted = classify(composite)
        truth     = session["ground_truth"]["insider_type"]

        results.append({
            "id":        session["id"],
            "category":  session["category"],
            "truth":     truth,
            "predicted": predicted,
            "composite": composite,
            "correct":   predicted == truth,
        })

    # ── Metrics ──────────────────────────────────────────────
    total = len(results)
    tp = sum(1 for r in results if r["truth"] == "malicious" and r["predicted"] == "malicious")
    tn = sum(1 for r in results if r["truth"] == "negligent" and r["predicted"] == "negligent")
    fp = sum(1 for r in results if r["truth"] == "negligent" and r["predicted"] == "malicious")
    fn = sum(1 for r in results if r["truth"] == "malicious" and r["predicted"] == "negligent")

    accuracy  = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall    = tp / (tp + fn) if (tp + fn) else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr       = fp / (fp + tn) if (fp + tn) else 0

    # ── Per category ─────────────────────────────────────────
    by_cat = {}
    for r in results:
        cat = r["category"]
        by_cat.setdefault(cat, {"correct": 0, "total": 0})
        by_cat[cat]["total"] += 1
        if r["correct"]:
            by_cat[cat]["correct"] += 1

    # ── Print ─────────────────────────────────────────────────
    print("\n" + "="*55)
    print("  BASELINE (scoring engine only) — SO4 evaluation")
    print("="*55)
    print(f"\n{'ID':<12} {'Truth':<12} {'Predicted':<12} {'Score':<8} {'OK'}")
    print("-"*55)
    for r in results:
        mark = "✅" if r["correct"] else "❌"
        print(f"{r['id']:<12} {r['truth']:<12} {r['predicted']:<12} {r['composite']:<8} {mark}")

    print("\n" + "-"*55)
    print(f"  Accuracy:              {accuracy:.1%}  ({tp+tn}/{total})")
    print(f"  Precision (malicious): {precision:.1%}")
    print(f"  Recall (malicious):    {recall:.1%}")
    print(f"  F1-score:              {f1:.1%}")
    print(f"  False Positive Rate:   {fpr:.1%}")
    print(f"\n  Confusion matrix:")
    print(f"    TP={tp}  FN={fn}")
    print(f"    FP={fp}  TN={tn}")
    print(f"\n  Per category:")
    for cat, v in by_cat.items():
        acc = v["correct"] / v["total"]
        print(f"    {cat:<25} {v['correct']}/{v['total']}  ({acc:.1%})")
    print("="*55 + "\n")

    # ── Save JSON ─────────────────────────────────────────────
    output = {
        "accuracy":  round(accuracy, 3),
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
        "fpr":       round(fpr, 3),
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "by_category": {
            cat: {
                "correct":  v["correct"],
                "total":    v["total"],
                "accuracy": round(v["correct"] / v["total"], 3),
            }
            for cat, v in by_cat.items()
        },
        "per_session": results,
    }
    with open(os.path.join(BASE_DIR, "baseline_eval_results.json"), "w") as f:
        json.dump(output, f, indent=2)
    print("Saved → baseline_eval_results.json")


if __name__ == "__main__":
    main()
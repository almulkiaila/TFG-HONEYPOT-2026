"""
evaluate.py — Honeypot LLM analysis evaluation.

Loads labeled sessions from test_sessions.json, runs them through the LLM
analysis pipeline and compares predictions against ground truth.

Outputs:
  - eval_results.csv: per-session predictions, reasoning and latency
  - eval_metrics.json: aggregated metrics (accuracy, precision, recall, F1, FPR)
  - eval_confusion_matrix.csv: malicious vs negligent confusion matrix

Features:
  - Uses an isolated DB (honeypot_eval.db) to avoid polluting production data
  - Wipes the eval DB at start (each evaluation runs from a clean slate)
  - Automatic retry when the LLM returns empty / all-unknown output
  - Simulates prior sessions for repeat offenders declared in the dataset

Usage:
    python evaluate.py
    python evaluate.py --runs 3        # repeat each session 3 times (consistency)
    python evaluate.py --sessions 5    # only first 5 sessions (quick debug)
    python evaluate.py --keep-db       # don't wipe the eval DB between runs
    python evaluate.py --skip-stages   # skip attack-stage evaluation (faster)
"""

import argparse
import csv
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── ISOLATED DB: redirect BEFORE importing ssh_honeypot ──────────
# This is critical: ssh_honeypot imports db and insider_profiler, which
# build their DB path at import time. We must patch the paths first.
EVAL_DB = os.path.join(BASE_DIR, "honeypot_eval.db")

import db as honeypot_db
import insider_profiler as profiler

honeypot_db.DB_FILE = EVAL_DB
profiler.DB_FILE = EVAL_DB

from ssh_honeypot import run_session_summary, run_llm_analysis, LLM_MODEL

DATASET_FILE = os.path.join(BASE_DIR, "test_sessions.json")
RESULTS_CSV = os.path.join(BASE_DIR, "eval_results.csv")
METRICS_JSON = os.path.join(BASE_DIR, "eval_metrics.json")
CONFUSION_CSV = os.path.join(BASE_DIR, "eval_confusion_matrix.csv")


def reset_eval_db():
    """Delete the eval DB and reinitialize fresh tables."""
    if os.path.exists(EVAL_DB):
        os.remove(EVAL_DB)
        print(f"🗑️  Previous eval DB removed: {EVAL_DB}")
    honeypot_db.init_db()
    profiler.init_profiler_db()
    print(f"✨ Clean eval DB initialized: {EVAL_DB}\n")


def load_dataset():
    """Load dataset and sort so sessions with prior history come last."""
    with open(DATASET_FILE, "r") as f:
        data = json.load(f)
    return sorted(data, key=lambda d: d.get("previous_sessions", 0))


def simulate_prior_sessions(test_case):
    """
    Insert fake prior sessions in the DB so get_ip_history() returns the
    expected count. Simulates a repeat offender's history without having
    to run N real sessions beforehand.
    """
    n = test_case.get("previous_sessions", 0)
    if n <= 0:
        return
    ip = test_case["ip"]
    import sqlite3
    with sqlite3.connect(EVAL_DB) as conn:
        for i in range(n):
            fake_sid = f"prior_{test_case['id']}_{i}"
            fake_ts = datetime.now(timezone.utc).isoformat()
            # CORREGIDO: Eliminadas las columnas inexistentes attack_stage y risk_level
            conn.execute(
                "INSERT INTO commands (timestamp, ip, session_id, command, response) "
                "VALUES (?, ?, ?, ?, ?)",
                (fake_ts, ip, fake_sid, "ls", "(simulated prior)"),
            )


def evaluate_session(test_case, run_idx=0, max_retries=2):
    """Run a session through run_session_summary and return prediction + timing."""
    session = {
        "session_id": f"eval_{test_case['id']}_run{run_idx}_{uuid.uuid4().hex[:6]}",
        "ip": test_case["ip"],
    }
    simulate_prior_sessions(test_case)

    last_error = None
    elapsed = 0.0
    attempts = 0

    for attempt in range(max_retries + 1):
        attempts = attempt + 1
        start = time.time()
        try:
            result = run_session_summary(
                session=session,
                commands=test_case["commands"],
                canaries_touched=test_case["canaries_touched"],
                duration_seconds=test_case["duration_seconds"],
            )
            elapsed = time.time() - start

            if result is None:
                last_error = "run_session_summary returned None (missing `return event`?)"
                continue

            # If everything came back as unknown, the LLM either returned empty
            # or unparseable JSON. Retry before giving up.
            all_unknown = (
                result.get("insider_type") == "unknown"
                and result.get("risk_level") == "unknown"
                and result.get("attack_path") == "unknown"
            )
            if all_unknown and attempt < max_retries:
                last_error = "LLM returned all 'unknown'"
                print(f"\n   ⚠️  Retry {attempt+1}/{max_retries}", end=" ", flush=True)
                time.sleep(2)
                continue

            return {
                "predicted_insider_type": result.get("insider_type", "unknown"),
                "predicted_risk_level": result.get("risk_level", "unknown"),
                "predicted_training_level": result.get("recommended_training_level", 0),
                "insider_reasoning": result.get("insider_reasoning", "")[:200],
                "training_action": result.get("training_action", "")[:120],
                "composite_score": result.get("insider_composite_score", 0.0),
                "json_ok": not all_unknown,
                "elapsed_seconds": round(elapsed, 2),
                "attempts": attempts,
                "error": last_error if all_unknown else None,
            }
        except Exception as e:
            elapsed = time.time() - start
            last_error = str(e)
            continue

    return {
        "predicted_insider_type": "ERROR",
        "predicted_risk_level": "ERROR",
        "insider_reasoning": "",
        "training_action": "",
        "composite_score": 0.0,
        "json_ok": False,
        "elapsed_seconds": round(elapsed, 2),
        "attempts": attempts,
        "error": last_error,
    }


def evaluate_attack_stage(test_case, run_idx=0):
    """Evaluate run_llm_analysis (attack stage classification per N commands)."""
    session = {
        "session_id": f"eval_stage_{test_case['id']}_run{run_idx}",
        "ip": test_case["ip"],
    }
    start = time.time()
    try:
        result = run_llm_analysis(session, test_case["commands"])
        elapsed = time.time() - start
        if result is None:
            return {"attack_stage": "ERROR", "elapsed": elapsed}
        return {
            "attack_stage": result.get("attack_stage", "unknown"),
            "elapsed": round(elapsed, 2),
        }
    except Exception:
        return {"attack_stage": "ERROR", "elapsed": time.time() - start}


# ── Metrics ──────────────────────────────────────────────────────

def compute_metrics(results):
    """Compute accuracy, precision, recall, F1, FPR for insider_type."""
    valid = [r for r in results if r["predicted_insider_type"] in ("malicious", "negligent")]
    errors = [r for r in results if r["predicted_insider_type"] not in ("malicious", "negligent")]

    if not valid:
        return {
            "model": LLM_MODEL,
            "total_sessions": len(results),
            "valid_predictions": 0,
            "errors": len(errors),
            "error_msg": "No valid predictions — all were unknown/ERROR",
        }

    # Treat "malicious" as the positive class
    tp = sum(1 for r in valid if r["truth_insider_type"] == "malicious" and r["predicted_insider_type"] == "malicious")
    tn = sum(1 for r in valid if r["truth_insider_type"] == "negligent" and r["predicted_insider_type"] == "negligent")
    fp = sum(1 for r in valid if r["truth_insider_type"] == "negligent" and r["predicted_insider_type"] == "malicious")
    fn = sum(1 for r in valid if r["truth_insider_type"] == "malicious" and r["predicted_insider_type"] == "negligent")

    n = tp + tn + fp + fn
    accuracy = (tp + tn) / n if n else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0

    # Risk level: exact match and within-1-step match
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    risk_exact = risk_close = risk_total = 0
    for r in valid:
        if r["truth_risk_level"] in risk_order and r["predicted_risk_level"] in risk_order:
            risk_total += 1
            if r["predicted_risk_level"] == r["truth_risk_level"]:
                risk_exact += 1
            if abs(risk_order[r["predicted_risk_level"]] - risk_order[r["truth_risk_level"]]) <= 1:
                risk_close += 1

    latencies = [r["elapsed_seconds"] for r in results if r.get("elapsed_seconds")]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    json_ok_count = sum(1 for r in results if r.get("json_ok"))

    # Training level accuracy
    training_valid = [
        r for r in valid
        if isinstance(r.get("truth_training_level"), int)
        and isinstance(r.get("predicted_training_level"), int)
    ]
    training_correct = sum(
        1 for r in training_valid
        if r["predicted_training_level"] == r["truth_training_level"]
    )
    training_accuracy = (
        round(training_correct / len(training_valid), 3)
        if training_valid else 0
    )

    return {
        "model": LLM_MODEL,
        "total_sessions": len(results),
        "valid_predictions": len(valid),
        "errors": len(errors),
        "confusion_matrix": {
            "TP_malicious": tp,
            "TN_negligent": tn,
            "FP_false_alarm": fp,
            "FN_missed_attack": fn,
        },
        "accuracy": round(accuracy, 3),
        "precision_malicious": round(precision, 3),
        "recall_malicious": round(recall, 3),
        "f1_malicious": round(f1, 3),
        "false_positive_rate": round(fpr, 3),
        "risk_level_exact_accuracy": round(risk_exact / risk_total, 3) if risk_total else 0,
        "risk_level_within_1_step": round(risk_close / risk_total, 3) if risk_total else 0,
        "avg_latency_seconds": round(avg_latency, 2),
        "json_parse_success_rate": round(json_ok_count / len(results), 3),
        "training_level_accuracy": training_accuracy,
    }

def compute_per_category_accuracy(results):
    """Accuracy broken down by category (clear vs ambiguous)."""
    by_cat = {}
    for r in results:
        cat = r["category"]
        by_cat.setdefault(cat, {"correct": 0, "total": 0})
        by_cat[cat]["total"] += 1
        if r["predicted_insider_type"] == r["truth_insider_type"]:
            by_cat[cat]["correct"] += 1
    return {
        cat: {
            "correct": v["correct"],
            "total": v["total"],
            "accuracy": round(v["correct"] / v["total"], 3) if v["total"] else 0,
        }
        for cat, v in by_cat.items()
    }


# ── Main loop ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Honeypot LLM evaluation")
    parser.add_argument("--runs", type=int, default=1,
                        help="Number of times each session is evaluated (for consistency analysis)")
    parser.add_argument("--sessions", type=int, default=None,
                        help="Limit number of sessions (debug mode)")
    parser.add_argument("--skip-stages", action="store_true",
                        help="Skip attack-stage evaluation (faster)")
    parser.add_argument("--keep-db", action="store_true",
                        help="Do not wipe the eval DB between runs (accumulate history)")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  Honeypot evaluation with LLM: {LLM_MODEL}")
    print(f"{'='*60}\n")

    if not args.keep_db:
        reset_eval_db()
    else:
        print(f"⚠️  Keeping existing eval DB\n")

    dataset = load_dataset()
    if args.sessions:
        dataset = dataset[: args.sessions]

    print(f"📋 Sessions to evaluate: {len(dataset)}")
    print(f"🔁 Runs per session: {args.runs}")
    print(f"📊 Total LLM calls: ~{len(dataset) * args.runs * (1 if args.skip_stages else 2)}\n")

    all_results = []

    for i, test_case in enumerate(dataset, 1):
        print(f"\n[{i}/{len(dataset)}] {test_case['id']} ({test_case['category']})")
        print(f"   GT: insider={test_case['ground_truth']['insider_type']}, "
              f"risk={test_case['ground_truth']['risk_level']}, "
              f"stage={test_case['ground_truth']['attack_stage']}")
        if test_case.get("previous_sessions", 0) > 0:
            print(f"   📜 Simulating {test_case['previous_sessions']} prior sessions for this IP")

        for run in range(args.runs):
            print(f"   Run {run+1}/{args.runs}...", end=" ", flush=True)

            session_result = evaluate_session(test_case, run_idx=run)

            stage_result = {"attack_stage": "skipped", "elapsed": 0}
            if not args.skip_stages:
                stage_result = evaluate_attack_stage(test_case, run_idx=run)

            row = {
                "session_id": test_case["id"],
                "category": test_case["category"],
                "description": test_case["description"],
                "run": run + 1,
                "truth_insider_type": test_case["ground_truth"]["insider_type"],
                "truth_risk_level": test_case["ground_truth"]["risk_level"],
                "truth_attack_stage": test_case["ground_truth"]["attack_stage"],
                "predicted_insider_type": session_result["predicted_insider_type"],
                "predicted_risk_level": session_result["predicted_risk_level"],
                "predicted_training_level": session_result.get("predicted_training_level", 0),  # NEW
                "truth_training_level": test_case["ground_truth"].get("training_level", 0),  # NEW
                "predicted_attack_stage": stage_result.get("attack_stage", "skipped"),
                "composite_score": session_result.get("composite_score", 0.0),
                "json_ok": session_result["json_ok"],
                "attempts": session_result.get("attempts", 1),
                "elapsed_seconds": session_result["elapsed_seconds"],
                "insider_reasoning": session_result.get("insider_reasoning", ""),
                "training_action": session_result.get("training_action", ""),
                "error": session_result.get("error"),
            }

            insider_match = "✅" if row["predicted_insider_type"] == row["truth_insider_type"] else "❌"
            risk_match = "✅" if row["predicted_risk_level"] == row["truth_risk_level"] else "❌"
            print(f"insider={row['predicted_insider_type']} {insider_match} "
                  f"risk={row['predicted_risk_level']} {risk_match} "
                  f"({row['elapsed_seconds']}s, {row['attempts']} tries)")

            all_results.append(row)

    # ── Save detailed results CSV ────────────────────────────────
    if all_results:
        fieldnames = list(all_results[0].keys())
        with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_results)
        print(f"\n💾 Results → {RESULTS_CSV}")

    # ── Aggregate metrics ────────────────────────────────────────
    metrics = compute_metrics(all_results)
    per_cat = compute_per_category_accuracy(all_results)

    full_metrics = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": LLM_MODEL,
        "config": {"runs_per_session": args.runs, "total_sessions": len(dataset)},
        "overall": metrics,
        "by_category": per_cat,
    }
    with open(METRICS_JSON, "w") as f:
        json.dump(full_metrics, f, indent=2)
    print(f"📈 Metrics → {METRICS_JSON}")

    # ── Confusion matrix CSV ─────────────────────────────────────
    cm = metrics.get("confusion_matrix", {})
    with open(CONFUSION_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["", "Predicted_malicious", "Predicted_negligent"])
        writer.writerow(["Real_malicious", cm.get("TP_malicious", 0), cm.get("FN_missed_attack", 0)])
        writer.writerow(["Real_negligent", cm.get("FP_false_alarm", 0), cm.get("TN_negligent", 0)])
    print(f"🔲 Confusion matrix → {CONFUSION_CSV}")

    # ── Console summary ──────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  SUMMARY ({LLM_MODEL})")
    print(f"{'='*60}")
    print(f"  Total sessions:          {metrics['total_sessions']}")
    print(f"  Valid predictions:       {metrics['valid_predictions']}")
    print(f"  Errors:                  {metrics['errors']}")
    if metrics.get("valid_predictions", 0) > 0:
        print(f"")
        print(f"  Accuracy:                {metrics['accuracy']:.1%}")
        print(f"  Precision (malicious):   {metrics['precision_malicious']:.1%}")
        print(f"  Recall (malicious):      {metrics['recall_malicious']:.1%}")
        print(f"  F1 (malicious):          {metrics['f1_malicious']:.1%}")
        print(f"  False Positive Rate:     {metrics['false_positive_rate']:.1%}")
        print(f"")
        print(f"  Risk level (exact):      {metrics['risk_level_exact_accuracy']:.1%}")
        print(f"  Risk level (±1 step):    {metrics['risk_level_within_1_step']:.1%}")
        print(f"")
        print(f"  JSON parse success:      {metrics['json_parse_success_rate']:.1%}")
        print(f"  Avg latency:             {metrics['avg_latency_seconds']}s")
        print(f"")
        print(f"  Accuracy per category:")
        for cat, v in per_cat.items():
            print(f"    {cat:25s} {v['correct']:2d}/{v['total']:2d} ({v['accuracy']:.1%})")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
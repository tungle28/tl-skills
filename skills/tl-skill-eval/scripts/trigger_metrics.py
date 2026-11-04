#!/usr/bin/env python3
"""Trigger precision/recall/F1 from skill-creator run_eval.py output.

Usage: python trigger_metrics.py run_eval_output.json [--evals trigger_evals.json]
                                 [--threshold 0.5] [--json out.json]
--evals lets near_miss tags from the eval set be joined by query text.
"""
import argparse, sys, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import utf8_stdio  # noqa: E402


def compute(results, near_miss_queries, threshold):
    tp = fp = fn = tn = 0
    nm_total = nm_fp = 0
    flaky, misses = [], []
    for r in results:
        rate = r.get("trigger_rate")
        if rate is None:
            rate = r["triggers"] / max(r["runs"], 1)
        fired = rate >= threshold
        should = bool(r["should_trigger"])
        if 0 < rate < 1:
            flaky.append({"query": r["query"], "trigger_rate": round(rate, 2)})
        if should and fired: tp += 1
        elif should and not fired:
            fn += 1; misses.append({"type": "FN", "query": r["query"], "trigger_rate": round(rate, 2)})
        elif not should and fired:
            fp += 1; misses.append({"type": "FP", "query": r["query"], "trigger_rate": round(rate, 2)})
        else: tn += 1
        if not should and r["query"] in near_miss_queries:
            nm_total += 1
            nm_fp += int(fired)
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if prec is not None and rec is not None else None)
    return {
        "counts": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "total": len(results)},
        "precision": prec, "recall": rec, "f1": f1,
        "accuracy": (tp + tn) / len(results) if results else None,
        "near_miss_negatives": nm_total,
        "near_miss_fp_rate": nm_fp / nm_total if nm_total else None,
        "flaky_queries": flaky, "misclassified": misses,
        "threshold": threshold,
        "warnings": ([] if nm_total else ["No near_miss-tagged negatives; precision may be inflated by easy negatives"])
                    + ([f"Only {len(results)} queries; confidence is low"] if len(results) < 16 else []),
    }


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser()
    ap.add_argument("run_eval_output", type=Path)
    ap.add_argument("--evals", type=Path)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    data = json.loads(a.run_eval_output.read_text(encoding="utf-8"))
    results = data["results"] if isinstance(data, dict) else data
    nm = set()
    if a.evals:
        ev = json.loads(a.evals.read_text(encoding="utf-8"))
        ev = ev.get("evals", ev) if isinstance(ev, dict) else ev
        nm = {e["query"] for e in ev if e.get("near_miss")}
    res = compute(results, nm, a.threshold)
    if a.json:
        a.json.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    f = lambda x: "n/a" if x is None else f"{x:.2f}"
    print(f"precision {f(res['precision'])}  recall {f(res['recall'])}  F1 {f(res['f1'])}  "
          f"near-miss FP {f(res['near_miss_fp_rate'])}  flaky {len(res['flaky_queries'])}")
    for m in res["misclassified"]:
        print(f"  {m['type']} ({m['trigger_rate']}): {m['query'][:90]}")


if __name__ == "__main__":
    main()

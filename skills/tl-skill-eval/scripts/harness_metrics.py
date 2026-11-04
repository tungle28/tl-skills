#!/usr/bin/env python3
"""Metrics for audit/review/harness skills against a seeded-defect fixture.

Usage:
  python harness_metrics.py --ground-truth gt.json --runs f1.json f2.json f3.json \
      [--adjudication adj.json] [--cost cost.json] [--kloc 12.4] \
      [--line-tolerance 3] [--json out.json]

Outputs seeded recall (overall, must_find), precision / FP rate (adjudicated),
reproducibility (pairwise Jaccard, stable core), severity calibration (exact agreement,
quadratic-weighted kappa), cost per run / per KLOC, and the list of unadjudicated
unmatched findings to classify next.
"""
import argparse, sys, itertools, json, math, statistics as st
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import utf8_stdio  # noqa: E402

SEV = ["info", "low", "medium", "high", "critical"]
MIN_KAPPA_PAIRS = 8
SEV_ALIASES = {"informational": "info", "minor": "low", "moderate": "medium", "major": "high", "blocker": "critical"}


def norm_path(p):
    p = (p or "").replace("\\", "/").lower()
    while p.startswith("./"):  # not lstrip("./"): that also eats the dot of ".github/…"
        p = p[2:]
    return p


def norm_sev(s):
    s = (s or "").strip().lower()
    s = SEV_ALIASES.get(s, s)
    return s if s in SEV else None


def overlaps(f, g, tol):
    fs, fe = f.get("line_start") or 0, f.get("line_end") or f.get("line_start") or 0
    gs, ge = g.get("line_start") or 0, g.get("line_end") or g.get("line_start") or 0
    if not fs or not gs:  # file-level finding or GT: file match suffices
        return True
    return fs <= ge + tol and gs <= fe + tol


def cat_match(f, g):
    fc = (f.get("category") or "").lower()
    cats = {(g.get("category") or "").lower(), *[a.lower() for a in g.get("aliases", [])]}
    return fc in cats


def cat_score(f, g):
    """2 = the GT's own category, 1 = one of its aliases, 0 = neither."""
    fc = (f.get("category") or "").lower()
    if fc == (g.get("category") or "").lower():
        return 2
    return 1 if fc in {a.lower() for a in g.get("aliases", [])} else 0


def line_iou(f, g):
    """Overlapping lines / lines covered by either span (0 when they only touch within tolerance)."""
    fs, fe = f.get("line_start") or 0, f.get("line_end") or f.get("line_start") or 0
    gs, ge = g.get("line_start") or 0, g.get("line_end") or g.get("line_start") or 0
    if not fs or not gs:
        return 0.0
    inter = min(fe, ge) - max(fs, gs) + 1
    return max(inter, 0) / (max(fe, ge) - min(fs, gs) + 1)


# A location-only match (category neither the GT's nor an alias) needs real overlap and a finding
# that is specific to those lines: a whole-file "no tests" finding must not claim an N+1 defect that
# happens to sit inside that file, but a 6-line finding may claim the 1-line GT inside it.
LOCATION_ONLY_MAX_SPAN = lambda gt_span: max(3 * gt_span, 10)


def span(x):
    s = x.get("line_start") or 0
    return (x.get("line_end") or s) - s + 1 if s else 0


def candidate_score(f, g, tol):
    """Sortable score for pairing finding f with GT item g, or None when they can't match."""
    if norm_path(f.get("file")) != norm_path(g.get("file")) or not overlaps(f, g, tol):
        return None
    cs, iou = cat_score(f, g), line_iou(f, g)
    if cs == 0 and (iou == 0 or span(f) > LOCATION_ONLY_MAX_SPAN(span(g))):
        return None
    # Real line overlap outranks category: a finding on lines 15-23 belongs to the GT item on 18-23
    # (alias category), not to the one on 26-32 that only its tolerance reaches (own category).
    # Among overlapping pairs, a close fit (IoU >= 0.5) goes first, so a broad finding spanning two
    # GT items doesn't take the one another finding pins down exactly.
    return (int(iou > 0), int(iou >= 0.5), cs, iou)


def match_run(findings, gt, tol, adj, run_id):
    """Return {finding_id: gt_id | 'dup:<gt_id>' | 'fp' | 'valid_extra' | None}.

    Each GT item counts once per run. Pairing is global and best-first: all (finding, GT) candidates
    are ranked by real line overlap (vs tolerance only), close fit, category fit (own category >
    alias > none), then how much the lines overlap, so a finding takes
    the GT it matches best, not the first one within tolerance. A finding whose best candidate is a
    GT item already found in the run (by the matcher or by adjudication), with a category match, is
    'dup:<gt_id>', a restatement: it neither counts again nor needs adjudication. Location-only
    leftovers stay unmatched for the adjudicator (e.g. a stuck-row finding that sits on the lines of
    the double-execution defect but describes the swallowed-error one).
    """
    out, used = {}, set()
    for f in findings:  # adjudication overrides first
        d = adj.get(f"{run_id}:{f['id']}")
        if d:
            out[f["id"]] = d
            # "dup:<gt>" is a restatement: it leaves the GT free for the finding that states it.
            if d not in ("fp", "valid_extra") and not d.startswith("dup:"):
                used.add(d)
    open_findings = [f for f in findings if f["id"] not in out]
    cands = sorted(((s, i, f, g) for i, f in enumerate(open_findings) for g in gt
                    if (s := candidate_score(f, g, tol)) is not None),
                   key=lambda c: tuple(-x for x in c[0]) + (c[1],))
    best_any, best_tier = {}, {}
    for s, _, f, g in cands:
        if s[2]:  # dup: only on a category match; a location-only one may be a different defect
            best_any.setdefault(f["id"], g["id"])
        best_tier.setdefault(f["id"], s[0])
        # A restatement whose best GT is taken must not fall back to one it only reaches by tolerance (e.g. a second
        # token-logging finding claiming the validation defect two lines above via an alias).
        if f["id"] in out or g["id"] in used or s[0] < best_tier[f["id"]]:
            continue
        out[f["id"]] = g["id"]
        used.add(g["id"])
    for f in open_findings:
        if f["id"] not in out:
            b = best_any.get(f["id"])
            out[f["id"]] = f"dup:{b}" if b in used else None
    return out


def gt_of(m):
    """The GT id a match value credits, or None (fp, valid_extra, unmatched)."""
    if not m or m in ("fp", "valid_extra"):
        return None
    return m[4:] if m.startswith("dup:") else m


def key_of(f, m):
    if gt_of(m):
        return gt_of(m)
    ls = f.get("line_start") or 0
    return f"{norm_path(f.get('file'))}:{(f.get('category') or '').lower()}:{ls // 10}"


def weighted_kappa(pairs):
    k = len(SEV)
    if len(pairs) < 2:
        return None
    idx = {s: i for i, s in enumerate(SEV)}
    O = [[0] * k for _ in range(k)]
    for a, b in pairs:
        O[idx[a]][idx[b]] += 1
    n = len(pairs)
    ra = [sum(O[i]) for i in range(k)]
    cb = [sum(O[i][j] for i in range(k)) for j in range(k)]
    num = den = 0.0
    for i in range(k):
        for j in range(k):
            w = ((i - j) ** 2) / ((k - 1) ** 2)
            num += w * O[i][j]
            den += w * ra[i] * cb[j] / n
    return None if den == 0 else 1 - num / den


def mean_sd(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return {"mean": round(st.mean(xs), 4), "stddev": round(st.stdev(xs), 4) if len(xs) > 1 else 0.0,
            "min": round(min(xs), 4), "max": round(max(xs), 4)}


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser()
    ap.add_argument("--ground-truth", type=Path, required=True)
    ap.add_argument("--runs", type=Path, nargs="+", required=True)
    ap.add_argument("--adjudication", type=Path)
    ap.add_argument("--cost", type=Path)
    ap.add_argument("--kloc", type=float)
    ap.add_argument("--line-tolerance", type=int, default=3)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()

    gtd = json.loads(a.ground_truth.read_text(encoding="utf-8"))
    gt = gtd["items"]
    must = {g["id"] for g in gt if g.get("must_find")}
    gt_by_id = {g["id"]: g for g in gt}
    adj_doc = json.loads(a.adjudication.read_text(encoding="utf-8")) if a.adjudication else {}
    adj = adj_doc.get("decisions", {})

    per_run, run_keys, sev_pairs, unadj = [], [], [], []
    missed_must_counts = {m: 0 for m in must}
    for rp in a.runs:
        rd = json.loads(rp.read_text(encoding="utf-8"))
        rid = rd.get("run_id", rp.stem)
        fs = rd["findings"]
        m = match_run(fs, gt, a.line_tolerance, adj, rid)
        hit = {gt_of(v) for v in m.values() if gt_of(v)}
        tp = len(hit)
        dups = sum(1 for v in m.values() if v and v.startswith("dup:"))
        fp = sum(1 for v in m.values() if v == "fp")
        vx = sum(1 for v in m.values() if v == "valid_extra")
        un = [f for f in fs if m[f["id"]] is None]
        unadj += [{"key": f"{rid}:{f['id']}", "file": f.get("file"), "line_start": f.get("line_start"),
                   "category": f.get("category"), "severity": f.get("severity"), "title": f.get("title")} for f in un]
        judged = tp + fp + vx
        for mid in must - hit:
            missed_must_counts[mid] += 1
        for f in fs:
            g = m[f["id"]]
            if g in gt_by_id:
                a_s, b_s = norm_sev(f.get("severity")), norm_sev(gt_by_id[g].get("severity"))
                if a_s and b_s:
                    sev_pairs.append((a_s, b_s))
        run_keys.append({key_of(f, m[f["id"]]) for f in fs})
        per_run.append({
            "run_id": rid, "findings": len(fs), "tp": tp, "duplicates_of_tp": dups, "fp": fp, "valid_extra": vx,
            "unadjudicated": len(un),
            "seeded_recall": tp / len(gt) if gt else None,
            "must_find_recall": len(hit & must) / len(must) if must else None,
            "precision": (tp + vx) / judged if judged else None,
            "fp_rate": fp / judged if judged else None,
        })

    jacc = [len(x & y) / len(x | y) if (x | y) else 1.0 for x, y in itertools.combinations(run_keys, 2)]
    all_keys = set().union(*run_keys) if run_keys else set()
    need = math.ceil(len(run_keys) / 2)
    stable = sum(1 for k in all_keys if sum(k in s for s in run_keys) >= need)

    cost = None
    if a.cost:
        cd = json.loads(a.cost.read_text(encoding="utf-8"))
        toks = [r.get("tokens") for r in cd.get("runs", [])]
        secs = [r.get("seconds") for r in cd.get("runs", [])]
        cost = {"tokens": mean_sd(toks), "seconds": mean_sd(secs)}
        if a.kloc and cost["tokens"]:
            cost["tokens_per_kloc"] = round(cost["tokens"]["mean"] / a.kloc, 1)
            cost["seconds_per_kloc"] = round(cost["seconds"]["mean"] / a.kloc, 2) if cost["seconds"] else None

    agg = lambda k: mean_sd([r[k] for r in per_run])
    res = {
        "fixture": gtd.get("fixture"), "fixture_version": gtd.get("fixture_version"),
        "ground_truth_items": len(gt), "must_find_items": len(must), "runs": len(per_run),
        "adjudicator": adj_doc.get("adjudicator"),
        "seeded_recall": agg("seeded_recall"), "must_find_recall": agg("must_find_recall"),
        "precision": agg("precision"), "fp_rate": agg("fp_rate"),
        "reproducibility_jaccard": mean_sd(jacc) if jacc else None,
        "stable_core_share": round(stable / len(all_keys), 4) if all_keys else None,
        "severity": {
            "pairs": len(sev_pairs),
            "exact_agreement": round(sum(x == y for x, y in sev_pairs) / len(sev_pairs), 4) if sev_pairs else None,
            # kappa on a handful of pairs is noise, not calibration: report it as not measured
            "quadratic_kappa": (lambda k: round(k, 4) if k is not None else None)(
                weighted_kappa(sev_pairs) if len(sev_pairs) >= MIN_KAPPA_PAIRS else None),
            "over_rated": sum(SEV.index(x) > SEV.index(y) for x, y in sev_pairs),
            "under_rated": sum(SEV.index(x) < SEV.index(y) for x, y in sev_pairs),
        },
        "missed_must_find": {k: f"missed in {v}/{len(per_run)} runs" for k, v in missed_must_counts.items() if v},
        "cost": cost, "per_run": per_run, "unadjudicated_findings": unadj,
        "warnings": ([f"{len(unadj)} unmatched findings are unadjudicated; precision/FP exclude them"] if unadj else [])
                    + (["Fewer than 3 runs; reproducibility is weakly estimated"] if len(per_run) < 3 else [])
                    + (["No must_find items marked in ground truth"] if not must else [])
                    + ([f"Only {len(sev_pairs)} severity pairs (< {MIN_KAPPA_PAIRS}); kappa not measured"]
                       if 0 < len(sev_pairs) < MIN_KAPPA_PAIRS else []),
    }
    if a.json:
        a.json.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    g = lambda d: "n/a" if not d else f"{d['mean']:.2f}±{d['stddev']:.2f}"
    print(f"seeded recall {g(res['seeded_recall'])} | must-find {g(res['must_find_recall'])} | "
          f"precision {g(res['precision'])} | FP {g(res['fp_rate'])} | Jaccard {g(res['reproducibility_jaccard'])} | "
          f"kappa {res['severity']['quadratic_kappa']}")
    for k, v in res["missed_must_find"].items():
        print(f"  MUST-FIND MISS {k}: {v}")
    if unadj:
        print(f"  {len(unadj)} unadjudicated findings -> classify in adjudication.json and re-run")


if __name__ == "__main__":
    main()

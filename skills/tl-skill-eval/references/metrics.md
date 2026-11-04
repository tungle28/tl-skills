# Metric definitions and interpretation

## Contents
1. Lint
2. Trigger
3. Quality
4. Harness
5. Cost
6. Common interpretation mistakes

## 1. Lint
- **errors**: violations of hard limits (name, description length, SKILL.md count/frontmatter,
  sub-agent frontmatter). Any error ⇒ verdict cannot be PASS.
- **warnings**: heuristics from Anthropic's authoring guidance. They are prompts for review,
  not proof of a defect.
- **tokens_est**: load cost in three tiers. The description is always in context, the body loads on
  every trigger, and references/agents load on demand. chars/4 is an estimate (Vietnamese and code
  cost more): use it to compare versions of the same skill, not as an absolute number.
- **family duplication**: share of a skill's sentences (≥ 12 words) that also appear in a sibling
  skill. Above ~15%, the shared text costs tokens twice and drifts apart over time.
- **sibling overlap**: Jaccard of description content words. It does not measure trigger accuracy.
  It points at which skills to draw near-miss queries from.

## 2. Trigger
Per query, trigger rate = triggers / runs; "triggered" if rate ≥ threshold (default 0.5).
- **Precision** = TP / (TP + FP) — when it fires, is it the right skill?
- **Recall** = TP / (TP + FN) — when it should fire, does it?
- **F1** = harmonic mean.
- **Near-miss FP rate** = FP among `near_miss` negatives / count of near-miss negatives.
  The most informative number for skills that overlap with siblings.
- **Flaky queries**: 0 < rate < 1. Many flaky queries ⇒ description is borderline, not wrong.

Claude tends to under-trigger, so low recall is the common failure; fix with more explicit
triggers in the description, then re-measure on held-out queries.

## 3. Quality (from skill-creator benchmark.json)
- **pass_rate (mean ± sd)** per configuration, **delta** = with_skill − baseline.
- Treat a delta as meaningful only if it exceeds roughly the pooled stddev; with 3 runs
  per config, small deltas are noise.
- **Non-discriminating assertions** (pass in both configs) must be excluded or hardened
  before trusting the delta.
- **Cost delta** (time, tokens): a skill that adds +5% pass rate for +200% tokens may not be
  worth it; report both.

## 4. Harness (class B)
Matching: a finding can match a ground-truth item in the same file (normalized path) whose line
range overlaps within tolerance (default ±3 lines) and whose category or an alias matches. Without
a category match it needs real line overlap and a finding no wider than max(3 × GT span, 10) lines,
so a whole-file finding can't claim a defect inside the file. Pairs are assigned best-first across
the run: real overlap before tolerance-only, close fit (IoU ≥ 0.5), the GT's own category before an
alias, then IoU. Each ground-truth item matches at most one finding per run; a finding whose best
match is a GT item already found in the run (by the matcher or by adjudication), with a category
match, is labelled `dup:<GT id>` — a restatement, reported as `duplicates_of_tp` and left out of
TP, FP and precision, so it needs no adjudication. Location-only leftovers stay unmatched for the
adjudicator.

- **Seeded recall** = matched GT / total GT (mean across runs). Report `must_find` recall
  separately — missing a critical seeded defect matters more than a minor one.
- **Precision** = (TP + valid_extra) / total findings. `valid_extra` requires adjudication.
- **FP rate** = fp / total findings. Unadjudicated unmatched findings are reported as
  `unadjudicated` and excluded from both — never silently counted as FP or TP.
- **Reproducibility** = mean pairwise Jaccard over finding keys across runs.
  Key = matched GT id, else `file:category:line_bucket` (bucket = 10 lines).
  **Stable core** = share of distinct keys appearing in ≥ ceil(N/2) runs.
  Low Jaccard with high recall ⇒ the skill finds things but not consistently; users will
  see different reports each run.
- **Severity calibration** on TPs: exact agreement and quadratic-weighted Cohen's kappa over
  an ordinal scale (info < low < medium < high < critical). Kappa < 0.4 ⇒ prioritization
  in the report is unreliable even if detection is good. Below 8 TP pairs, kappa is reported
  as not measured (a kappa over 2–3 pairs is noise); exact agreement and the over/under counts
  are still shown.

## 5. Cost
Tokens and wall-clock per run; per KLOC for code-scanning skills. Compare with baseline.
Watch for super-linear growth across fixture sizes — a sign the harness doesn't chunk.

## 6. Common interpretation mistakes
- Treating a high pass rate as skill value without looking at the baseline.
- Tuning and scoring on the same cases (overfit). Use held-out cases for the verdict.
- Counting every non-seeded finding as FP on real code.
- Comparing runs across different models; record the model in metadata.
- Reading a single run. LLM variance is large; N≥3.
- Averaging away a critical miss. Always surface `must_find` misses by name.

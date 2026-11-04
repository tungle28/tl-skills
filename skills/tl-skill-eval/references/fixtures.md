# Building fixtures for harness / audit skills

## Contents
1. Fixture types
2. Seeding defects
3. ground_truth.json
4. Normalizing skill output
5. Adjudication
6. Keeping fixtures honest

## 1. Fixture types
- **Synthetic mini-repo** (1–5 KLOC): fast, fully known ground truth. Good for recall,
  reproducibility, cost. Weak on realism.
- **Real repo slice, held out**: a repo or module never used while writing the skill.
  Ground truth is partial, so precision needs adjudication. Good for realism.
- **Clean control**: a repo region with no seeded defects. Measures false-alarm rate
  directly; a good skill should produce few or no high-severity findings there.

Use at least the synthetic repo plus one of the others for a verdict.

## 2. Seeding defects
- Seed 10–30 defects across the skill's declared categories, with a spread of severity
  and difficulty (obvious, needs cross-file reasoning, needs business-logic context).
- Mark 3–8 as `must_find` — the ones whose miss would make the skill unfit for purpose.
- Vary surface form: a defect detectable by grep teaches nothing about semantic review.
- For security skills, seed only in throwaway fixture code, never in real deployments;
  describe the defect pattern (e.g. missing ownership check on GET /orders/{id}) rather
  than shipping working exploit payloads.
- Record each seed immediately in ground truth; reconstructing later is error-prone.

## 3. ground_truth.json
See the schemas reference file. Minimum per item: `id`, `file`, `line_start`, `line_end`, `category`,
`severity`, `must_find`. Add `aliases` for categories the skill may name differently
(e.g. `idor` ↔ `broken-access-control`).

Write `severity` by applying **the skill's own rubric** to each seed, in the skill's vocabulary, then
map it with the same table used for the skill's output (section 4). A ground truth written on a finer
scale than the skill's (5 levels against `blocker/major/minor/nit`) measures the scale gap, not
calibration: tl-code-review showed kappa 0.16 and "23 over-rated" against author labels, and
0.38 with 0 over-rated once an independent labeler applied the skill's rubric. Have someone who has
not seen the skill's output do the labeling.

## 4. Normalizing skill output
Harness skills write reports in their own format. Convert each run's report into
`findings_run<i>.json` with a small script or a subagent. Keep the original report next
to it. Paths relative to repo root, forward slashes. Map the skill's severity vocabulary
to info/low/medium/high/critical and document the mapping.

## 5. Adjudication
After a first `harness_metrics.py` pass, the output lists unmatched findings. Classify
each as `fp`, `valid_extra`, or map it to a GT id if the matcher missed it (e.g. line
drift). Save as `adjudication.json` and re-run. Prefer an adjudicator that did not run
the skill (grader subagent or the user) and record who it was.

## 6. Keeping fixtures honest
- Never tune the skill while looking at the held-out fixture's ground truth.
- When a real-world miss is reported, add a seeded variant to the synthetic fixture
  (regression test), and rotate a fresh held-out fixture periodically.
- Version fixtures with the skill; scorecards reference the fixture version.

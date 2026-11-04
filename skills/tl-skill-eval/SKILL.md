---
name: tl-skill-eval
description: Measure and evaluate how well an Agent Skill performs and produce an evidence-backed scorecard with a verdict and prioritized fixes. Covers static lint against official authoring limits, trigger accuracy (precision/recall incl. near-miss queries), output quality vs a no-skill or previous-version baseline, and for audit/harness skills also seeded-defect recall, false-positive rate, run-to-run reproducibility, severity calibration and cost. Delegates run execution, grading and description optimization to skill-creator. Use whenever the user wants to evaluate, benchmark, score, compare or regression-check a skill, or asks whether a skill is worth it or triggers correctly, even without saying "eval" — e.g. "đo hiệu năng skill", "đánh giá skill", "chấm điểm skill", "so sánh 2 phiên bản skill".
---

# Skill Eval

Evaluate a skill the way you would evaluate any software component: against a baseline,
with repeated runs, on held-out data, and with numbers that can be recomputed.
The output is a **scorecard** (see "Scorecard" below), not a vibe check.

Division of labour with **skill-creator**:
- skill-creator = *execution engine* (spawn with-skill/baseline runs, grade assertions,
  aggregate `benchmark.json`, run the trigger eval, optimize the description).
- tl-skill-eval = *measurement design + metrics + verdict* (what to measure for this kind of
  skill, extra harness metrics skill-creator doesn't have, gates, scorecard, what to fix).

**Scripts count, agents judge**: every number in the scorecard comes from a script over files in the
workspace. Agents write eval sets, run the skill, and adjudicate. `S=<this skill's dir>/scripts`.
All scripts are stdlib Python and read and write UTF-8 explicitly, so Vietnamese eval sets work on Windows.

Don't re-implement what skill-creator already does. Locate it cheaply: if the session's skill list
has it (e.g. `anthropic-skills:skill-creator`), load it with the Skill tool. Otherwise look in
`~/.claude/skills/skill-creator/`, `.claude/skills/skill-creator/` and
`~/.claude/plugins/**/skill-creator/`. Never `find /`: it takes minutes on a large or Windows disk.
If found, read its SKILL.md before Phase 2–3 and use its scripts and JSON schemas unchanged, so
outputs stay compatible with its eval viewer. If not found, follow the manual fallbacks noted per phase.

## Phase 0 — Scope the evaluation

Establish, from the conversation first and by asking only for what's missing:

1. **Target**: path to the skill folder (and, for version comparison, the old version).
2. **Skill class** — decides which metric families apply:

| Class | Examples | Metric families |
|---|---|---|
| A. Single-output | doc/report generator, post writer, formatter | Lint, Trigger, Quality |
| B. Harness / audit | tl-code-refactor, tl-security-audit, tl-architecture-doc, tl-seo-audit | Lint, Trigger, Quality, **Harness** |
| C. Workflow / tool-use | deploy, data pipeline, form filling | Lint, Trigger, Quality (assert on side effects/files) |

3. **Question being answered** — this sets the baseline:
   - "Is this skill worth having?" → baseline = `without_skill`.
   - "Is v2 better than v1?" → baseline = snapshot of v1 (`old_skill`).
   - "Did my change break anything?" → regression run vs the last accepted scorecard.
4. **Environment capability** — read `references/environments.md`. It decides which
   metrics can be measured *for real* and which must be marked `not measured`.
   Never fill an unmeasurable metric with an estimate.

Create the workspace **outside any skills tree**: `<repo>/.skill-evals/<skill-name>/iteration-N/`
(add `.skill-evals/` to `.git/info/exclude`). A workspace next to the skill would sit inside
`skills/`, and skill-creator's `old_skill/` snapshot contains a SKILL.md with the same name.
Installers that scan for SKILL.md then find a duplicate skill and stop.

## Phase 1 — Static lint (always, cheap)

```bash
python $S/lint_skill.py <skill-path> [<module-path> …] --siblings <skills-root>   [--name-prefix tl-] --json <workspace>/lint.json
```

Pass a whole **skill family** (a core plus its modules) in one call, and the lint also reports
sentences duplicated across them. Shared text belongs in one reference that the others point to.
`--siblings` lists the other skills whose descriptions overlap most. Those are the near-miss sources
for Phase 2. `info.tokens_est` gives the load cost: description (always in context), body (every
trigger), on-demand references. It is an estimate: report it as such, and compare versions with it,
never with absolute claims.

Checks hard limits (name format/length, description ≤1024 chars, single SKILL.md) and
authoring heuristics (body ≤500 lines, reference depth = 1, TOC on files >100 lines,
first/second-person descriptions, time-sensitive wording, Windows paths, missing
"when to use" signal, a `WORKFLOW.md` user guide that git shows is older than SKILL.md). The guide is
for people, so it is left out of the load cost. Errors block a PASS verdict; warnings go into recommendations.
Also read the SKILL.md yourself for things a script can't judge: code or markup the agent must
re-derive every run from prose (a candidate for `scripts/` or `assets/`), contradictions between a
skill and its modules, terminology drift,
instructions that restate what the model already knows, over-constrained steps on tasks
that need judgment (or vice versa). Record these as reviewer notes, clearly labelled as
judgment, not measurement.

## Phase 2 — Trigger accuracy

1. Build `trigger_evals.json` (skill-creator schema: `{"query", "should_trigger"}`), plus an
   optional `"near_miss": true` tag on hard negatives. Aim for 20+: ~10 positive with varied
   phrasing (formal, casual, Vietnamese/English if the user works bilingually, implicit
   need), ~10 negative that are *near misses* — sharing keywords but needing a different
   tool or a competing skill. Easy negatives inflate precision and test nothing. Build the
   near misses from the `siblings` list in `lint.json`: for each overlapping skill, write queries
   that belong to it (e.g. a plain diff review for `tl-security-audit` versus an HTML security report
   for `tl-architecture-doc-security`). Evaluate both skills of an overlapping pair with the same
   queries, since a fix to one description can steal triggers from the other.
   Queries must be substantive: Claude doesn't consult skills for trivial one-step asks,
   so trivial positives fail regardless of description quality. A query that names repo state
   (staged changes, a commit, a folder, a file) must run in a `--cwd` that has that state; build a
   small trigger fixture for it. In an empty cwd Claude checks, finds nothing and answers, and
   the miss belongs to the fixture, not the description.
2. Show the set to the user for a quick review before running — bad queries produce a
   misleading score.
3. Run: if `claude -p` is available, use skill-creator's `run_eval.py`
   (`--runs-per-query 3`) and save its JSON output. On Windows, or when the target skill is
   already installed (its real copy then competes with run_eval's temporary one), use
   `python $S/run_trigger.py` instead: install the version under test, and it measures the
   installed skill and writes the same JSON. Without `claude -p`, mark trigger metrics
   `not measured` (self-simulation by the same model that knows the skill is biased).
4. Compute:
   ```bash
   python $S/trigger_metrics.py <run_eval_output.json> --evals trigger_evals.json --json <workspace>/trigger.json
   ```
   Reports precision, recall, F1, near-miss FP rate, and flaky queries (0 < trigger rate < 1).
5. Before blaming the description, read each false negative's `fired` list: a run that ended after
   a few `git`/`Glob` calls usually means the cwd lacked what the query named.
   If trigger F1 is still below gate, recommend skill-creator's description optimization loop
   (`run_loop.py`, held-out split) — don't hand-edit the description as the first move.
   On Windows, run it through `python $S/run_loop_compat.py --hide-installed -- <run_loop args>`
   (see `references/environments.md`).

## Phase 3 — Output quality vs baseline

Use skill-creator's run/grade/aggregate workflow as-is (with-skill and baseline launched
together, assertions graded with evidence, `aggregate_benchmark.py` → `benchmark.json`,
analyst pass, eval viewer for the human). Your added responsibilities:

- **Eval set design**: 3–10 realistic prompts covering the main path, edge cases, and at
  least one case where the skill should *decline or stay narrow*. Keep 30–40% of cases
  held out from iteration so the final score isn't overfit to cases the author tuned on.
- **Assertion hygiene**: each assertion must be able to fail. After the run, list
  non-discriminating assertions (pass in both configs) and drop or harden them; they
  inflate pass rate without measuring the skill.
- **Runs per config ≥3** when the environment supports it; single runs can't separate
  signal from variance.

Without subagents (claude.ai), a real baseline isn't possible: run the cases with the skill
only, grade them, and mark `quality_delta` as `not measured`.

**Record every prompt you dispatch**, baseline included, in `<workspace>/prompts/` (format in
`references/schemas.md`). Write the file *before* launching the run, with the exact text sent
and how it was sent (subagent type, or the `claude -p` flags and disabled tools). The baseline
prompt shows what a plain request looks like when it already gets a good result. Reviewing it
next to the with-skill result is the quickest way to see what the skill adds and which of its
instructions a well-written prompt makes unnecessary. A baseline number without its prompt
can't be reviewed or reproduced.

## Phase 4 — Harness metrics (class B only)

Read `references/fixtures.md` before starting; it covers how to build seeded-defect
fixtures, ground truth, and the adjudication step. In short:

1. A fixture repo with **known seeded defects** (`ground_truth.json`) — ideally one
   small synthetic repo plus one real repo slice the skill was never tuned on.
2. Run the skill N≥3 times on the same fixture, each in a fresh subagent. Normalize each run with
   `python $S/normalize_findings.py <run-output> --run-id run<i> --out <workspace>/findings_run<i>.json`.
   It auto-detects `tl-architecture-doc` (`.src` dir), `tl-code-refactor` and `tl-security-audit`
   (`merged.json`). It drops findings the skill's own verifier rejected, and records its severity
   mapping. Other skills need a small converter to the schema in `references/schemas.md`.
3. **Adjudicate** unmatched findings as `fp` or `valid_extra` (a real issue that wasn't
   seeded). This step matters: on real code, "not in ground truth" ≠ false positive.
   Dispatch **`tl-skill-eval-adjudicator`** (it never ran the skill; fallback: `general-purpose`
   reading `agents/tl-skill-eval-adjudicator.md`) or ask the user. State who adjudicated in the scorecard.
4. Compute:
   ```bash
   python $S/harness_metrics.py --ground-truth ground_truth.json \
     --runs findings_run1.json findings_run2.json findings_run3.json \
     [--adjudication adjudication.json] [--cost cost.json] [--kloc 12.4] \
     --json <workspace>/harness.json
   ```
   Outputs: seeded recall (overall and for `must_find` items), precision,
   FP rate, pairwise Jaccard reproducibility + stable-core share, severity exact agreement
   + quadratic-weighted kappa, tokens/time per run and per KLOC.
5. For "is the harness worth it", also run the plain baseline (Claude asked to review the
   same fixture without the skill) through the same pipeline and compare. Save the with-skill,
   baseline and grader prompts in `prompts/`, as in Phase 3.

## Phase 5 — Scorecard and verdict

```bash
python $S/scorecard.py --workspace <workspace> --skill-name <name> \
  [--gates references/default_gates.json] --out <workspace>/scorecard.md
```

It merges `lint.json`, `trigger.json`, skill-creator's `benchmark.json`, and
`harness.json` (whichever exist), lists `prompts/`, applies gates, and writes the scorecard. Then replace the italic placeholder under its
`## Verdict, top fixes, confidence` heading (do not add a second heading) with, in your own words:

- **Verdict**: PASS / CONDITIONAL / FAIL, with the one or two metrics driving it.
- **Top 3 fixes**, ordered by expected impact per effort, each tied to a metric
  (e.g. "near-miss FP 40% → add exclusion clause for X; re-run trigger eval").
- **Confidence and gaps**: sample sizes, what was `not measured`, who adjudicated,
  whether evals were held out. Separate measured facts from your interpretation.

Default gates are proposals in `references/default_gates.json`; tell the user they're
starting points and should be tuned per skill (a security skill should weight recall
over precision; a content skill the reverse). Tune them in `gates.json` in the skill's eval root
(the workspace's parent), `{"gates": [{"metric", "fail", "warn", "reason"}]}`. `scorecard.py`
merges it by metric and prints every override with its reason. Change a gate only after a
measurement shows the default does not fit (e.g. with-skill at ceiling on a discriminating set).
Metric definitions and interpretation
pitfalls: `references/metrics.md`.

## Hand-off back to skill-creator

If the user wants to act on the results: description problems → skill-creator description
optimization; instruction/output problems → skill-creator improve loop with this eval set
and baseline. Re-run tl-skill-eval afterwards and diff scorecards (`--previous
<old_scorecard.json>`) to confirm the fix moved the metric without regressing others.

## Scorecard

Always deliver: `scorecard.md` (human) + `scorecard.json` (machine, for regression diffs),
plus the raw inputs in the workspace so every number can be recomputed, including
`prompts/`. The scorecard lists those prompts and warns when a baseline was measured
without one.

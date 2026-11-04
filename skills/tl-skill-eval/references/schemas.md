# Schemas used by tl-skill-eval

Trigger eval inputs/outputs and quality benchmark files use **skill-creator's schemas
unchanged** (`trigger_evals.json` = list of `{query, should_trigger}`; run_eval output;
`benchmark.json`). tl-skill-eval adds an optional `near_miss: true` field to trigger items.

## ground_truth.json
```json
{
  "fixture": "shop-api-synthetic",
  "fixture_version": "1.2",
  "items": [
    {"id": "GT-01", "file": "src/orders/controller.ts", "line_start": 40, "line_end": 52,
     "category": "idor", "severity": "high", "must_find": true,
     "aliases": ["broken-access-control"], "note": "no ownership check"}
  ]
}
```

## findings_run<i>.json
```json
{
  "run_id": "run1",
  "findings": [
    {"id": "F-001", "file": "src/orders/controller.ts", "line_start": 44, "line_end": 44,
     "category": "broken-access-control", "severity": "critical", "title": "..."}
  ]
}
```
`normalize_findings.py` also writes `source_format`, `source` and `severity_map` (the skill's
vocabulary → info/low/medium/high/critical). Quote the map in the scorecard when severity
calibration is discussed. `tl-architecture-doc` categories are `security` / `performance` /
`integrity` / `smell`, so give GT items `aliases` for them.

## adjudication.json
Keys are `"<run_id>:<finding_id>"`; value is `"fp"`, `"valid_extra"`, a GT id, or `"dup:<GT id>"` for a restatement of a GT item
another finding in the same run already states (it neither counts again nor takes that GT).
```json
{"adjudicator": "grader-subagent", "decisions": {"run1:F-007": "fp", "run2:F-003": "GT-04"}}
```

## cost.json
```json
{"runs": [{"run_id": "run1", "tokens": 182000, "seconds": 410}]}
```

## prompts/<config>[-<case>].md
Write one file for each distinct prompt dispatched: `baseline-eval-1.md`, `with_skill-eval-1.md`,
`harness-baseline.md`, `grader.md`, and so on. Repeated runs of the same prompt share one file.
The front matter comes first; after it, put the exact text that was sent, unedited and not
summarised:
```markdown
---
config: baseline            # baseline | without_skill | old_skill | with_skill | grader | other
case: harness-fixture-v1    # eval id or fixture name
runner: claude -p           # or: subagent general-purpose
flags: --disallowedTools "Skill Agent Task" --permission-mode acceptEdits
cwd: <fixture copy>
result: tokens 2.3M, $3.39, 731 s, 18/18 GT captured    # optional; fill in after the run
---
<verbatim prompt>
```
`scorecard.py` lists these files. It warns when a baseline was measured but none of the
files has `config` set to baseline, without_skill or old_skill (or a file name starting
with one of them).

## scorecard.json
Written by `scorecard.py`: `{skill, generated_at, sections: {lint, trigger, quality,
harness}, prompts: [{file, config, case, runner, result}], gates: [{metric, value, op,
threshold, status}], verdict_hint}`.
`verdict_hint` is mechanical (any error/fail ⇒ FAIL, any warn ⇒ CONDITIONAL); the final
verdict in scorecard.md is yours, with reasoning.

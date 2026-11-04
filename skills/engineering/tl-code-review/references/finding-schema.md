# Finding schema & severity rubric

Every reviewer writes exactly one file: `<DIR>/findings/<shard-id>.json` (`DIR` is the run folder).
`aggregate_findings.py` validates it; malformed findings are dropped and reported,
so follow the schema exactly.

```json
{
  "shard": "S01",
  "coverage": {
    "reviewed": ["src/Orders/OrderService.cs", "src/Orders/OrderController.cs"],
    "skipped": "src/Orders/Legacy/*.cs — generated code",
    "lenses_applied": ["correctness", "data", "concurrency"]
  },
  "positives": ["Idempotency key checked before charging the card"],
  "findings": [
    {
      "id": "S01-001",
      "file": "src/Orders/OrderService.cs",
      "line_start": 142,
      "line_end": 150,
      "severity": "blocker",
      "category": "concurrency",
      "confidence": "high",
      "in_diff": true,
      "title": "Balance check and debit are not atomic (lost update)",
      "evidence": "var acc = await _db.Accounts.FindAsync(id);\nif (acc.Balance >= amount) { acc.Balance -= amount; ... }",
      "why": "Two concurrent withdrawals both read the old balance and both pass the check.",
      "scenario": "Balance 100; two requests of 80 arrive within ms → both succeed, balance -60.",
      "suggestion": "Use a conditional UPDATE ... WHERE Balance >= @amount and check rows affected, or add a rowversion concurrency token and retry on DbUpdateConcurrencyException."
    }
  ]
}
```

## Field rules

| Field | Rule |
|---|---|
| `id` | `<shard>-<nnn>`, unique within the shard |
| `file`, `line_start/end` | NEW-side line numbers (post-change file). Point at the defect, not the whole method |
| `severity` | `blocker` / `major` / `minor` / `nit` — see rubric below |
| `category` | One of: `correctness`, `error-handling`, `concurrency`, `data`, `security`, `performance`, `api-contract`, `backward-compat`, `resilience`, `config-ops`, `tests`, `test-quality`, `ui-state`, `maintainability`, `observability` |
| `confidence` | `high` = you traced the code path and are sure; `medium` = likely, depends on something you couldn't fully see; `low` = suspicion worth a human look |
| `in_diff` | Diff modes only: `true` if the defect is introduced or made reachable by the change; `false` if it pre-exists untouched. Non-diff modes: always `true` |
| `evidence` | ≤ 10 lines of the actual code. No evidence → it's a hunch, lower confidence |
| `why` | The consequence in production terms (wrong money, data loss, 500s, security exposure), not "violates best practice" |
| `scenario` | Required for `blocker`/`major`: concrete input/interleaving that triggers it |
| `suggestion` | Specific fix; a short code snippet is welcome. Mention trade-off if the fix has one |

## Severity rubric

The question is **"what happens in production if this ships?"**, not how ugly the code is.

| Severity | Meaning | Examples |
|---|---|---|
| 🔴 **blocker** | Will (or very plausibly can) cause incorrect results, data loss/corruption, security exposure, outage, or breaks callers/contract. Merge must wait | Race on balance update; missing authz check on new endpoint; migration drops a column still read by running pods; `async void` swallowing exceptions in a payment flow; float for money |
| 🟠 **major** | Real defect with bounded impact, or a latent issue likely to bite under realistic conditions | N+1 on a list endpoint; missing timeout/retry on external call; unhandled edge case (empty list, null) reachable from API; no test for new branching business logic |
| 🟡 **minor** | Correct but fragile, confusing, or inconsistent; costs maintainers later | Misleading name; duplicated logic that will drift; weak log message on an error path |
| ⚪ **nit** | Taste/style. Only when `report_nits` is true for the shard, max 3 per shard | Formatting a linter would catch, wording |

Calibration rules:
- Don't inflate. Three real majors beat ten speculative blockers — false positives train people to ignore the review.
- A linter/compiler already flags it → don't report (it's in the Tooling section).
- A minor needs a consequence in *this* code, as it is used today. Leave out hardening wishes whose
  only trigger is someone misconfiguring the system later (e.g. "no check that MIN <= MAX"),
  speculative deploy or infrastructure concerns you can't see in the repo, a missing rollback when
  the repo has no rollback convention, and index/sort tweaks without evidence of a hot path. In
  evaluation these were almost all of the false positives. Low-confidence minors: leave them out.
  This does not cover N+1 queries, unbounded result sets (no limit/pagination) or I/O inside
  loops: those are concrete and belong in the `performance` lens (usually major, see the rubric).
- Before calling documented behaviour a bug, check README/CONTRIBUTING/ADRs: if the project says
  it is intended (e.g. "a failed recurring transfer stops the series"), it is not a finding unless
  it breaks a rule the same docs state.
- Deep security issues (taint flows, IDOR across tenants, crypto) → report what you see at `security` category, and add `"suggestion": "... run the tl-security-audit skill for a full pass"` rather than doing the deep audit here.
- Large refactoring opportunities → one `maintainability` minor pointing to the `tl-code-refactor` skill, not a list of 15 smells.

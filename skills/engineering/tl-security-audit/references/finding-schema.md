# Finding schema — contract between reviewers, verifier and `findings.py`

`findings.py merge` validates reviewer output: findings missing a required field are dropped and
listed under "schema problems"; invalid enum values are coerced to conservative defaults.

## Language
Free-text fields (`title`, prose in `evidence`, `attack_scenario`, `impact`, `fix`, `reason`,
`note`, `notes`, narrative, surface.md) are written in the run language (`lang` in `state.json`,
passed to agents as `LANG`). Machine-read values stay exactly as specified here: ids, paths, line
numbers, field names, enum values, OWASP codes, CWE ids, rule ids, code excerpts. Markdown
headings in surface.md / narrative stay in English (report headings are English by design).

## Quoting code in free text
Put every code or markup excerpt in a backtick code span. `findings.py` wraps stray `<`/`>` tokens
in code spans when it renders `report.md` (`md_text`), but do not rely on it. Never copy secrets or
PEM key headers; describe them ("PEM private-key header") with `file:line`. Convert `report.md` to
HTML with raw HTML disabled (e.g. `--safe`); `render_html.py` already escapes it.

## Shard reviewer output — `<RUN_DIR>/findings/<SHARD_ID>.json`
```json
{
  "reviewer": "shard-reviewer",
  "shard": "S03",
  "files_reviewed": ["src/Api/Controllers/AccountsController.cs"],
  "not_reviewed": ["scripts/deploy.sh — referenced by CI but not in the repo"],
  "notes": "optional",
  "triage": [
    {"hit_id": "H0012", "verdict": "confirmed", "finding_id": "S03-001", "reason": "..."},
    {"hit_id": "H0013", "verdict": "dismissed", "reason": "test fixture password for local container"}
  ],
  "gates": [
    {"hit_id": "H0040", "verdict": "clear", "reason": "OwnerPolicy applied at controller level (AccountsController.cs:18)"},
    {"hit_id": "H0041", "verdict": "candidate", "finding_id": "S03-002", "reason": "..."},
    {"hit_id": "H0042", "verdict": "unknown", "reason": "service lives in another repo"}
  ],
  "findings": [ { "...": "finding object" } ]
}
```
- Every scanner **finding hit** in the shard gets a `triage` entry: `confirmed` (fold into a finding
  and reference it), `duplicate` (same as another confirmed finding), or `dismissed` (with reason).
  Untriaged hits appear in the report as `untriaged` — visible, never silently dropped.
- Every **gate** in the shard gets an answer: `clear` (say where the control is), `candidate`
  (write a finding) or `unknown` (say what could not be established).

## Surface reviewer output
`<RUN_DIR>/findings/surface.json` — same shape with `"reviewer": "surface-reviewer"`, `"shard": null`,
finding ids `SURF-NNN`; plus `<RUN_DIR>/surface.md` (see `security-architecture.md`).

## Finding object
Keep the prose fields short (budgets below). Every word is generated on each run and rendered in the
report; length adds minutes and cost, and readers skim long entries.

| Field | Req | Meaning |
|---|---|---|
| `id` | yes | `<SHARD_ID>-NNN` or `SURF-NNN`, unique in the run |
| `kind` | yes | `vulnerability` (exploitable weakness) · `weakness` (unsafe practice, exploitability unconfirmed) · `hardening` (defense-in-depth gap) · `cost-risk` (runaway loop / billing / quota) |
| `category` | no | check id (e.g. `access-control`, `business-logic`) or rule id |
| `owasp` | yes | `A01`…`A10` (OWASP Top 10:2025) |
| `cwe` | no | `CWE-639` |
| `title` | yes | ≤ 14 words, names the flaw and where: "Statement download does not check account ownership" |
| `file`, `line_start`, `line_end` | yes | primary location, real line numbers — never estimated |
| `evidence` | yes | what was seen: ≤ 3-line excerpt or precise description, plus one sentence naming the places checked for a control (≤ 60 words in all). Secrets redacted. |
| `attack_scenario` | yes | 1–2 sentences: who (anonymous / any user / tenant user / admin / insider), what they control, what they achieve — in words. **No payloads, exploit code or step-by-step weaponization.** |
| `impact` | yes | one sentence: concrete consequence for this system (data, money, availability, compliance) |
| `fix` | yes | 1–2 sentences: the change to make; point at an existing correct pattern in the codebase when there is one |
| `severity` | yes | `critical` · `high` · `medium` · `low` · `info` — see `severity-rubric.md` |
| `confidence` | yes | `high` (source→sink/absence traced across files) · `medium` (read the code, not every caller) · `low` (pattern-level) |
| `requires` | no | attacker position: `none` (unauthenticated) · `user` · `privileged` · `internal` (network position/insider) · `local` · `unknown` |
| `from_hits` | no | scanner hit ids folded into this finding |
| `trace` | no | taint flow from the scanner hit: `[{"role": "source|step|call|enter|sink", "file", "line", "text"}]` — keep it when folding a taint hit into a finding |
| `related` | no | `[{"file": "...", "line_start": 10, "line_end": 20}]` |

## Verifier output — `<RUN_DIR>/verification/<BATCH_ID>.json`
```json
{"batch": "V01", "verdicts": [
  {"id": "S03-002", "verdict": "confirmed", "note": "checked route group, service and query; no owner filter"},
  {"id": "S01-004", "verdict": "rejected", "note": "EF global query filter on TenantId (AppDbContext.cs:61)"},
  {"id": "SURF-002", "verdict": "adjusted", "severity": "medium", "requires": "privileged", "note": "admin-only route"}
]}
```
`adjusted` may change `severity`, `confidence`, `requires`, `kind`. A `note` is always required.

## Narrative — `<RUN_DIR>/narrative.json`
`{"executive_summary": "markdown", "roadmap": "markdown"}` — content in the user's language.

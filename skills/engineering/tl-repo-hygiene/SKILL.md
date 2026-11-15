---
name: tl-repo-hygiene
description: Repo hygiene pass over an entire project folder — code, config, CI, docs and agent instructions (AGENTS.md, CLAUDE.md, skills, sub-agents) — for anything broken, inconsistent, inefficient, technically inaccurate, wasting tokens or no longer needed. Fixes what is certain and writes an HTML report of the rest for the user to approve or reject. Use when the user asks to review, clean up or health-check the whole project or repo, or its skills and agent instructions — including trimming or de-duplicating AGENTS.md and CLAUDE.md — e.g. "rà soát toàn bộ dự án", "kiểm tra project xem có gì lỗi/thừa", "dọn dẹp repo", "vệ sinh repo", "audit project", "repo hygiene", "audit AGENTS.md và skills", "AGENTS.md và CLAUDE.md trùng nhau, cắt bớt". Not for a code-only refactor review (tl-code-refactor), a security audit (tl-security-audit) or a diff/PR review (tl-code-review).
license: MIT
---

# Repo Hygiene

Go through the whole project folder and find everything that is broken, inconsistent, inefficient, technically inaccurate, wasting tokens or no longer needed — including skills, sub-agent definitions and agent instruction files. Fix what you are certain about. List the rest with a recommendation, and hand the user an HTML report to approve.

Reply and write the report in the language the user writes in. Keep code, paths and identifiers as they are.

## Outputs

All in `<project>/.repo-hygiene/` (add `.repo-hygiene/` to `.git/info/exclude` so it never shows up as untracked; do not edit `.gitignore` for this):

- `scan.json` — mechanical scan from `scripts/scan.py`
- `findings.json` — everything you fixed and everything you propose (schema below)
- `report.html` — rendered from `findings.json` by `scripts/render_report.py`

Never commit. The user reviews the diff and commits.

## Step 0 — Scope and safety

1. Root = the folder the user named, else the current working directory. If the user names a sub-area ("chỉ skills", "only docs"), audit only that.
2. Run `git status --porcelain`. Auto-fixes need a clean undo path:
   - Clean git tree → proceed.
   - Uncommitted changes, or not a git repo → tell the user and ask whether to (a) audit only, no fixes, or (b) fix anyway. Default to (a) if they do not answer.
3. Skip vendored and generated content: `node_modules`, `vendor`, `dist`, `build`, `.venv`, lock files, `graphify-out`, minified files, and anything the scan marks `generated`. Mention the skip in the report.

## Step 1 — Mechanical scan

```bash
python <skill-dir>/scripts/scan.py <root> --out <root>/.repo-hygiene/scan.json
```

It lists tracked files with size and a token estimate, finds the agent instruction files, and reports mechanical issues: Python files that do not compile, invalid JSON, broken relative Markdown links, SKILL.md / agent frontmatter problems (missing `name`/`description`, name not matching the folder, description over 1024 chars, body over 500 lines), byte-identical duplicate files, tracked junk (`__pycache__`, `.pyc`, `.DS_Store`…) and very large always-loaded instruction files. Each item still needs a look before you act on it — the scan finds candidates, you confirm them.

## Step 2 — Read the project

Build a map before judging: README, manifests (`package.json`, `pyproject.toml`, `*.csproj`…), CI workflows, scripts, and **every** instruction file the scan listed under `instruction_files`. Read instruction files in full — they are a main target, not background.

Small project (roughly ≤100 tracked source files): also read every source file in full, not only the ones the scan or a search points to. Many real defects sit in code no instruction mentions (an async route that never handles errors, a type package a stated rule needs, a helper the docs reference but nobody created), and a small repo is cheap to read whole.

Large project (roughly >300 tracked source files, or >40 instruction files): if your agent can run sub-agents, split by top-level area (about 4 areas of similar size) and brief each one with:

- its area and that it is **read-only** (it may run tests and read-only commands, never edit);
- the six lenses (Step 3) and the fix-now rules (Step 4);
- the output: a JSON array written to `.repo-hygiene/agent-<area>.json`, each item shaped like a `proposals` entry (Step 5) without `id`, plus `certain_fix`: `null`, or `{"file", "old", "new"}` with `old` copied exactly from the file and occurring once — only when the item meets every fix-now rule.

Merge the arrays yourself: drop duplicates (two areas often report the same cross-cutting issue), then for every `certain_fix` read the evidence yourself before applying it — a sub-agent's certainty is a candidate, not a verdict. Look for the same mistake elsewhere (the same wrong command often appears in two files) and fix those too. Otherwise work area by area and keep notes in `.repo-hygiene/notes.md` so a long session survives context loss.

## Step 3 — Look through six lenses

| Lens (`category`) | What to look for |
|---|---|
| `broken` | Code that cannot run or build; scripts calling missing files, flags or commands; dead links; config keys nothing reads; tests that cannot pass; instructions that reference files, tools, scripts or agents that do not exist. Also behaviour bugs you can trace in the code: a handler that ignores a message or event it is sent, state that is never reset or cleaned up, an error path that leaves a request hanging, a path written at install time that breaks after an update. |
| `inconsistent` | The same fact stated differently in two places (versions, paths, counts, names, commands); docs, READMEs, architecture pages or code comments that describe behaviour the code no longer has; AGENTS.md vs CLAUDE.md vs skills contradicting each other; naming convention breaks; one skill describing another's behaviour wrongly. |
| `inefficient` | Redundant work in scripts or CI (repeated installs, no caching where it matters, serial steps that could be one); slow algorithms on real hot paths; workflows that make the agent do by hand what a script already does. |
| `inaccurate` | Technically wrong or outdated claims: deprecated APIs, retired model IDs, wrong standard versions (e.g. OWASP), wrong CLI flags, wrong defaults. Verify against the source or official docs before calling it wrong; if you cannot verify, say "needs verification" in the proposal. |
| `token-waste` | Always-loaded files (AGENTS.md, CLAUDE.md, skill descriptions, sub-agent prompts) carrying content the agent does not need every time: rules duplicated across files, things the model already does by default, long examples, history/changelogs, big tables that belong in an on-demand reference file; skills whose triggers overlap so two load for one request; descriptions longer than needed to trigger. Estimate the saving in tokens. |
| `obsolete` | Files, scripts, skills, agents, config, dependencies or docs nothing uses any more; superseded versions left next to the new one; finished plans still described as active. Prove "unused" with a search for references, not by guessing. |

For skills and sub-agents specifically, also check: frontmatter valid; `name` matches folder; description says what it does and when to use it (and when not, if it has near neighbours); every referenced `scripts/`, `references/` file exists; instructions match what the scripts actually accept; no two skills claim the same trigger without a tie-break.

**Docs against code.** For every document that describes how the project works (README, `docs/**` including HTML architecture pages, AGENTS.md, skill bodies, header comments of main modules), list its concrete claims — what a component does, when something happens, which files or state exist where, names, counts, commands — and check each against the code. A claim the code contradicts is an `inconsistent` finding with both locations as evidence. This is where most real-repo drift hides; do not skip it for long or generated-looking docs.

**Behaviour in main code paths.** For each entry point and long-lived component (servers, request/message handlers, CLIs, installers, background loops), read the handling code and ask: is every message or event it receives handled, does every error path end the request, is state that grows ever cleaned up, does cleanup on exit or cancel actually run? Report what you can trace to specific lines. This is not a diff review — leave style and refactoring opinions to tl-code-refactor and change-by-change review to tl-code-review.

When the project has more than about 15 source files and your agent can run sub-agents, run this behaviour pass in parallel even if the project is not "large": split the source into 2–4 areas by top-level folder or component (e.g. runtime, CLI/server, importers, tests and helpers), and give each sub-agent its file list, the questions above, the `broken` lens, the "concrete defect only" rule below, and the `proposals` item format with `file:line` evidence. They are read-only. Do the docs-against-code pass yourself, since it needs the whole picture, then merge their findings, drop duplicates and confirm each one by reading the cited lines before you report it.

Report only issues with a concrete defect you can point to. General hardening or style wishes ("add input validation", "more tests", "fail fast on empty config") are not findings unless something in the project states or needs them (a rule in AGENTS.md, a documented contract, an input that already breaks). Leave them out, or mention at most the one most useful under `low`.

## Step 4 — Decide: fix now or propose

Fix now only when **all** of these hold:

1. You read the evidence yourself (not only the scan output).
2. There is one obviously right correction (typo, wrong path, broken link to a file that moved, stale count, a frontmatter `name` that differs from its folder, a flag name that the script clearly defines differently). The text you change must be wrong, not just approximate or incomplete: leave "~2 MB" alone when the file is 2.4 MB, and leave a usage comment alone when it lists fewer options than exist. Every edit must correspond to a finding you record; no drive-by wording or comment refreshes.
3. It does not change intended behaviour, public interfaces, data, or what an instruction means — it only makes it correct.
4. You can verify it right after (the link resolves, the script runs, the test passes, the check is green).

Always **propose** instead of fixing when the change would:

- delete or move files, folders, skills, agents, rules or dependencies (even if clearly unused);
- shorten or rewrite instructions for token savings (the user decides what their agents must keep);
- touch CI/CD, release/publish config, security settings, secrets, migrations or anything in production paths;
- choose between two conflicting sources of truth;
- rest on a domain claim you could not verify.

Apply each fix, verify it, and record it. If verification fails, revert that fix and turn it into a proposal. Run the project's own cheap checks afterwards (tests, lint, link/consistency scripts) and record the result in `checks_run`.

## Step 5 — Write findings.json and render

```json
{
  "project": "repo-name",
  "root": "absolute path",
  "generated": "2026-01-01T10:00:00",
  "language": "vi",
  "summary": "2–4 sentences: overall health and the most important items.",
  "skipped": ["node_modules", "dist"],
  "checks_run": [{"command": "pytest -q", "result": "pass", "note": "48 passed"}],
  "fixed": [{
    "id": "F1", "category": "broken", "severity": "high", "title": "Short title",
    "files": ["path/to/file.md:12"],
    "what": "What was wrong and what you changed.",
    "verify": "How you confirmed it is right."
  }],
  "proposals": [{
    "id": "P1", "category": "token-waste", "severity": "high",
    "title": "Short title",
    "evidence": [{"file": "AGENTS.md", "line": 40, "note": "duplicates CLAUDE.md:12-30"}],
    "problem": "What is wrong and why it matters.",
    "recommendation": "Concrete change you would make.",
    "effort": "S", "risk": "What could go wrong if applied.",
    "saving_tokens": 1200
  }]
}
```

`severity` (on fixes and proposals alike — rate a fixed issue by how bad it was before the fix): `high` (broken now, misleads agents, or costs a lot every session), `medium`, `low`. `effort`: `S`/`M`/`L`. `saving_tokens` only for `token-waste`. Order proposals by severity, then by value.

```bash
python <skill-dir>/scripts/render_report.py <root>/.repo-hygiene/findings.json --out <root>/.repo-hygiene/report.html
```

The renderer validates the JSON and escapes all text; fix any error it prints and rerun. Do not hand-write the HTML.

## Step 6 — Hand over

Tell the user, briefly: how many fixes were applied (and that they are uncommitted, with `git diff --stat`), how many proposals by severity, the 3 most important ones, and the report path. If your environment can open or publish an HTML page for the user, do so; otherwise give the absolute path.

In the report the user marks each proposal **Approve / Reject / Later**, may add a note, and presses **Copy decisions**; that copies a Markdown list (with the report path and each item's location) to paste back. When they paste it, apply only the approved items and verify each. Do not edit `findings.json` for them: record each outcome, in the report language, with

```bash
python <skill-dir>/scripts/record_fix.py <root>/.repo-hygiene/fixes.json --id P12 --status fixed|partial|failed \
  --what "What you changed, or why not" --verify "Command: result" --files a.md,b.py [--commit <sha>]
```

`fixed` needs `--verify`; a fix you had to revert is `failed` with the reason. Then rerun `render_report.py` (it reads `fixes.json` next to `findings.json`): fixed proposals move to "Fixed automatically" with what changed and how it was verified, partial or failed ones stay open with the attempt shown on the card, and a "Fix results" block under the summary counts them. Add any new checks you ran to `checks_run`.

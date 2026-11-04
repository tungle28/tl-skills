# Cross-run memory

What a later run reuses from earlier ones: triage decisions the user approved, and a diff against
the previous run. Code: `scripts/memory.py` (the triage file format is in its docstring).

## Triage file
`<repo>/.security-audit/triage.yml` holds one entry per approved decision:
`false-positive` or `accepted-risk`.

- **Matching.** An entry matches a finding in the same file, of the same class (rule/check id, CWE
  or OWASP), whose code lines overlap the entry's (at least half of the shorter set), while every
  line the entry recorded still exists in the file. Whitespace is ignored, so line shifts and
  reformatting still match. Once any of those lines is edited the entry stops applying, and the
  site is reviewed again.
- **Scan.** A false positive is skipped at scan time for the scanner rules listed in the entry
  (`category`, `rules`). Reviewers never see that hit; it is counted under "Suppressed".
- **Merge.** A finding that matches gets status `known-fp` or `accepted-risk`. It is not verified,
  not counted, and not in the HTML findings table. The report lists it under "Known from Earlier Runs".
- **Expiry.** An entry with `until` in the past is ignored. `--accept` sets it to 180 days ahead
  unless `--until` is given. Entries without `reason` or `lines` are ignored.
- **Privacy.** `accepted-risk` entries describe real weaknesses. Tell the user so before the first
  entry is written, so they can keep the file out of a public repository.

## Learning step (Phase 7, after `run finish`)
`run finish` prints a `learn:` hint when the run rejected or dismissed anything.

1. `python3 $S/scripts/memory.py learn --run-dir $RUN_DIR` writes `triage_proposed.yml`. It has one
   proposal per verifier-rejected finding and per reviewer-dismissed scanner hit, with the
   verifier's or reviewer's reason. It leaves out (and prints) two kinds of rejection. One is a
   rejection whose reason says it duplicates another finding. The other is a rejected finding
   whose lines are covered by a live finding. Neither is a verdict on the code, and learning one
   would hide the real finding. An entry learned from a dismissed scanner hit
   (`match: rule`) applies only to that scanner rule.
2. Show the user the proposals (id, location, reason) in one short list. Ask which to keep.
3. Apply only those: `memory.py learn --run-dir $RUN_DIR --apply P001,P003` (or `all`).
4. For a live finding the user accepts as a risk:
   `memory.py learn --run-dir $RUN_DIR --accept <id> --reason "<who accepted it and why>" [--until YYYY-MM-DD]`.

Never apply without asking: the file is in the user's repository and hides findings from later
reports. `memory.py list --root <repo>` shows the entries and which have expired.

## Diff against the previous run
`report` compares with a baseline run. By default that is the newest finished run of the same repo
in `.security-run/`; `init --baseline <RUN_DIR>` picks another.

- Each current finding is tagged `new` or `persisting` (with the baseline id).
- "Changes Since Previous Run" lists baseline findings that are gone:
  - *code changed*: probably fixed. Confirm it.
  - *code unchanged, reported differently (id)*: a finding with the same category this run is in
    the same file or carries the same CWE, so the flaw was probably merged, split or anchored
    elsewhere. Check that the named finding covers it.
  - *code unchanged, not reported*: probably missed this time. Re-check it; it is also listed under
    Coverage Gaps.
  - *file removed*.
- A scoped run compares only the files in its scope.
- In the chat summary, report both kinds of gone findings, not only the fixed ones.

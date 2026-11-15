# Re-review, run comparison, baselines and cleanup

Read this when re-reviewing a changeset, comparing runs, using a baseline, or pruning old runs.
`$S` = the skill directory, `$RUN` = the current run folder.

## Re-review of a changeset already reviewed

New commits on the PR or branch, or fixes after a review: add `--since-run <run folder>` (or
`latest`) to `resolve_scope.py`. The scope is then only the commits after the head that run
reviewed; the manifest records `since_run`, and the report covers those commits only, so say so.

The script stops:
- when nothing was pushed since — tell the user; review from scratch only if they ask for one, and
  offer `--depth quick`;
- when the old head is no ancestor of the new one (rebased or force-pushed) — review the whole change.

Without `--since-run` the whole change is reviewed again, which is what "review again from scratch"
means.

## Compare runs

After Phase 5, when an earlier run of the same target exists, or when the user asks:

```bash
python3 $S/scripts/compare_runs.py --new $RUN --lang <BCP-47>
```

It pairs the findings with the run before it (`--old <run>` to choose; `--list` shows all runs with
verdict and counts) and writes `$RUN/compare.md`: new findings, gone ones, kept ones with severity
changes. When both runs reviewed the same commits, a gone finding was not found again (review
variance), not fixed; the report says which case applies. Mention the counts in the summary.

## Baseline for recurring `full`/`layer` assessments

Run `aggregate_findings.py --write-baseline` once (written to `.code-review/baseline.json`, shared by
all runs), then `--baseline .code-review/baseline.json` shows only new findings. Say in the summary
that the baseline hides known issues.

## Cleaning up old runs

Old run folders are kept. Only when the user asks to clean them up: `compare_runs.py --prune <keep>`
lists the runs beyond the newest `<keep>` (the latest run is always kept); show the list, and add
`--confirm` after the user agrees. It removes each run's `head/` worktree from git too.

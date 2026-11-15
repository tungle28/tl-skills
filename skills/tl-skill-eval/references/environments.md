# What can be measured where

Mark anything the current environment can't measure as `not measured` in the scorecard.
A missing number is honest; a simulated one is misleading.

| Capability | Claude Code | Cowork | claude.ai |
|---|---|---|---|
| Static lint (`lint_skill.py`) | yes | yes | yes |
| Trigger eval via `claude -p` (`run_eval.py`, or `run_trigger.py` on Windows) | yes | yes | **no** |
| Description optimization loop (`run_loop.py`, or `run_loop_compat.py` on Windows) | yes | yes | **no** |
| Parallel with-skill + baseline runs (subagents) | yes | yes | **no** |
| Independent grader subagent | yes | yes | no (self-grade, flag as bias) |
| Eval viewer | browser | `--static` HTML | present results inline |
| Harness metrics (`harness_metrics.py`) | yes | yes | yes, if findings files exist |
| Token/time capture | from subagent task notifications | same | not available |

All scripts are stdlib Python and read and write UTF-8 explicitly. On Windows, call `python`
(or `py -3`) instead of `python3`. Frontmatter parsing accepts CRLF checkouts.

## Windows notes

- **Trigger eval:** skill-creator's `run_eval.py` polls the subprocess pipe with `select()`,
  which Windows supports only for sockets, so it fails. Use `scripts/run_trigger.py`: it reads
  the stream line by line, calls the real `claude.exe` behind the npm `.cmd` shim (the shim
  re-parses arguments through cmd.exe and mangles quotes and non-ASCII queries), and writes
  run_eval-compatible JSON for `trigger_metrics.py`.
  A trigger is the Skill tool naming the skill exactly, or a Read of an installed `<skill>/SKILL.md`
  outside `--cwd`. A SKILL.md inside `--cwd` is project content (e.g. the skill being evaluated),
  so reading it neither counts nor ends the run.
  A run that makes `--max-tools` (default 15) other tool calls first counts as not triggered; at
  5, about 6% of real triggers were cut off because the model explored the repo first.
- **Description optimization:** `run_loop.py` calls the same `run_eval()`, and its
  `improve_description` starts `claude` without a shell, so the `.cmd` shim is not found.
  `scripts/run_loop_compat.py` runs skill-creator's own loop in UTF-8 mode with both calls
  swapped for portable ones. Arguments after `--` go to `run_loop.py`; pass `--timeout 150`,
  because the default 30 s is too short, and the wrapper raises anything lower to 120 s.
  Candidates are tested through a temporary command, so an installed copy of the skill would
  compete with them. The wrapper refuses to start until you pass `--hide-installed`. That flag
  moves the copy to `~/.claude/.tl-skill-eval-hidden/` for the run and restores it afterwards,
  including on the next start if a run was killed.
- **skill-creator scripts** such as `aggregate_benchmark.py` open files with the default code
  page (cp1252), and crash on Vietnamese `grading.json`. Run them with `PYTHONUTF8=1`.
- **No `claude` on PATH:** `npm i -g @anthropic-ai/claude-code`. `claude -p` reuses the
  credentials of an existing Claude Code login.

## Headless harness runs (`claude -p`)

Observed behaviour, not documented API, so re-check it on the installed Claude Code version:
- A `claude -p` run of a harness skill that waits on background sub-agents can end at a
  background-wait ceiling (about 600 s seen) before the harness finishes. Setting the env var
  `CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0` for the run avoided it; a cut-off run could be
  continued with `claude --resume <session_id>`.
- Set a cost cap before starting, and use a fixture larger than one context: on a small fixture a
  no-skill baseline can already find everything (ceiling effect), so the run only shows the
  harness's cost overhead.

## Detecting capabilities

- `which claude` → trigger eval and description loop possible.
- A subagent/Task tool in the tool list → baseline runs and independent grading possible.
- Neither → run lint + self-run quality cases + harness metrics on user-supplied reports,
  and recommend running the full evaluation in Claude Code.

## Bias notes to record in the scorecard

- **Self-execution bias**: when the same context that read tl-skill-eval also executes the
  target skill, it knows what is being tested. Prefer fresh subagents.
- **Self-grading bias**: grader == executor inflates pass rates. Prefer a grader subagent
  or programmatic checks.
- **Author-written evals**: cases written while tuning the skill overfit to it. Keep a
  held-out set and add real-world failures over time.

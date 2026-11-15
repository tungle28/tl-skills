# Fix playbook (mode `fix`, user-selected findings only)

1. **Preconditions:** clean working tree (`git status --porcelain` empty — the run dir is already
   hidden via `.git/info/exclude` by `init`; if `.security-run/` still shows up, add
   `/.security-run/` there rather than editing `.gitignore`); create a branch
   `security/fix-<run-id>`; build and tests green before changes (record the baseline). If tests are
   missing around the code, add a characterization test first for money/state/auth paths.
2. **Commit rules are known before the first change.** Inspect the repository's convention
   (`git log --oneline -20`, commitlint/commitizen config, `CONTRIBUTING.md`, `AGENTS.md`/`CLAUDE.md`)
   and any commit rule from the user or another installed skill (e.g. a commit skill requiring
   per-commit approval). If commits need approval, present the planned commits up front — one line
   per finding: id, files, draft message — and get explicit approval for that list (or for each
   commit as you reach it, if the user prefers). Never commit anything outside the approved list.
3. **Order:** secrets first (see below), then critical/high by priority, one finding per commit.
4. **Per finding:** apply the fix using the codebase's existing correct pattern where one exists;
   add a regression test that fails before and passes after (authorization: a test proving user A
   cannot access user B's resource; injection: a test with a hostile-but-harmless value asserting it
   is treated as data). Build + tests. Red → revert that finding completely — modified files with
   `git restore --staged --worktree -- <files>`, and delete files the change **created** (they show
   as `??` in `git status --porcelain`; `git restore` leaves them behind) — confirm the tree is clean
   again, log why, continue.
5. **Commit**, following the rules from step 2. Default format when the repository has no convention
   of its own: `fix(security): <summary> [<finding id>]`, summary in the repository's commit
   language. Never include secret values or exploit details in commits, messages or logs. Never use
   `--no-verify`; if a hook fails, fix the cause and create the commit again (no `--amend`).
6. **Secrets:** removing a secret from code does not revoke it. The fix commit moves it to
   configuration/secret store; the log tells the user to **rotate/revoke** the credential and decide
   about history rewriting (a destructive, coordinated operation — never done automatically).
7. **Do not** change security-relevant behaviour beyond the finding (e.g. tightening CORS for other
   origins) without asking; do not disable tests or linters to get green. Do not push or open a PR
   unless the user asks.
8. Write `<RUN_DIR>/fix/log.md` (run language): per finding — status, commit, test added, follow-ups
   (rotation, config changes in other repos, infra changes the code cannot make).
9. **Record each outcome for the report** right after its commit (or revert), in the run language:
   `python3 $S/scripts/record_fix.py <RUN_DIR>/fixes.json --id <finding id> --status fixed|partial|failed
   --what "<what changed, or why not>" --verify "<command: result>" --files <a,b> [--commit <sha>]`.
   `fixed` needs `--verify`; reverted means `failed` with the reason. Never put secret values in these
   texts. When the batch is done, run `render_html.py --run-dir <RUN_DIR>` again: fixed findings move to
   a "Fixed" section with what changed and how it was verified; partial/failed ones keep their card,
   with the attempt shown on it.

# Adding rules and checks

Three extension points, from cheapest to most powerful. All of them work without editing the
skill: put project-specific ones under `<repo>/.security-audit/` and they are picked up automatically.

| Want to catch | Use | Where |
|---|---|---|
| A recognizable line/shape (API call, config key, literal) | **pattern rule** (`type: finding`) | `rules/*.yml` or `<repo>/.security-audit/rules/*.yml` |
| A place where a reviewer must answer a question | **gate rule** (`type: gate`) | same |
| A class of flaw that needs reasoning across files | **review check** (markdown) | `checks/*.md` or `<repo>/.security-audit/checks/*.md` |
| Untrusted input reaching a dangerous call (dataflow, incl. cross-file) | **taint spec** (sources/sinks/sanitizers) | `rules/taint/<lang>.yml` or `<repo>/.security-audit/taint/*.yml` — see `taint-analysis.md` |
| Any other Semgrep-expressible rule | **Semgrep/OpenGrep rule** | `rules/semgrep/*.yml` or `<repo>/.security-audit/semgrep/` |

## Pattern rule
```yaml
rules:
  - id: cs-my-legacy-crypto            # unique; reuse an existing id to override it
    type: finding                      # default
    title: LegacyCrypto.Encrypt used
    languages: [csharp]                # any | csharp | js (=javascript+typescript, incl. .vue) | go | dart | sql | xml
                                       # aliases: web | dotnet | config | mobile (dart,kotlin,swift,java,xml) | backend
    paths: {include: ["src/*"], exclude: ["*/Migrations/*"]}   # optional globs
    pattern: '\bLegacyCrypto\.Encrypt\s*\('   # Python regex, searched over the whole file (MULTILINE)
    pattern_not: 'allow-legacy'        # optional: drop hit if the matched line matches
    context_not: 'IsDevelopment\(\)'   # optional: drop hit if found within ±context_lines (default 3)
    file_requires: 'using Company\.Crypto'   # optional: file must contain
    file_excludes: '...'               # optional: file must not contain
    ignore_case: false
    multiline: false                   # true: '.' also matches newlines
    severity: high                     # critical|high|medium|low|info
    confidence: high                   # high|medium|low
    owasp: A04                         # A01..A10 (2025)
    cwe: CWE-327
    message: Why this is a problem here.
    fix: What to do instead.
    examples:                          # REQUIRED in practice — `rules.py test` runs them
      bad: ['var c = LegacyCrypto.Encrypt(data);']
      good: ['var c = AesGcmCrypto.Encrypt(data);']
```
File-level rule (the path itself is the finding): use `path_pattern` without `pattern`, and
`examples.file` to test it. Secret rules add `secret: true`, `secret_group: N`, optional
`entropy_min` — matched values are always redacted in every output.

Disable a built-in rule for one project: `- {id: gha-unpinned-action, disabled: true}` in
`<repo>/.security-audit/rules/overrides.yml`.

## Gate rule
Gates assert nothing. They tag a site and carry the question the reviewer must answer — that is
what keeps deep review affordable (cost scales with gate sites, not repo size) and its false-positive
rate survivable.
```yaml
  - id: cs-transfer-endpoint
    type: gate
    title: Money-moving endpoint
    languages: [csharp]
    pattern: '\b(?:Transfer|Withdraw|Payout)\w*Async\s*\('
    owasp: A06
    question: Is this operation idempotent and protected against concurrent double execution (lock, concurrency token, atomic update)?
    guidance: Check the handler, the service and the SQL; look at how sibling operations do it.
    examples: {bad: ['await _svc.TransferAsync(cmd);']}
```
Good gate questions are answerable by reading code and name where to look. If you notice a bug at an
untagged site during review, the durable fix is a new gate rule, not only a one-off finding.

## Review check (markdown)
```markdown
---
id: payments-callback
title: Payment gateway callbacks
owasp: A08
cwe: [CWE-345]
languages: [csharp, js]
frameworks: []             # optional: only when these frameworks are detected
triggers: ['(?i)vnpay|momo|ipn|callback']   # optional: only shards containing a match
---
# What to look for / how to confirm / false positives / severity guidance
```
The scan phase computes which checks apply to each shard; reviewers read only those.

## Workflow for a new rule
1. Write it with `examples` (at least one bad, ideally a good twin that must not match).
2. `python3 scripts/rules.py validate` then `python3 scripts/rules.py test --id <rule>`.
3. Try it on real code: `python3 scripts/rules.py try --id <rule> --file path/to/File.cs`.
4. Rules with many dismissals in reports ("Dismissed and Suppressed" table) need a tighter
   `pattern_not` / `file_requires`, a lower confidence, or conversion to a gate.

## Suppressions
`<repo>/.security-audit/suppressions.yml`:
```yaml
- rule: secret-generic-assignment
  path: "tests/fixtures/*"
  reason: fake credentials for the local docker-compose database
  until: 2027-01-01          # optional; expired suppressions stop applying
```
A suppression without `reason` is ignored. Inline: `// security-audit: ignore <rule-id>` on the line
or the line above. Suppressed hits are counted in the report, never hidden completely.

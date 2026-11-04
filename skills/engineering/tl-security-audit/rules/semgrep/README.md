# Custom Semgrep / OpenGrep rules (optional tier)

Built-in dataflow lives in `rules/taint/` (generated into OpenGrep rules by `scripts/taint.py`,
including cross-file chains). Use this directory only for extra hand-written rules; they run with
the same engine (`scripts/engine.py`), with `--taint-intrafile` when the engine is OpenGrep.

Put Semgrep-format rule files (`*.yml`) here or in `<repo>/.security-audit/semgrep/` to add
intra-file dataflow (`mode: taint`) rules. They run only if `semgrep` or `opengrep` is on PATH;
otherwise the scan records a coverage gap. Local rules only — no registry download, `--metrics=off`.

Map results into the pipeline with metadata:
```yaml
rules:
  - id: cs-taint-query-to-sql
    mode: taint
    languages: [csharp]
    severity: ERROR
    message: Request value flows into raw SQL
    metadata:
      owasp: A05
      cwe: CWE-89
      confidence: medium
      fix: Use parameterized queries.
      # type: gate          # make it a gate instead of a finding
      # question: "..."     # required for gates
    pattern-sources: [...]
    pattern-sinks: [...]
```

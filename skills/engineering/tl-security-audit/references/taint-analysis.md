# Taint analysis

Taint analysis answers the question pattern rules cannot: *does untrusted input actually reach this
dangerous call?* It runs as its own phase (`pipeline.py run taint`) before `scan`, and its flows
become scanner findings with a **trace** (source → calls → sink) that reviewers triage like any hit.

## Contents
1. Engine
2. Scope and time
3. Three layers
4. Not followed
5. Rule packs: `rules/taint/<language>.yml`
6. Project-specific extensions (no skill edits)
7. Commands

## Engine
- **OpenGrep** (preferred, pinned `v1.30.0` in `scripts/engine.py`): `--taint-intrafile` gives
  cross-function taint within a file (return values, constructors, fields, higher-order functions)
  without a commercial license.
- **Semgrep CE** (fallback): intraprocedural only — reported as a coverage gap.
- None installed → the phase records a coverage gap and the audit continues with pattern rules.
  `python3 scripts/engine.py install` downloads the pinned release into `~/.cache/security-audit/bin`
  (signature-verified with cosign when cosign is present). **On the user's machine, ask before
  installing**; in a disposable sandbox it is fine to install directly.
- **Sandboxed agents:** the engine writes a log under the home directory (`~/.opengrep/`, `~/.semgrep/`).
  An agent sandbox that cannot write there makes the binary fail, so `engine.py status` and
  `taint.py test` report "no engine" although it is installed. Run the taint phase and its tests from
  an unrestricted shell or worker, and do not record "no engine" as the gap in that case.

## Scope and time
- The engine scans the repo minus `common.EXCLUDE_DIRS` (names that occur in the repo's own path are
  dropped, so a copy under `.security-run/` is still scanned), minified/generated files, the
  inventory's `--exclude` globs and vendored front-end assets (`inventory.json` `vendor_roots`;
  `--include-vendor` at init keeps them).
- Each round runs once per language. `--timeout` is per file; a whole run that exceeds
  `max(600, 60 × timeout)` s is lost for that language and round only, and is printed as a
  `COVERAGE GAP` — 0 flows after a timeout is never "clean".

## Three layers
| Layer | What it follows | How | Confidence |
|---|---|---|---|
| L1 | source → sink inside one function | engine | high |
| L2 | across functions in the same file | engine `--taint-intrafile` | high |
| L3 | across files (controller → service → repository) | taint **summaries** composed by `taint.py` | medium (unique names) / low (ambiguous names) |

L3 algorithm (all built from engine runs, so sanitizers are honoured at every hop):
1. **Summary rules** — every function parameter is a source; facts "`F` parameter *i* reaches
   sink kind *K*" are extracted (`taint_unify_mvars` exposes the function and parameter names).
2. **Param bridges** — "parameter *j* of `G` flows into argument *i* of a call to `F`" → `G` also
   reaches *K*. Repeated for `--depth` rounds (default 3).
3. **Entry bridges** — "untrusted source flows into argument *i* of a call to `F`" → a cross-file
   finding whose trace is the concatenation of hops.

Calls are matched by **function name + argument position + arity** (plus keyword/named arguments
for Python, C#, Dart; PHP calls match `$obj->f()`, `Cls::f()` and `f()`). A language needs a signature
parser (`DEF_RX`/`parse_params` in `taint.py`) for L3; a spec without one runs L1/L2 only and prints a
coverage gap instead of failing. This deliberately follows interface/DI dispatch (`_svc.SearchAsync(...)`
reaches `AccountService.SearchAsync`), at the price of ambiguity when names collide — such chains
are marked `low` with a note naming the ambiguous function, and reviewers must confirm which
implementation is actually invoked.

## Not followed (state these in coverage, never imply otherwise)
Reflection, string-based DI/service location, dynamic dispatch the name match cannot see,
callbacks registered at runtime, message queues/events, HTTP calls between services, framework
magic (model binders, AOP interceptors) beyond the listed sources, and chains deeper than `--depth`.
Stored (second-order) flows — input saved to the DB and read back elsewhere — are not taint-tracked;
review checks cover them.

PHP specifically: values loaded through the DB (`Auth::setUser($quotation->consumer)` where the
quotation was found by a request id), Eloquent relations and accessors, magic `__get`/`__call`,
container/DI resolution (`app(...)`, `resolve(...)`), facades beyond the listed ones, and Blade
templates (`{!! !!}` is a gate in `rules/php.yml`).

Taint never finds missing checks: IDOR (an id from the request used without an ownership check),
role middleware that lets everything through, a verifier that returns early, CSRF exclusions. Those
are gate and review-check territory (for PHP: `rules/php.yml`, `checks/php-laravel.md`).

## Rule packs: `rules/taint/<language>.yml`
One spec per language family generates all three rule kinds, so a new source or sink is added once:
```yaml
language: go                       # key; also used in generated rule ids
engine_languages: [go]             # OpenGrep language ids
inventory_languages: [go]          # languages from inventory.json that activate this spec
example_ext: .go                   # for `taint.py test`
function_scopes:                   # how a function + parameter looks; MUST use $SAFN and $SAP
  - |
    func $SAFN(..., $SAP $SATY, ...) { ... }
sources:                           # untrusted input (Semgrep taint source specs)
  - pattern: '($C : *gin.Context).Query(...)'
sanitizers:                        # apply to every sink kind
  - pattern: strconv.Atoi(...)
sinks:
  sql-injection:                   # sink kind → rule id taint-sql-injection
    title: Untrusted input reaches a SQL query
    owasp: A05
    cwe: CWE-89
    severity: high
    message: ...
    fix: ...
    impact: ...                    # optional (defaults per kind)
    sanitizers: [...]              # optional, kind-specific
    sinks:                         # Semgrep sink specs; focus the dangerous argument
      - patterns:
          - pattern: $DB.Exec($Q, ...)
          - focus-metavariable: $Q
    examples:                      # bad must produce a flow, good must not (string or list)
      bad: |
        ...
      good: |
        ...
crossfile_example:                 # optional: files + expected cross-file kind
  expect: sql-injection
  files: {handler.go: "...", repo.go: "..."}
```
PHP examples must start with `<?php` (`taint.py test` writes each example to a file as-is; without it
the engine sees text, and bad examples silently produce no flow).

Reserved metavariables (the generator uses them): `$SAFN $SAP $SARV $SATY $SARET $SABODY $SAE
$SAO $SAX $SART` — never use them in sources, sanitizers or sinks.

Precision lessons baked into the packs — follow them when extending:
- **Type the sources** where the language allows (`($C : *gin.Context).Query(...)`), otherwise
  unrelated methods with the same name (`db.Query`) become sources.
- **Focus the dangerous argument** (`focus-metavariable`) — `db.Query("... $1", id)` must not match.
  Mind argument positions (sqlx `Get(dest, query, ...)`, `Process.Start(exe, args)`).
- **Exclude look-alike receivers** for generic method names (`pattern-not: http.$F(...)`), or
  constrain the receiver (`metavariable-regex` on `$M`), e.g. Mongo models vs services named `find`.
- Exclude value-typed framework parameters (int, Guid, bool) from sources where the language
  allows; they cannot carry payloads.
- Schema validation (zod, FluentValidation) is **not** a sanitizer for injection — a validated
  string is still a string.

## Project-specific extensions (no skill edits)
`<repo>/.security-audit/taint/<anything>.yml` with the same `language:` key **extends** the
built-in spec: lists (`sources`, `sanitizers`, `function_scopes`) are appended; `sinks` kinds are
added or overridden; `disabled_kinds: [xss]` removes kinds. Typical uses: an in-house request
wrapper as a source, a `SafeSql.Escape(...)` helper as a sanitizer, a legacy `LegacyDb.Run(sql)` as
a sink.

## Commands
```bash
python3 scripts/engine.py status            # engine, version, capabilities
python3 scripts/engine.py install           # pinned OpenGrep into the user cache (ask first)
python3 scripts/taint.py test [--lang go] [--kind ssrf] [--repo <repo>]   # run spec examples
python3 scripts/pipeline.py run taint --run-dir $RUN_DIR [--depth 3] [--max-targets 150] [--timeout 20]
python3 scripts/taint.py --run-dir $RUN_DIR --include-vendor     # also scan vendored assets
```
Output: `<RUN_DIR>/scan/taint.json` (engine, mode, stats, errors, hits with traces); generated rules
per round in `<RUN_DIR>/taint/` for debugging.

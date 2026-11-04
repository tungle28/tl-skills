# Report tables

Every table in `report.md` follows this file, so the report renders as real tables in GFM viewers
(GitHub, VS Code, markdown-it, tl-md-to-html) and in `render_html.py` without hand edits.
`findings.py report` (`run finish`) writes its own tables this way and re-emits every other pipe
table in the report (from `surface.md` or `narrative.json`) under the same rules, printing
`WARNING: table repaired` for each one it had to fix. Fix the source when you see that warning.

## Cell rules (all tables)
| Rule | Why |
|---|---|
| Rows start and end with `\|`; header row, then a `\|---\|` separator with the same column count | Both renderers detect tables only this way |
| Every row has exactly as many cells as the header | GFM silently pads short rows and drops extra cells |
| One line per cell: no line breaks, lists or code fences inside a cell | A newline ends the row |
| Escape every literal `\|` as `\|`, also inside backticks | GFM splits on `\|` even inside code spans |
| `<` and `>` only inside backticks (`` `List<int>` ``) | Outside code, GFM reads them as an HTML tag and hides the text |
| An even number of backticks per cell | `render_html.py` toggles code on each backtick |
| Empty cell = `-` | An empty cell reads like a missing value |
| A blank line before and after each table | Keeps it apart from paragraphs and lists in every renderer |
| Paths and locations in backticks: `` `src/a.cs:12-14` `` | Keeps `_` and `*` in paths from becoming emphasis |

`findings.table()` / `md_cell()` apply these rules; agent-written tables follow them by hand.

## Allowed values
| Column | Values |
|---|---|
| Severity | `critical` · `high` · `medium` · `low` · `info` (lowercase; render_html.py badges them) |
| Confidence | `high` · `medium` · `low` |
| Status (finding) | `unverified` · `verified` · `rejected` · `scanner` · `untriaged` · `unreviewed` · `out-of-scope` |
| OWASP | `A01` … `A10` (Top 10:2025) |
| Status (OWASP coverage, surface.md) | `Controlled` · `Needs review` · `Not checked` · `Not applicable` (translated in a non-English run) |

## Tables and their columns (fixed names and order)
| Section | Columns | Source |
|---|---|---|
| (top, run summary) | Generated \| Scope \| Files reviewed / scanned \| Languages \| Frameworks \| Findings \| Rejected \| Verified | script |
| Dashboard — by severity | Severity \| Count \| % \| Share | script |
| Dashboard — by OWASP | OWASP 2025 \| Category \| critical \| high \| medium \| low \| info \| Total | script |
| Dashboard — by area | Area \| Findings \| Share | script |
| Other Findings by OWASP Category (one per category) | ID \| Title \| Location \| Severity \| Confidence \| Status | script |
| Changes Since Previous Run | Previous ID \| Title \| Location \| Severity \| Why gone | script |
| Known from Earlier Runs | ID \| Title \| Location \| Severity \| Verdict \| Entry \| Reason \| Until | script |
| Dependencies | ID \| Package \| Severity \| Ecosystem \| Transitive \| Advisories | script |
| Outside Review Scope | ID \| Title \| Location \| Severity | script |
| Dismissed and Suppressed | Rule \| Dismissed by reviewer \| Suppressed | script |
| Security Architecture — Data Classification | Data type \| Where stored \| Protection (at rest / in transit / hashing) \| Evidence | surface reviewer |
| Security Architecture — OWASP Top 10:2025 Coverage | Category \| Status \| Evidence reviewed \| Notes / finding links | surface reviewer |

Headers stay in English in every run language; cell content follows the run language. `Share` is a
bar of `█`. Do not add other tables to `narrative.json`. Write the executive summary and roadmap as
prose or lists. A new table type gets a row here first.

# Security architecture — surface reviewer spec (`surface.md`)

The proactive, whole-system view. **Full scope only**: a changeset or partial scan cannot establish
what the system's auth architecture or data handling looks like, so in those scopes skip this file
unless the user explicitly asks — and then run it as a full pass and say so.

Every claim carries a `file:line` or config-key citation from a file you actually opened and read.
Unverifiable facts are written as "unknown" and also listed under open questions — never guessed.
Headings in English (as below), content in the run language. Aim for ≤ 120 lines: tables and
bullets over prose, and point at finding ids instead of restating findings. Both tables below use
the exact headers shown and the cell rules in `report-tables.md` (one line per cell, escape `|`,
`<`/`>` only inside backticks, empty cell = `-`).

## Required sections

### Overview
Stack, entry points (APIs, UIs, jobs, consumers, webhooks), deployment shape visible in the repo,
trust boundaries (internet ↔ gateway ↔ services ↔ data stores ↔ third parties).

### Authentication and Authorization Flow
A Mermaid `sequenceDiagram` or `flowchart`, verified against the actual middleware/guard code:
login → token/session issuance → per-request authentication → authorization decision (where roles,
policies, ownership and tenant checks happen). Put the diagram in a ```mermaid fence.

### Data Classification
Shape (the example row shows the format only; write rows for what the code actually shows):

```markdown
| Data type | Where stored | Protection (at rest / in transit / hashing) | Evidence |
|---|---|---|---|
| Email address | `users.email` column | TLS in transit; not encrypted at rest | `db/schema.sql:12` |
```
Rows for PII, credentials, payment/card data, bank account numbers, national ids, tokens, health
data — only types that exist. This table decides compliance applicability below.

### OWASP Top 10:2025 Coverage
One row per category A01–A10, same shape:

```markdown
| Category | Status | Evidence reviewed | Notes / finding links |
|---|---|---|---|
| A01 Broken Access Control | Needs review | auth middleware `src/auth.ts:40`; role checks in 3 of 5 controllers | S03-002, S05-001 |
```
Status is one of: `Controlled` · `Needs review` · `Not checked` · `Not applicable` (translate the
status words into the run language if not English). Rules:
- **Evidence reviewed** names *what was actually checked* ("auth middleware in Program.cs:40, rate
  limiter in RateLimitSetup.cs:12"), not just a conclusion. A status without it is a guess.
- `Not checked` and `Not applicable` always carry a reason ("no outbound HTTP from server code, so
  SSRF under A01 does not apply"; "dependency audit tool not available in this run").
- Link finding ids where gaps exist, or the control's code where handled well.
- Scale depth to the project in one stated sentence: an internal tool without auth/user data only
  needs the categories that structurally apply; a customer-facing app with accounts/payments/PII
  gets the full pass. Name which security-critical files (auth/authz middleware, session/token
  handling, input validation, access-control checks) were fully read vs out of scope.

### Compliance Mapping (only when the data classification shows it applies)
Include a framework only if the data table has the triggering data — never "just in case":
- **Vietnam Personal Data Protection Law (Law 91/2025/QH15, effective 2026-01-01; detailed by
  Decree 356/2025/ND-CP, which replaced Decree 13/2023/ND-CP)** — when the system processes
  personal data of people in Vietnam: consent capture/withdrawal, data subject rights (access,
  correction, deletion) and where implemented, sensitive-data handling, retention, cross-border
  transfer, breach notification process, impact assessment evidence. Verify current guidance if unsure.
- **GDPR** — when personal data of EU-based individuals is processed.
- **PCI-DSS** — when the system itself stores/processes/transmits cardholder data. If it delegates
  to a payment processor (Stripe, VNPay, MoMo, …) and never touches raw card data, say so with the
  integration's `file:line` — that sharply reduces scope (often SAQ-A).
Each item: evidence or "unknown — needs legal/compliance review". Every conclusion carries the caveat
that a code review is not a legal or compliance certification.

### Runaway-loop and Cost Risk
Result of `checks/runaway-cost.md` across the system: self-triggering paths, unbounded retries,
overlapping schedules, unbounded fan-out, platform safeguards (budget alerts, caps) found or missing.

### Open Questions
Everything marked unknown above, plus assumptions a reader must confirm.

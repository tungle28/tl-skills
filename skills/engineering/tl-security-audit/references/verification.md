# Verification — try to disprove each finding

Reviewers over-report; a report full of weak findings gets ignored and the real ones are skimmed.
Enter this pass trying to **refute**. Default to rejected: a finding survives only if you looked for
the control everywhere it could reasonably live and did not find it.

**This is not attack simulation.** You challenge a written claim by reading code: "is there a
control I missed?" is this pass; "could I get past the control?" is not. Never write payloads or
exploit code.

## Refutation checklist (roughly by how often each one refutes)
1. **Middleware / route registration / global policies** — find the registration yourself; read the
   middleware body; check fallback authorization policies, global filters, API gateway/ingress
   config in the repo. A group-level guard with one route registered outside it confirms the finding
   for that route only.
2. **Framework safe defaults** — parameterized ORM APIs, Razor/React auto-encoding, antiforgery
   defaults, System.Text.Json (no polymorphic types by default), `DtdProcessing.Prohibit` default.
3. **Where the value really comes from** — trace to origin: request, config, database, constant. A
   value resolved by an earlier scoped lookup is already guarded. Check *every* caller.
4. **Service / data layer** — ownership in the service, EF global query filters, row-level security
   in migrations, database constraints that make the bad case impossible.
5. **Reachability** — is the route registered/deployed? behind a feature flag that is off?
   internal-only listener? dead code with no callers? test-only?
6. **Environment** — is the risky setting only in Development config? Is production config
   overriding it (appsettings.Production.json, Helm values, env vars in IaC)?
7. **Taint traces** — a sanitizer or validator on the path the rule pack does not know, a
   conversion to a non-string type, a guard that returns early, or a cross-file hop that resolves to
   a different implementation than the one in the trace (name collision).
8. **Premise** — does the code do what the finding claims? Names mislead. Re-read with fresh eyes.

## Outcomes
- `confirmed` — list the places you checked in the note.
- `rejected` — cite where the control is (`file:line`).
- `adjusted` — real, but severity/requires/kind wrong (e.g. admin-only, internal network, test code).

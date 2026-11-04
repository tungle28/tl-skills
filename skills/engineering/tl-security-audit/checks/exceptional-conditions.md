---
id: exceptional-conditions
title: Mishandling of exceptional conditions — fail-open, error leakage
owasp: A10
cwe: [CWE-636, CWE-209, CWE-390, CWE-755, CWE-252]
languages: [csharp, js, python, java, go, php, ruby]
triggers: ['(?i)catch|except|try|error|finally|timeout|fallback|default:']
---
# Exceptional conditions (A10 — new in 2025)

- **Fail-open:** authorization/validation helpers that return `true`/allow in a catch block or on
  timeout; feature flags or remote policy services whose failure path grants access; signature
  checks that treat "could not verify" as "valid".
- **Partial failure in money/state flows:** debit succeeds, credit throws, no compensation or
  transaction; retries that double-apply non-idempotent operations; missing transaction boundaries.
- **Error leakage:** stack traces, SQL errors, internal hostnames returned to clients.
- **Swallowed errors:** empty catch in security-relevant code; ignored return values of
  verification functions.
- **Resource exhaustion paths:** unbounded input sizes, missing timeouts on outbound calls, thread
  pool starvation via sync-over-async.

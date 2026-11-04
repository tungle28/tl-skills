---
id: logging-alerting
title: Security logging and alerting
owasp: A09
cwe: [CWE-778, CWE-532, CWE-117, CWE-223]
languages: [csharp, js, python, java, go, dart, yaml, json]
triggers: ['(?i)log|logger|audit|serilog|nlog|winston|pino|logging\.']
---
# Logging and alerting (A09 — "alerting" added in 2025)

- **Sensitive data in logs:** passwords, tokens, full card numbers, OTPs, national ids, request
  bodies of auth/payment endpoints, connection strings, full JWTs. Structured logging of whole
  request/DTO objects is the usual culprit.
- **Missing audit trail** for security-relevant events: login success/failure, MFA changes,
  permission/role changes, money movement, beneficiary changes, data exports, admin actions.
  For banking/finance, audit records need who/what/when/before/after and tamper resistance
  (append-only store, separate permissions).
- **Log injection:** user input with CR/LF written to text logs used for audit.
- **Alerting:** repeated auth failures, authorization denials, rate-limit hits and webhook signature
  failures should produce a signal someone sees. If the code shows logging only to local files with
  no shipping/alerting config in the repo, report it as a gap to confirm, not a vulnerability.

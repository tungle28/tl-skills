# Severity rubric

Severity = **impact** if exploited × **likelihood** (attacker position, preconditions, discoverability).
Rate the finding in *this* system, not the bug class in general.

| Severity | Typical meaning |
|---|---|
| critical | Unauthenticated or any-user path to: remote code execution, auth bypass, cross-tenant/other-customer data at scale, moving money, forging payment confirmations; live production secret with broad scope. |
| high | Authenticated user can access/modify other users' sensitive data or perform privileged actions; injection in a reachable path; signature/TLS verification disabled on a sensitive channel; runaway cost with no bound. |
| medium | Exploitable with meaningful preconditions (specific role, user interaction, internal network); stored XSS behind auth; weak crypto for sensitive data; missing rate limit on login/OTP. |
| low | Limited impact or hard to exploit: info disclosure of internals, missing hardening that enables nothing concrete alone, unpinned CI actions. |
| info | Observation/best practice; no direct security impact. |

Adjustments:
- **Attacker position** (`requires`): none > user > privileged > internal > local. An admin-only
  endpoint missing an extra check is usually low.
- **Domain:** money movement, credentials, PII/financial data, audit integrity raise impact by one
  level in banking/finance/healthcare contexts.
- **Test/sample code** not deployed: drop to info/low unless it holds a real shared credential.
- **Mitigations elsewhere** (WAF, network isolation, non-enumerable ids) lower likelihood; they do
  not remove the finding — say so in the text.
- **Uncertain dependency:** when severity depends on an unknown, choose the lower value and state
  the unknown.
- **cost-risk override:** a runaway pattern on a pay-per-use or quota-limited resource is at least
  high (critical when nothing bounds it at any layer), regardless of code size or current plan.
- **Secrets:** production credential with write/admin scope → critical; read-only or non-prod shared
  environment → high/medium; local-only test container → low.

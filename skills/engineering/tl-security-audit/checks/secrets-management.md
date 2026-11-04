---
id: secrets-management
title: Secrets handling
owasp: A04
cwe: [CWE-798, CWE-522, CWE-532, CWE-538]
languages: [any]
triggers: ['(?i)secret|password|apikey|api_key|token|credential|connectionstring|private']
---
# Secrets

Scanner hits find literals; review answers what the literal is and how secrets flow.
- **Triage each secret hit:** real credential vs placeholder/test fixture/public key/publishable key
  (Stripe `pk_`, Firebase web config, Google Maps browser key with referrer restriction). Test-only
  secrets for local containers are low; anything that works against a shared environment is real.
- **Never repeat the value** in findings — refer to it by file:line and a redacted prefix.
- **Flow:** where are secrets loaded (Key Vault/Secrets Manager/Vault/K8s secrets/env)? Are they
  logged at startup, dumped in health/diagnostic endpoints, serialized into error responses, sent
  to the browser, baked into images or mobile apps?
- **Remediation is rotation first:** removing a committed secret from HEAD does not revoke it; git
  history, forks, CI caches and clones keep it. The fix always says: rotate/revoke, then move to a
  secret store, then optionally purge history (a user decision).

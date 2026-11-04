---
id: integrity-deserialization
title: Software and data integrity — deserialization, webhooks, updates
owasp: A08
cwe: [CWE-502, CWE-345, CWE-347, CWE-494]
languages: [csharp, js, python, java, go, php, ruby]
triggers: ['(?i)deserializ|pickle|yaml\.load|BinaryFormatter|TypeNameHandling|webhook|signature|hmac|x-hub|stripe-signature|callback|ipn']
---
# Integrity

- **Deserialization** of untrusted data into arbitrary types (BinaryFormatter, TypeNameHandling,
  pickle, yaml full loader, Java native serialization) → high/critical.
- **Webhooks / callbacks from payment gateways and partners** (VNPay, MoMo, Stripe, PayPal, banks):
  signature/HMAC verified over the *raw* body with a constant-time compare; timestamp/replay window;
  idempotency on the event id; amount/currency/order re-checked against your own records instead of
  trusting the payload. A payment callback that marks orders paid without signature verification → critical.
- **Client-trusted data:** prices, discounts, roles, account numbers or approval flags taken from
  the request instead of server state.
- **Signed tokens/URLs:** pre-signed URLs with long expiry, unsigned "remember me" or export links.
- **Auto-update / plugin loading** without signature verification.

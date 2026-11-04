---
id: crypto-data-protection
title: Cryptography and data protection
owasp: A04
cwe: [CWE-327, CWE-328, CWE-326, CWE-330, CWE-311, CWE-319, CWE-295]
languages: [any]
triggers: ['(?i)encrypt|decrypt|aes|rsa|hash|hmac|cipher|key|iv|nonce|salt|tls|ssl|certificate|pii|card|iban|account']
---
# Cryptography and data protection

- **Algorithms:** no DES/3DES/RC4/MD5/SHA1 for security; AES-GCM or ChaCha20-Poly1305 for
  encryption; ECB mode → high; CBC without MAC → medium; static/reused IV/nonce with GCM → high.
- **Keys:** hardcoded keys or keys derived from constants; keys in config files next to the data
  they protect; no rotation story; key sizes (RSA < 2048).
- **Randomness:** CSPRNG for tokens, ids used as secrets, salts, IVs.
- **Transport:** TLS enforced (HSTS, `UseHttpsRedirection`), certificate validation never disabled,
  internal service calls over plain HTTP carrying credentials or PII.
- **At rest:** PII, credentials, card data, bank account numbers, national ids, tokens — encrypted or
  hashed as appropriate; database/backup encryption; column-level encryption for highly sensitive fields.
- **Leakage:** sensitive data in URLs (logged by proxies), in client bundles, in analytics events,
  in error messages, in exports without access checks.
- **Data classification (surface reviewer):** list each sensitive data type, where it is stored,
  and the protection mechanism with `file:line` — this table drives the compliance mapping.

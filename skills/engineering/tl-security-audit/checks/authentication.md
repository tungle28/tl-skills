---
id: authentication
title: Authentication, sessions and tokens
owasp: A07
cwe: [CWE-287, CWE-307, CWE-384, CWE-521, CWE-640, CWE-347, CWE-613]
languages: [csharp, js, python, java, go, php, ruby, dart]
triggers: ['(?i)login|signin|password|jwt|token|session|oauth|oidc|otp|mfa|reset|cookie']
---
# Authentication

## Credentials
- Password storage: Argon2id, bcrypt, scrypt, PBKDF2 (≥600k iterations for SHA-256) or ASP.NET
  `PasswordHasher`. Plain SHA-*/MD5, unsalted or reversible encryption → high.
- Comparison of secrets/tokens/HMACs must be constant-time (`CryptographicOperations.FixedTimeEquals`,
  `crypto.timingSafeEqual`, `hmac.compare_digest`).
- Brute force: lockout or progressive delay + rate limit on login, OTP verification, password reset
  and any "check if exists" endpoint. User enumeration via different messages/timings/status codes.
- Password reset: token random (CSPRNG, ≥128 bits), single-use, short expiry, bound to the user,
  invalidated on password change; reset link host not derived from the `Host` header.

## Tokens (JWT / OAuth / OIDC)
- Signature verified with a pinned algorithm; `none` rejected; HS256 secrets long and not shared
  with other services; RS/ES keys fetched from trusted metadata over HTTPS.
- `exp`, `iss`, `aud` validated; clock skew small. Long-lived access tokens without revocation →
  medium. Refresh tokens rotated and revocable; reuse detection.
- `decode` vs `verify` confusion (JS/Python). Claims from an unverified token used for authz → critical.
- OAuth: `state` validated, PKCE for public clients, redirect URIs exact-match, tokens not in URLs.

## Sessions / cookies
- New session id on login and privilege change (session fixation). Server-side invalidation on
  logout. Idle and absolute timeouts appropriate for the domain (banking: short).
- Cookies: `HttpOnly`, `Secure`, `SameSite` set; no sensitive data in unsigned cookies.

## MFA and step-up
- For finance/admin: MFA for login and step-up for sensitive actions (transfers, beneficiary
  changes, email/phone change). MFA bypass paths: "remember device" without binding, recovery flows
  weaker than the primary factor, OTP not bound to the transaction.

## Service-to-service
- Internal endpoints trusting a header (`X-User-Id`, `X-Forwarded-User`) without mTLS/signed token.
- API keys compared non-constant-time, logged, or accepted from query strings.

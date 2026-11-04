---
id: security-misconfiguration
title: Security misconfiguration — CORS, headers, debug, defaults
owasp: A02
cwe: [CWE-16, CWE-942, CWE-1004, CWE-489, CWE-611, CWE-693]
languages: [any]
triggers: ['(?i)cors|header|debug|swagger|helmet|hsts|csp|cookie|appsettings|environment|startup|program\.cs|main\.ts|settings\.py']
---
# Security misconfiguration (A02 — #2 in 2025)

- **CORS:** wildcard or reflected origin with credentials → high; `null` origin allowed; regex
  origin checks that match `evil-example.com`.
- **Environment gating:** Swagger/OpenAPI UI, GraphQL playground/introspection, developer exception
  pages, debug toolbars, actuator/diagnostic endpoints, seed/admin setup endpoints enabled outside
  development.
- **Headers:** HSTS, `X-Content-Type-Options: nosniff`, frame protection (CSP `frame-ancestors`),
  CSP for apps rendering user content. Missing headers = hardening (low/info) unless they enable a
  concrete attack (e.g. clickjacking on a transfer confirmation page).
- **Defaults:** default credentials in compose/seed files that also run in shared environments;
  sample apps/routes left enabled; directory listing; verbose server banners.
- **Parsers:** XML external entities, YAML/JSON polymorphic type handling, file upload size limits,
  request body limits.
- **Host header trust:** building absolute URLs (password reset, email links) from `Host` /
  `X-Forwarded-Host` without an allow-list (ASP.NET `AllowedHosts`, ForwardedHeaders KnownProxies).

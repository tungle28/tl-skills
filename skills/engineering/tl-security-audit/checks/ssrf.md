---
id: ssrf
title: Server-side request forgery and outbound calls
owasp: A01
cwe: [CWE-918]
languages: [csharp, js, python, java, go, php, ruby]
triggers: ['(?i)HttpClient|fetch\(|axios|requests\.|httpx|urllib|got\(|WebClient|RestClient|webhook|callback|url']
---
# SSRF (part of A01 in OWASP 2025)

Question: can a caller make the server send a request to a destination they choose?
- **Sources:** webhook/callback URLs, "import from URL", image/avatar fetchers, PDF/HTML renderers
  (headless Chrome, wkhtmltopdf fetching embedded resources), XML with external entities, SSO
  metadata URLs, OpenAPI/URL previewers.
- **Controls to look for:** host allow-list; scheme restricted to https; resolve DNS and block
  private, loopback, link-local (169.254.169.254 cloud metadata), and IPv6 equivalents *after*
  resolution (and on every redirect — disable auto-redirects or re-validate); response size/time limits.
- **Partial control:** only the path/query is user-controlled on a fixed host → usually low, unless
  the path allows `@`/`//`/encoded tricks that change the authority.
- **Cloud impact:** reachable metadata endpoints can yield instance credentials → critical.

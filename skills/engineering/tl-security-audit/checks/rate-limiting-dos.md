---
id: rate-limiting-dos
title: Rate limiting and resource exhaustion
owasp: A06
cwe: [CWE-770, CWE-400, CWE-307, CWE-1333]
languages: [csharp, js, python, java, go, yaml, json]
triggers: ['(?i)rate|throttl|limit|page|pageSize|take|top|regex|Regex|timeout|upload|batch']
---
# Rate limiting and DoS

- Login, OTP, password reset, registration, contact/SMS/email-sending endpoints without rate
  limits (credential stuffing, OTP brute force, SMS pumping cost).
- Pagination: caller-controlled `pageSize`/`limit`/`take` without a maximum; GraphQL without depth/
  complexity limits.
- Expensive operations (report generation, exports, search) without quotas or background queues.
- Regex built from input or catastrophic-backtracking patterns on user input without timeouts
  (`Regex` without `matchTimeout` in .NET).
- Request size limits for JSON/multipart bodies; decompression bombs.

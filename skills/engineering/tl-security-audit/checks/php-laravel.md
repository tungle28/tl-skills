---
id: php-laravel
title: PHP / Laravel pitfalls
owasp: A01
cwe: [CWE-639, CWE-862, CWE-287, CWE-915, CWE-502]
languages: [php]
---
# PHP / Laravel review points

Taint covers request data reaching a sink in PHP. It does not cover the flaws below, which are the
usual source of real Laravel findings: check them at every gate site in the shard.

- **Routes and middleware:** a route registered outside the `auth`/`auth:api` group, a group whose
  role middleware is a no-op (returns `$next($request)` when the role or header is missing), a
  controller constructor `middleware()` with an `except` list that is too wide. Read the route
  file, the RouteServiceProvider and the Kernel's middleware aliases together.
- **Ownership (IDOR):** `Model::find($id)` / `findOrFail` / `destroy` / `where('email', ...)` on a
  caller-supplied value without a policy (`authorize`, `can`), a scoped query
  (`$request->user()->orders()`), or a scoped route model binding. Delete and update actions
  first.
- **Principal selection:** `Auth::setUser`, `loginUsingId`, `login`, `onceUsingId` on a user that a
  caller can choose, including a user reached through a relation of a request-selected record
  (`Auth::setUser($quotation->consumer)`).
- **Verifiers that do not verify:** an early `return;` or `return true` in token/OTP/signature or
  social-login checks, an exception swallowed into success, `==` instead of `hash_equals`, debug
  or test bypass flags left reachable in production.
- **Mass assignment:** `create/update/fill($request->all())` with `$guarded = []` or wide
  `$fillable`; check the columns that matter (role, is_admin, user_id, tenant_id, balance, status).
- **Output:** Blade `{!! !!}` on user or external content; `echo` in legacy controllers.
- **Deserialization and config:** `unserialize` on cookies, cache or request data (Laravel < 5.6.30
  also had cookie-decryption object injection with a leaked APP_KEY); `APP_DEBUG=true` or a
  committed `APP_KEY` in production config.

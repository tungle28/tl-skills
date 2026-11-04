---
id: access-control
title: Broken access control — IDOR/BOLA, function-level authz, tenant isolation
owasp: A01
cwe: [CWE-639, CWE-862, CWE-863, CWE-285]
languages: [csharp, js, python, java, go, php, ruby]
triggers: ['\b(?:id|Id|ID)\b', 'Authorize|Guard|permission|role|tenant|owner|claims|req\.user|current_user|User\.']
---
# Access control

The bugs here are *absent relationships* — a check that should exist and does not — so no pattern
proves them. Answer one question per site:

> Can a caller reach data or an action that is not theirs by supplying a value they control?

## Walk the path (outward to the route, inward to the data)
1. **Route registration / middleware** — which group, filter, guard, policy or fallback policy
   applies? Read the middleware body, not its name: `RequireAuth` may only validate a token;
   `RequireAdmin` may check a claim that is never issued.
2. **Handler → service** — does the handler pass the caller identity, or only the raw id? If an
   identity is passed, is it actually *used* to constrain the lookup? An identity threaded through
   and ignored is a real finding that looks safe at every layer.
3. **Query** — is the final lookup constrained by owner/tenant (`WHERE Id = @id AND TenantId = @t`),
   by a global query filter (EF `HasQueryFilter`), or by database row-level security?
4. **Siblings** — how do neighbouring handlers guard themselves? Nine actions building an owner
   filter and one that does not is the strongest signal you will get.
5. **Where the id comes from** — caller-supplied (route/query/body) vs resolved by an earlier
   scoped lookup. A query is safe only if *all* callers resolve the id safely.

## Also look for
- **Function-level (BFLA):** admin/back-office actions reachable by ordinary users (role checked in
  UI only; `[Authorize]` without a role/policy on an admin controller).
- **Mass assignment / over-posting:** binding request bodies directly to entities
  (`Update(entity)`, `Object.assign(user, req.body)`, `Model.update(**request.json)`) lets callers
  set `Role`, `IsAdmin`, `TenantId`, `Balance`, `OwnerId`.
- **Tenant leaks:** caches keyed without tenant, background jobs running without tenant context,
  exports/reports that query across tenants, search indexes shared between tenants.
- **Authenticated ≠ authorized:** `requireUserSession`, `[Authorize]`, `AuthGuard` prove the caller
  is logged in, not that this row is theirs. Conflating the two *is* the IDOR class.
- **Client-side enforcement only:** hidden buttons, disabled fields, route guards in React/Angular.
- **CSRF** on cookie-authenticated state-changing endpoints (not relevant for pure bearer-token APIs).

## Stack-specific places the guard lives
- **ASP.NET Core:** controller/action attributes, `FallbackPolicy`, resource-based `IAuthorizationService`, EF `HasQueryFilter`.
- **NestJS / Express:** global `APP_GUARD`, controller-level `@UseGuards`, router-level middleware, service-level owner filters.
- **Go (gin/echo/chi/fiber):** middleware attached to a router *group* — a route registered on the root router instead of the group is the classic hole; a caller/tenant value built in the handler and passed to the service; the tenant clause in the sqlc `.sql` query or RLS policy in migrations.
- **Nuxt/Nitro:** `server/middleware/*` (runs before every route, invisible from the route file), helpers in `server/utils/` (e.g. a `backendFetch` that forwards the session). A Nuxt route that delegates to a backend is only safe if **that backend** enforces ownership — a frontend trusting the backend and a backend trusting the frontend is a real hole with no single file to blame.
- **Flutter / mobile:** there is no client-side guard — hidden buttons and `if (user.isAdmin)` are UX. The finding, if any, is on the API the app calls.

## Answers
- Enforced → say where (`file:line`) and mark the gate `clear`.
- Not enforced anywhere you looked → finding; list the places you checked.
- Cannot tell → `unknown` gate / low-confidence finding stating what you could not establish.
  Never resolve uncertainty with "the middleware probably handles it" — open the middleware.

## Severity
Blast radius decides: cross-tenant read of financial/PII data or any write/delete/transfer on
another user's object → high/critical. Missing check on a route already restricted to admins → low.
Non-enumerable ids (random UUIDs) lower likelihood, they are not a control.

# Review lenses

Each shard in `shards.json` lists the lenses to apply. Read only the sections
for those lenses plus the stack section(s) matching the shard's languages.
These are prompts for thinking, not checkboxes to tick — report only what you
can back with evidence from the code.

## Contents
1. Universal lenses: correctness · error-handling · tests · test-quality · concurrency · data · backward-compat · api-contract · security · performance · resilience · config-ops · ui-state · observability
2. Stack notes: .NET/C# · TypeScript/Node/NestJS · React · SQL (SQL Server/PostgreSQL) · Go · Flutter/Dart · Python
3. Domain overlay: financial / banking systems

---

## 1. Universal lenses

### correctness (always)
- Does the code do what the change intent (commit message / feature description) says? Missing half of the requirement is a finding.
- Boundary values: empty collection, single element, null/undefined, zero, negative, max values, unicode, timezone boundaries, DST, month-end, leap year.
- Branch coverage by reasoning: for each new `if`/`switch`, what happens in the branch not taken? Is there a default case?
- Inverted conditions, `&&` vs `||`, off-by-one on ranges (`<` vs `<=`), wrong variable used after copy-paste.
- State transitions: can an entity reach an invalid state (e.g. `Refunded` without `Paid`)?
- Equality/comparison: reference vs value equality, string comparison culture/case, floating point `==`.

### error-handling (always)
- Swallowed exceptions (`catch {}` / `catch (e) { log }` then continue as if success).
- Errors converted to wrong status (500 for validation, 200 with error body).
- Partial failure: step 2 of 3 fails — is step 1 rolled back or compensated?
- Resource cleanup on error paths (`using`/`await using`, `finally`, `defer`).
- Retries on non-idempotent operations.

### tests (always, diff modes)
- New branching logic without a test → major if business-critical, minor otherwise.
- Changed behavior but tests unchanged → tests may now be asserting the old behavior or not exercising the path.
- Bug fix without a regression test.

### test-quality (test files in scope)
- Tests that can't fail: no assertion, asserting on the mock itself, `expect(true)`.
- Over-mocking the unit under test; testing implementation details.
- Time/order/random dependence → flaky. Shared mutable fixtures between tests.

### concurrency
- Check-then-act on shared state (read → decide → write) without lock/transaction/conditional write.
- Lost updates; missing optimistic concurrency token on entities edited concurrently.
- Async misuse: sync-over-async (`.Result`, `.Wait()`), `async void`, un-awaited promises/tasks, `Promise.all` where one rejection should not cancel the others (`allSettled`).
- Shared mutable singletons (static fields, DI singletons holding request state, module-level caches in Node).
- Message consumers: at-least-once delivery → handler must be idempotent; ordering assumptions.
- Background jobs running on multiple instances without a distributed lock.

### data
- Transaction boundaries: multiple writes that must be atomic but aren't in one transaction; transaction spanning an external HTTP call.
- Isolation level assumptions; read-modify-write under READ COMMITTED.
- Queries: missing filter (tenant, soft-delete), unbounded result sets, missing pagination, N+1, `SELECT *` into wide DTOs.
- Precision: money as `double`/`float`/JS `number`; rounding mode; currency mixing.
- Nullability mismatch between DB column and code model.
- Time: `DateTime.Now` vs UTC, storing local time, comparing different time zones.

### backward-compat (migrations, contracts)
- Expand/contract: does the migration break the version of the app still running during rolling deploy (drop/rename column, NOT NULL without default, type narrowing)?
- Long locks on big tables (adding index without `CONCURRENTLY`/`ONLINE`, column rewrite).
- Data backfill correctness and idempotency; down-migration exists or is explicitly not supported.
- Serialized formats: renamed JSON fields, enum value reordering (int-serialized enums), removed message fields in Kafka/RabbitMQ payloads with consumers still on old schema.

### api-contract
- Breaking changes: removed/renamed field, changed type, new required field, changed status code or error shape, changed default sort/pagination.
- Input validation at the boundary (length, range, format), and the error contract for invalid input.
- Idempotency for POST that creates money movements/orders (idempotency key).
- Versioning: if breaking, is there a new version or a compatibility shim?

### security (light pass — deep audit belongs to `tl-security-audit`)
- New endpoint/handler: authentication required? Authorization checks the *resource owner/tenant*, not just "is logged in"?
- User input reaching SQL/shell/file path/HTML/redirect/URL fetch without parameterization or allow-listing.
- Secrets in code/config/logs; PII in logs.
- Mass assignment (binding request body directly to entity).
- Missing rate limiting on auth/OTP endpoints.

### performance
- Work inside loops that should be batched (DB calls, HTTP calls, allocations).
- List endpoints and batch jobs that return or load everything: no limit/pagination, no page size cap.
- Materializing too early (`ToList()` before filter), loading full entities to read one field.
- Missing index for a new query pattern (check WHERE/ORDER BY columns against migrations).
- Hot-path allocations, regex compiled per call, string concatenation in loops.
- Caching: key includes all varying inputs (tenant/user!), invalidation on write, TTL sanity, stampede.

### resilience (external calls, infrastructure)
- Timeouts on every outbound call; retries with backoff + jitter only for idempotent ops; circuit breaker for flaky dependencies.
- Behavior when dependency is down: fail fast, fallback, or queue? Does a failure cascade?
- `HttpClient` lifetime (.NET: `IHttpClientFactory`), connection pool exhaustion.
- Poison messages: dead-letter handling, max retry.

### config-ops (config, CI, IaC, Dockerfiles)
- New config key without default and without being added to all environments.
- Secrets committed or passed as plain env in manifests.
- Resource limits/requests, health checks (liveness vs readiness), graceful shutdown.
- CI: tests actually run; pinned action versions; permissions scoped.

### ui-state (React/Vue/Flutter UI)
- Stale closures; missing/over-broad effect dependencies; effects without cleanup (subscriptions, timers, abort controllers).
- Race between async responses (older response overwriting newer); double-submit.
- Loading/empty/error states handled; optimistic update rollback.
- Keys in lists; derived state duplicated into state.
- Money/number formatting and locale.

### observability (logging, metrics, tracing calls; not in `--depth quick`)
- Errors logged with enough context (correlation id, entity id) and without PII.
- New critical flow has metrics/traces; log level appropriate (no error-level for expected cases).

---

## 2. Stack notes

### .NET / C#
- EF Core: tracking vs `AsNoTracking`, `Include` explosion (cartesian) → `AsSplitQuery`, client-side evaluation, `SaveChanges` inside loops, DbContext captured in singleton/background service (must use `IServiceScopeFactory`).
- `async void` (except event handlers), `.Result`/`.Wait()`, missing `CancellationToken` propagation, `Task.Run` in ASP.NET request path.
- `IDisposable`/`IAsyncDisposable` not disposed; `HttpClient` newed per call.
- DI lifetimes: scoped service injected into singleton (captive dependency).
- `decimal` for money; `DateTimeOffset`/UTC; `string.Equals(..., StringComparison.Ordinal)`.
- Nullable reference types warnings suppressed with `!` hiding real nulls.
- Minimal APIs/controllers: `[Authorize]` policy present; model validation; `[FromBody]` binding to entities.

### TypeScript / Node.js / NestJS
- Un-awaited promises (floating), `forEach(async ...)` (doesn't await), unhandled rejections.
- `any`/type assertions (`as X`) that hide shape mismatches at runtime boundaries — validate external input (class-validator/zod).
- NestJS: guards on new controllers/resolvers, `ValidationPipe` with `whitelist`, request-scoped providers performance, circular deps via `forwardRef`.
- JS numbers for money/IDs > 2^53 (use decimal libs / strings / bigint).
- Event loop blocking (sync crypto, large JSON parse, sync fs) in request path.
- ORM (TypeORM/Prisma): N+1 via lazy relations, transactions not passed through (`manager`/`tx` client).

### React
- See ui-state. Plus: server/client component boundary (Next.js), secrets leaking into client bundle (`NEXT_PUBLIC_`), unmemoized context values causing re-render storms, uncontrolled→controlled input warnings.

### SQL (SQL Server / PostgreSQL)
- Non-sargable predicates (functions on indexed columns, implicit conversions `nvarchar` vs `varchar`).
- Parameter sniffing on skewed data (SQL Server); `OPTION (RECOMPILE)` trade-offs.
- Missing `ORDER BY` with `TOP/LIMIT` or pagination; `OFFSET` on large tables → keyset.
- Postgres: `CREATE INDEX CONCURRENTLY` for big tables, `ALTER TABLE ... ADD COLUMN ... DEFAULT` rewrite behavior on older versions, `SELECT ... FOR UPDATE SKIP LOCKED` for queues.
- Stored procs: transaction + `XACT_ABORT ON` (SQL Server), error handling with `TRY/CATCH` + rethrow.

### Go
- Ignored errors (`_ =`), error wrapping (`%w`), `defer` in loops, goroutine leaks (no ctx cancellation), data races on maps, closing channels from the receiver side, `context` not propagated.

### Flutter / Dart
- `setState` after dispose, `BuildContext` used across async gaps (`mounted` check), controllers not disposed, heavy work in `build`, missing `const` constructors in hot widgets, platform-channel error handling.

### Python
- Mutable default args, broad `except Exception`, blocking calls in async code, timezone-naive datetimes, SQL string formatting.

---

## 3. Domain overlay — financial / banking systems

Apply automatically when paths or code mention money movement, ledger, portfolio, risk, settlement, or when the manifest marks files `sensitive`.

- **Money correctness**: decimal types end to end (DB → code → JSON → UI); explicit rounding mode (banker's vs half-up) consistent with the business rule; currency always travels with amount.
- **Ledger integrity**: double-entry invariants (debits = credits) preserved; no update-in-place of posted entries (reversal entries instead); balances derived or reconciled, not only mutated.
- **Idempotency & exactly-once effects**: payment/transfer handlers dedupe by idempotency key or business key; retries cannot double-post.
- **Auditability**: who/when/what for state changes; audit log written in the same transaction as the change (or via outbox).
- **Consistency across services**: outbox pattern or saga with compensation instead of "write DB then publish" without guarantees.
- **Cut-off & calendars**: business dates vs system dates, end-of-day batch boundaries, holidays, value date vs trade date (T+n).
- **Regulatory data handling**: PII/account numbers masked in logs, retention rules, maker-checker for sensitive operations.
- **Reporting/lineage**: computed figures reproducible from source data; changes in calculation logic versioned.

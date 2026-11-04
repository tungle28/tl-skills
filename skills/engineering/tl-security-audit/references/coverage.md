# Coverage by stack

Pattern rules are single-file regex (finding = likely weakness, gate = question for the reviewer).
Review checks are applied by agents to every shard whose languages/frameworks/triggers match.

| Stack | Rule pack | Findings | Gates | Stack-specific checks | Framework detection |
|---|---|---|---|---|---|
| Docker, K8s, GitHub Actions, Azure Pipelines, Terraform, app config | `config.yml` | 16 | 2 | `infrastructure-containers`, `supply-chain-cicd` | - |
| C# / ASP.NET Core / EF Core | `csharp.yml` | 17 | 6 | - | csproj PackageReference |
| Flutter/Dart + AndroidManifest / Info.plist | `flutter.yml` | 13 | 5 | `mobile-flutter` | pubspec.yaml (`sdk: flutter`, dio, webview, storage, deep links) |
| Go — net/http, gin, echo, chi, fiber, gorm, sqlc | `go.yml` | 14 | 8 | `go-backend` | go.mod require |
| JS/TS — Node, Express, NestJS, React, Next | `javascript.yml` | 15 | 7 | - | package.json |
| Nuxt 3/4 (Nitro/h3) + Vue SFC | `nuxt.yml` | 5 | 6 | `nuxt-server` | package.json (`nuxt`, `nuxt-auth-utils`, `@sidebase/nuxt-auth`) |
| PHP — Laravel, Symfony, plain PHP, Blade | `php.yml` | 3 | 7 | `php-laravel` | composer.json (`laravel/framework`, `symfony/framework-bundle`) |
| Python — Django, Flask, FastAPI | `python.yml` | 10 | 2 | - | requirements / pyproject |
| Runaway cost + money operations (C#, JS, Python, Go) | `runaway.yml` | 1 | 5 | `runaway-cost`, `business-logic` | - |
| Secrets (all files) | `secrets.yml` | 13 | 0 | `secrets-management` | - |

Taint rule packs (`rules/taint/`, run by `scripts/taint.py`; intra-function, cross-function and
cross-file chains):

| Language | Sources | Sink kinds |
|---|---|---|
| C# | controller/PageModel action params (value types excluded), Minimal API lambdas, `Request.*` | sql, command, path, ssrf, redirect, xss, ldap |
| JS/TS | Express/Koa `req.*`, NestJS `@Param/@Query/@Body…`, Nuxt/h3 `getQuery/readBody/…`, Next `searchParams`, DOM `location/referrer/postMessage` | sql, nosql, command, code, path, ssrf, redirect, xss (DOM/React/server), template, deserialization |
| Python | Flask/Django `request.*`, FastAPI/Flask route params, Starlette `await request.json()` | sql, command, code, path, ssrf, redirect, deserialization, template, xss |
| Go | typed gin/echo/fiber/net/http accessors, `chi.URLParam`, `mux.Vars`, `ShouldBind/BodyParser/Decode(&x)` | sql (database/sql, sqlx, pgx, gorm), command, path, ssrf, redirect, xss, template |
| Dart/Flutter | deep links/`Uri.queryParameters`, GoRouter state, push `RemoteMessage.data`, WebView `JavaScriptMessage` | sqlite, webview/launcher, navigation, path |
| PHP | Laravel `$request->input/all/get/query/route/only/json/header/cookie/file/validated…`, magic `$request->field`, `request()`, `Request::`/`Input::` facades, Symfony `$request->query/request/headers->get`, `$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES`, `php://input` | sql (DB facade, `*Raw`, PDO/mysqli, Doctrine), command, code, path/include/Storage/download, upload name/dir, auth-bypass (`setUser`/`loginUsingId`), redirect, ssrf, xss (`echo`), unserialize, email/SMS recipient |

Language-agnostic checks (all stacks): access-control, authentication, injection, xss-output-encoding,
ssrf, crypto-data-protection, secrets-management, security-misconfiguration, supply-chain-cicd,
integrity-deserialization, logging-alerting, exceptional-conditions, file-handling, business-logic,
rate-limiting-dos, runaway-cost, llm-integration, api-data-exposure.

Dependency audit (deps phase): hygiene for npm, NuGet, pip, Go modules (go.sum, local replace) and
pub (pubspec.lock, `any`, unpinned git deps); CVEs via osv-scanner (covers go.mod and pubspec.lock),
npm audit, dotnet, pip-audit, govulncheck (reachability-aware for Go).

Taint skips vendored front-end assets (`app-assets/`, `third_party/`, `public/**/{lib,libs,plugins,themes,vendor}/`,
see `common.vendor_root`) and minified/generated files; the review skips the vendored assets unless
`--include-vendor`. Rules and secrets still scan them.

Not covered by rule packs (agents still review with generic checks, without scanner anchors):
Java/Kotlin backend, Ruby, Rust, Swift/Kotlin native mobile code, Bicep/CloudFormation. Composer
dependencies are audited only by osv-scanner (`composer.lock`).

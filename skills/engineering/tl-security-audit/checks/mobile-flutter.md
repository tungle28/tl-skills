---
id: mobile-flutter
title: Flutter / mobile client security
owasp: A04
cwe: [CWE-922, CWE-295, CWE-312, CWE-602, CWE-939, CWE-749]
languages: [dart, xml]
triggers: ['(?i)flutter|package:|MaterialApp|android|NSAppTransportSecurity']
---
# Flutter / mobile client (aligned with OWASP MASVS)

Threat model: the attacker owns the device and the binary. Anything in the app can be read
(strings, assets, `--dart-define` values, Firebase config), patched (client checks) or intercepted
(unless TLS is enforced and, for high-value apps, pinned). Report client issues in proportion —
the decisive controls are on the server.

- **Storage (MASVS-STORAGE):** tokens, PINs, personal/financial data in SharedPreferences, Hive,
  GetStorage, sqflite files or plain files → move to flutter_secure_storage (Keychain/Keystore);
  sensitive screens excluded from screenshots/app switcher (`FLAG_SECURE`) for banking apps;
  backups (`allowBackup`) excluding sensitive data; caches cleared on logout.
- **Network (MASVS-NETWORK):** HTTPS everywhere, no `badCertificateCallback => true`, no cleartext
  (`usesCleartextTraffic`, ATS exceptions). Certificate or public-key pinning for banking/fintech,
  with a rotation plan (backup pins).
- **Secrets in the binary (MASVS-CRYPTO/RESILIENCE):** API secrets, signing keys, encryption keys
  or `--dart-define` secrets are extractable. Anything that must stay secret belongs on a server;
  keys used for request signing from the app are at best obfuscation. Publishable keys (Firebase
  web config, Maps with app restrictions) are acceptable if restricted — say so.
- **Authentication (MASVS-AUTH):** refresh-token storage and rotation, logout revoking server-side,
  biometric (`local_auth`) used as a real unlock of a Keystore-bound credential rather than a
  boolean check that can be patched; session timeout for financial apps.
- **Platform interaction (MASVS-PLATFORM):** deep links/App Links validated and never triggering
  sensitive actions without confirmation; exported Android components; WebViews restricted to
  trusted origins with JS bridges exposing nothing sensitive; clipboard use for OTP/account numbers.
- **Client-side trust:** feature flags, roles, prices, limits and "premium" checks in Dart are UX;
  find the API that enforces them (report there if missing).
- **Resilience (hardening, usually low/info):** release builds with `--obfuscate --split-debug-info`,
  root/jailbreak and tamper detection for banking apps where required by policy; debug logging and
  `LogInterceptor` bodies off in release.
- **Code review scope note:** native plugins (Kotlin/Swift in `android/`, `ios/`) and third-party
  SDKs (analytics, ads) handle data too — list them if they receive personal data.

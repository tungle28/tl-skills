---
id: business-logic
title: Business logic — money, state machines, race conditions
owasp: A06
cwe: [CWE-840, CWE-362, CWE-367, CWE-841, CWE-20]
languages: [csharp, js, python, java, go, php, ruby, sql]
triggers: ['(?i)balance|amount|transfer|payment|withdraw|refund|order|invoice|wallet|ledger|discount|coupon|voucher|limit|quota|status|approve|state']
---
# Business logic (A06 Insecure Design)

Highest-value area for banking/finance code; scanners cannot see it.
- **Race conditions / double spend:** check-then-act on balances, vouchers, limits or stock without
  a row lock, optimistic concurrency token, atomic update (`UPDATE ... SET balance = balance - @x
  WHERE balance >= @x`) or unique constraint. Parallel requests redeeming the same voucher.
- **Idempotency:** payment, transfer and order-creation endpoints without an idempotency key;
  retries from clients or gateways applying twice.
- **Amount validation:** negative or zero amounts, decimal precision/rounding (floating point for
  money), currency mismatch, overflow; limits enforced client-side only.
- **State machines:** transitions allowed from any state (approve an already rejected loan, refund a
  refunded order); maker-checker bypass (same user creates and approves).
- **Trusting the client:** price, fee, exchange rate, or discount from the request.
- **Time/sequence:** OTP or approval not bound to the specific transaction and amount; TOCTOU between
  validation and execution.
Severity is driven by financial impact; state it concretely ("a user can redeem one voucher N times
by sending concurrent requests").

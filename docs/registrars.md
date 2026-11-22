# Registrar API notes

Each client in `internal/registrar/` follows the registrar's official documentation (read 2026-11-21).
Orders are paid from the account balance; no card payments are handled.

| Registrar | Availability check | Order | Async | Documented limits | Required setup |
|---|---|---|---|---|---|
| **Dynadot** ([REST v2](https://www.dynadot.com/domain/api-document)) | `GET /restful/v2/domains/{d}/search?show_price=true` | `POST /restful/v2/domains/{d}/register`, `X-Signature` = base64(HMAC-SHA256(secret, `key\npath?query\nX-Request-ID\nbody`)) | 500 "order created" → treated as pending | Regular 1 thread / 1 req/s; Bulk 5 / 10/s; Super Bulk 35 / 100/s; 429 = 60 s | API key + secret; IP whitelist; contact id or inline contact |
| **Porkbun** ([v3](https://porkbun.com/api/json/v3/documentation)) | `POST /domain/checkDomain/{d}` | `POST /domain/create/{d}` `{cost (cents), agreeToTerms:"yes"}`; cost quoted via `dryRun` | no | checks 10 / 10 s / account (bulk-checking accounts throttled to 50 / 5 min); 1 create attempt/s; $100 / order and default $100 / month API spend | keys with `read`+`purchase` scopes, verified email+phone, prepaid credit; premium not allowed |
| **Internet.bs** ([PDF](https://internetbs.net/internet-bs-api.pdf)) | `/Domain/Check` | `/Domain/Create` (`CloneContactsFromDomain` or `Registrant_/Admin_/Technical_/Billing_*`) | `STATUS=PENDING` | not documented | key bound to server IP |
| **Netim** ([REST 1.0](https://support.netim.com/en/docs/api-rest-1-0/)) | `GET /domain/{d}/check/` | `POST /domain/{d}/` `{idOwner,idAdmin,idTech,idBilling,duration}` | `StructOperationResponse` `Pending` | 10 concurrent sessions per account (one shared session is used) | owner contact handle |
| **Cloudflare** ([Registrar API beta](https://developers.cloudflare.com/registrar/registrar-api/)) | `POST /accounts/{id}/registrar/domain-check` | `POST /accounts/{id}/registrar/registrations` `{domain_name}`; 201 done / 202 poll `links.self` | yes (polled ~30 s, then reported pending) | 1200 req / 5 min per token | token with Registrar write; default payment method + default registrant contact in dashboard; premium not allowed; 500 domains / account |

## Outcome mapping

| Outcome | Meaning | Drop-catch reaction |
|---|---|---|
| `success` | registered to our account | stop all registrars: **won** |
| `pending` | accepted, completes later | stop that registrar (never double-order); session ends **pending** |
| `unavailable` | not registrable *yet* (normal before the drop) | retry at the registrar's pace |
| `error` | transient (timeout, 5xx, registry busy, price changed) | retry |
| `rate_limited` | throttled | wait `Retry-After` / documented cool-down, retry |
| `fatal` | credentials, funds, unsupported TLD, premium, contact data | drop that registrar for the session, log a warning |
| `dry_run` | `ORDERS_DRY_RUN=true` | nothing purchased |

Fields not shown by the docs (e.g. Netim JSON error bodies) are matched on message text; an
unrecognised failure is treated as retryable so a drop is never abandoned early.

## Internet.bs: verified against the test server

Run `LIVE_INTERNETBS=1 go test ./internal/registrar -run Live -v` (uses `https://testapi.internet.bs`
with the public `testapi`/`testpass` credentials and the `REGISTRANT_*` contact; nothing is bought).
Observed JSON responses (2026-11-22), now covered by unit tests:

| Call | Response | Mapped to |
|---|---|---|
| Check, taken (`example.com`) | `status:"UNAVAILABLE"`, `price:{"ispremium":"NO"}` | not available |
| Check, unknown name | `status:"FAILURE"` without message | error (never "available") |
| Create, taken | `status:"FAILURE"`, `product:[{status:"FAILURE", code:100017, "is not available for registration"}]` | `unavailable` (retry) |
| Create, bad/unverified contact | `code:100002` + `details:[{field,error}]` | `fatal` |
| Create, missing contact | `code:100003` | `fatal` |
| CloneContactsFromDomain not ours | `code:100005` "Permission denied" | `fatal` |
| Wrong API key/password | `code:107002` | `fatal` |
| Some TLDs on the test server (`.biz`, `.xyz`, `.co`) | `code:107015` "Unexpected ERROR" | `error` (retry) |

The test server never reports a random name as AVAILABLE and refuses to create any test name, so a
real `SUCCESS` cannot be produced there; the success shapes from the PDF (`status`/`product_0_status`
`SUCCESS`, `PENDING`) are unit-tested. Unverified contact e-mails are rejected by Internet.bs
(code 100002), so use a verified `REGISTRANT_EMAIL` or `INTERNETBS_CLONE_CONTACTS_FROM`.

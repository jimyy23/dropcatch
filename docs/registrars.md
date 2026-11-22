# Registrar API notes

Each client in `internal/registrar/` follows the registrar's official documentation (read 2026-11-21).
Orders are paid from the account balance; no card payments are handled.

| Registrar | Availability check | Order | Async | Documented limits | Required setup |
|---|---|---|---|---|---|
| **Dynadot** ([REST v2](https://www.dynadot.com/domain/api-document)) | `GET /restful/v2/domains/{d}/search?show_price=true` | `POST /restful/v2/domains/{d}/register`, `X-Signature` = base64(HMAC-SHA256(secret, `key\npath?query\nX-Request-ID\nbody`)) | 500 "order created" → treated as pending | Regular 1 thread / 1 req/s; Bulk 5 / 10/s; Super Bulk 35 / 100/s; 429 = 60 s | API key + secret; IP whitelist; contact id or inline contact |
| **Porkbun** ([v3](https://porkbun.com/api/json/v3/documentation)) | `POST /domain/checkDomain/{d}` | `POST /domain/create/{d}` `{cost (cents), agreeToTerms:"yes"}`; cost quoted via `dryRun` | no | checks 10 / 10 s / account (bulk-checking accounts throttled to 50 / 5 min); 1 create attempt/s; $100 / order and default $100 / month API spend | keys with `read`+`purchase` scopes, verified email+phone, prepaid credit; premium not allowed |
| **Internet.bs** ([PDF](https://internetbs.net/internet-bs-api.pdf)) | `/Domain/Check` | `/Domain/Create` (`CloneContactsFromDomain` or `Registrant_/Admin_/Technical_/Billing_*`) | `STATUS=PENDING` | not documented | key bound to server IP |
| **Netim** ([REST 1.0](https://support.netim.com/en/docs/api-rest-1-0/)) | `GET /domain/{d}/check/` | `POST /domain/{d}/` `{idOwner,idAdmin,idTech,idBilling,duration}` | `StructOperationResponse` `Pending` | 10 concurrent sessions per account (one shared session is used) | owner contact handle |
| **Regery** ([external API](https://regery.com/partnership/api/introduction)) | `GET /v1/domains/{d}/availability` (`available`, `notAvailable`, `internal`, `restricted`, `notSupported`, `rateLimit`, `error`) | `POST /v1/domains/{d}` `{period, autoRenew, contacts:{registrant}, nameservers}`; registrant from `POST /v1/contacts` (state as `CA_ON`) or `REGERY_CONTACT_ID` | `{"pending":true}`, result in the message queue | check 60/min & 1800/h, register 10/min, contacts 60/min, balance 4/h & 12/day | `Authorization: KEY:SECRET`; `TST_` test keys only accept names containing the test domain token |
| **NameSilo** ([API](https://www.namesilo.com/api-reference)) | `GET /api/checkRegisterAvailability?domains=` (`available[]` with price/premium, `unavailable`, `invalid`) | `GET /api/registerDomain?domain=&years=1` + `contact_id` or inline `fn,ln,ad,cy,st,zp,ct,em,ph`; no `payment_id` = account funds | no (301/302 = success with defaults) | not documented (code 400 = previous request still processing) | API key (optionally IP-bound); all calls GET |
| **Spaceship** ([API](https://docs.spaceship.dev/)) | `GET /v1/domains/{d}/available` (`available`, `taken`, `invalidDomainName`, `tldNotSupported`, `unexpectedError`; premium via `premiumPricing`) | `POST /v1/domains/{d}` `{autoRenew:false, years:1, privacyProtection:{level,userConsent}, contacts:{registrant,admin,tech,billing}}`; contact from `SPACESHIP_CONTACT_ID` or `PUT /v1/contacts` | 202 + `spaceship-async-operationid`, polled via `GET /v1/async-operations/{id}` (~45 s, then reported pending) | check 5/domain/300 s & 30/user/30 s; register 30/user/30 s; async status 60/300 s | `X-API-Key` + `X-API-Secret`; scopes domains:read, domains:billing, contacts:read/write, asyncoperations:read |
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

Regery errors (observed with a test key) are JSON `{code, message, type[, parameter, value]}`:
400 `validation` (`valueRequired`, `valueInvalid`) → fatal; 401 (empty body, bad key/secret) → fatal;
403 `apiGateway/wrongApiKeyMode` (test key used on a real name) → fatal for orders, unsupported for checks;
429 `apiGateway/rateLimit` with "cooldown: HH:MM:SS" in the message → waits that long;
500 `domains/objectExists` ("already exists") → unavailable. Regery's `dns`
availability source can report held/hidden domains as available; the monitor cross-checks it.

Fields not shown by the docs (e.g. Netim and Regery JSON error bodies) are matched on message text; an
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

## Account balances (Registrars page)

| Registrar | Endpoint | Verified live |
|---|---|---|
| Dynadot | `GET /restful/v2/accounts/info` (signed) → `account_info.balance_list` | yes |
| Porkbun | `GET /account/balance` → cents | yes |
| Internet.bs | `/Account/Balance/Get` → `balance[]` per currency | yes |
| Netim | `GET /account/` → `BALANCE_AMOUNT` (StructQueryResellerAccount) | no keys |
| Regery | `GET /v1/account/balance` → number (limit 4/hour; cached 20 min) | yes (test key) |
| NameSilo | `getAccountBalance` → `balance` | yes |
| Cloudflare | none: registrations are charged to the account's payment method | n/a |
| Spaceship | none in the API | n/a |

Dynadot note: the docs include `X-Request-ID` in the string to sign, but the live API only accepts
signatures whose request-id line is empty (`key\npath\n\nbody`), verified 2026-11-22.

## NameSilo: verified against production (read-only)

`LIVE_NAMESILO=1 go test ./internal/registrar -run LiveNameSilo -v` calls only
`getAccountBalance`, `contactList` and `checkRegisterAvailability` (orders are dry runs).
The live `checkRegisterAvailability` reply differs from the documented example, and all shapes
are handled and unit-tested:

| Case | Live shape |
|---|---|
| one available | `"available": {"domain": {"domain":"x.org","price":10.79,"renew":14.99,"premium":0,"duration":10}}` |
| several available | `"available": [{"domain":"a.com","price":19.99,...}, ...]` |
| one unavailable | `"unavailable": {"domain":"example.com"}` |
| several unavailable | `"unavailable": ["example.com","example.net"]` |
| unsupported TLD | `"invalid": {"domain":"foobar123.lu"}` or `["foobar123.lu", ...]` |

NameSilo does not sell `.lu` or `.tw` (reported as `invalid`).

## Spaceship: verified against production (read-only)

`LIVE_SPACESHIP=1 go test ./internal/registrar -run LiveSpaceship -v` calls only
`GET /v1/domains/{d}/available` and `GET /v1/contacts/{id}`. Observed: `example.com` → `taken`,
an unused `.com` → `available`, `.lu`/`.tw` → `tldNotSupported`, `bad_name!.com` →
`invalidDomainName`. Errors are `application/problem+json` `{detail}` with a
`spaceship-error-code` header; mapped by HTTP status and code text (429 back off, 401/403 fatal,
400/422 validation fatal unless "not available", 5xx retry).

## Regery: verified with a test key

`LIVE_REGERY=1 go test ./internal/registrar -run LiveRegery -v` (requires a `TST_` key plus
`REGERY_TEST_DOMAIN_TOKEN` / `REGERY_TEST_PHONE`; refuses live keys). Observed 2026-11-22:

- `<anything>-<token>.com` → `available`; `…-xna-<token>.com` → `notAvailable`; unknown zone →
  `notSupported`; a name without the token (e.g. `example.com`) → 403 `wrongApiKeyMode`.
- Contacts: `POST /v1/contacts` is idempotent on the data *excluding* the state, so a contact saved
  without a state keeps being returned; the client therefore names contacts after their region.
- Registration needs `registrant.state` as a region code (`CA_ON`, `US_NY`, list at
  https://regery.com/partnership/api/areas); plain `ON` is accepted when saving the contact but
  rejected (`valueInvalid`) when registering.
- Register → `{"pending":false}` (success); repeating it → 500 `objectExists`.
- In test mode the `-xna-` token only affects availability checks: registering such a name succeeds.

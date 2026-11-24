# Dropcatch

Self-hosted domain monitor and drop-catcher. You add domains, watch their WHOIS/RDAP state, and the moment one becomes available, it places orders with one or more registrars at the same time.

Single Go binary, SQLite, server-rendered admin UI, and a PHP WHOIS sidecar. It uses the same stack, UI style and authentication as psl-monitor.

## Quick start (Docker)

```sh
git clone https://github.com/jimyy23/dropcatch.git
cd dropcatch
cp .env.example .env        # set ADMIN_USERNAME / ADMIN_PASSWORD, registrar keys, Telegram/Twilio
docker compose up -d --build
open http://localhost:8080
```

Start with `ORDERS_DRY_RUN=true` to rehearse. Drop-catch sessions run and log every step, but nothing is bought.

### EasyPanel

Create an app from this repo using **Docker Compose** (`docker-compose.yml`). Then:

- Put the variables from `.env.example` into the service environment.
- Set `BASE_URL=https://your.domain` and `TRUST_PROXY=true`.
- Expose port 8080 of `dropcatch` through the EasyPanel domain.
- Keep the `dropcatch-data` volume. It holds the database at `/data/dropcatch.db`.

The `whois` service stays internal.

Admin CLI inside the container:

```sh
docker compose exec dropcatch dropcatch user create alice 'long-password-here'
docker compose exec dropcatch dropcatch user reset-password alice 'new-long-password'
```

## Features

- **Domains page:** add one or many domains (IDNs allowed; subdomains are rejected). Each row shows:
  - status (available / registered / pending delete / redemption / reserved), expiry and registrar
  - when it was last checked and when the next check runs
  - per-domain switches for monitoring, drop-catch, Telegram and phone call
  - bulk actions, a live-refreshing list, and filters (armed, available, pending delete, failing…)
- **Domain page:** registration details (registrar, dates, EPP status, nameservers, raw WHOIS), every control, a "test all sources" button that compares every checker's answer, and the history of checks, orders and events.
- **Per-domain controls:**
  - monitor on/off and its interval
  - drop-catch on/off and an optional UTC window (start/end)
  - a faster check interval while armed
  - how many minutes to keep placing orders
  - which registrars to use (several can be selected)
  - automatic drop-catch on pending delete
  - Telegram on/off and Twilio call on/off
- **Clocks:** the header shows a live UTC clock next to the browser clock. Catch-window inputs show their browser-local equivalent as you type, so time-zone mistakes are visible.
- **One worker per domain:** a slow registry or a running drop-catch never delays another domain.
- **Registrar support per suffix:** prices from [nazhumi](https://www.nazhumi.com/llms.txt) (every registrar for the suffix), with miqingju as the fallback, cached for a day. The domain page marks which of your registrars sell the suffix, and at what price.
- **Registrars page:** credential status and live account balances for every configured registrar (read-only API calls).
- **Register now:** on a domain's page, after a browser confirmation, orders go out immediately to every selected registrar without an availability check, for the domain's order duration.
- **Global settings page:** non-secret parameters only. Secrets live in `.env`, never in the database.

## How availability is decided

1. **WHOIS/RDAP** (sidecar in `whois-sidecar/`, based on [reg233/whois-domain-lookup](https://github.com/reg233/whois-domain-lookup)) is the primary source. It also supplies status and dates. WHOIS and RDAP are queried **separately** (never the upstream merged mode, where a cached RDAP answer overrode live WHOIS): port-43/web WHOIS first, RDAP when WHOIS fails; for `.tw`, RDAP first with registry-cache busting. Empty, unparseable or failed answers never count as "available".
2. When the internal WHOIS sidecar errors or is rate-limited for a suffix, the check tries the **external WHOIS sidecars** listed in `EXTERNAL_WHOIS_API_ENDPOINTS` (the same PHP program deployed elsewhere, so other IPs and registry rate-limit budgets), in order. They also supply registration data. Only after those does it fall back to **Cloudean** and **Regery**. These are keyless web checkers, which were probed for rate limits before use. After those come the **availability APIs** of configured registrars (Dynadot, Porkbun, Internet.bs, Netim, Cloudflare, Regery, NameSilo, Spaceship), which never place orders and are capped per hour.
3. Health is tracked **per suffix and per source**. A rate-limited or repeatedly failing source is benched for that suffix, then retried once the cooldown ends. A source that doesn't sell the suffix is skipped for a week. WHOIS becomes the primary source again as soon as it answers. See the **Sources** page.

Built-in protection for the fallbacks:

- **Regery:** limited to a local hourly budget, below its probed per-IP limit, with a reserve kept for armed domains. Its session ticket is refreshed proactively, and a suspiciously fast "available" is re-checked, because without a valid ticket Regery returns fake answers.
- **Cloudean:** names are validated locally first, because Cloudean silently rewrites invalid names before checking them.
- **WHOIS:** requests are spaced per suffix, and armed domains jump the queue.

## Drop-catch

A domain is **armed** when it has at least one registrar selected and either:

- drop-catch is on and now (UTC) is inside the optional window, or
- auto-catch on pending delete is on and a pending-delete status has been seen.

While armed, the domain is checked at its faster interval.

On the **first available signal**, orders go to **all selected registrars concurrently**. Each one retries at its documented pace, and a session ends when:

- one registrar succeeds (**won**)
- a registrar accepts the order asynchronously (**pending**; that registrar is never ordered twice)
- the monitor sees the domain registered twice in a row (**lost**)
- the duration or window ends
- you stop it

Errors that retrying can't fix (keys, funds, premium, unsupported suffix) drop only that registrar. Registrars receive only order calls during a session. Availability comes from the monitor, so no paid or rate-limited order calls are wasted.

## Fresh registry data (freshness guard)

Registry answers can come from old copies: TWNIC's RDAP is served by replicas holding different database snapshots
(minutes to 4+ hours old), so consecutive answers alternated between a new registration and the old pending-delete
record. Every monitor answer therefore goes through a guard before it may change anything:

- **Never backwards.** An answer from an older registry snapshot than one already seen, with an older creation or
  expiry date, or a pending-delete answer predating the current state is ignored. A registered domain with a known
  creation date does not revert to pending delete or available on an undated answer.
- **Agreement.** A status change needs 2 consecutive agreeing answers, except for self-evident ones (a direct
  port-43 answer, a delegation appearing in the live zone, a registration created after the last known one).
  Orders still start on the first plausible "available".
- **Debug stream.** Every raw answer is stored with request start/end (ms) and the guard's verdict
  (*committed, pending n/m, agrees, stale, weak, no verdict*) on the domain page under "Registry answers";
  only committed changes go to Events. Detection lag is measured from the first fresh answer.

**.tw direct source** (`TWNIC direct`, on by default): port-43 WHOIS `whois.twnic.net.tw` (live; TWNIC limits it
per IP: one query per ~6 s is fine, faster gets the IP blocked for ~6 min, so it is shared by all .tw domains and
paced at 6.5 s), RDAP `ccrdap.twnic.tw` with its snapshot time, and the live `.tw` DNS zone (republished every
30-90 s, not rate-limited: a delegation appearing means registered). The sidecar remains the fallback.

**Release watch.** Around a domain's expected release the monitor polls fast: `.tw` 05:55-06:10 UTC every second
(DNS each tick, port 43 whenever the per-IP budget allows, RDAP every 30 s), `.ca` every 10 s through the TBR
session, `.lu` every 1-2 min from End Date -1 day 23:00 to End Date 12:00 UTC.

## Scheduled fire (registry release time)

Some registries release pending-delete domains at a fixed, predictable time. For those, waiting for a monitor
signal is too slow: on `.tw` the fastest registrars create names 11 to 135 seconds after release. A domain can
have a **fire time**: from *lead* seconds before it until *duration* minutes after it, orders go to every
selected registrar without checking availability and without the monitor stopping them. It runs once per fire
time, and only while drop-catch (or auto pending-delete) is on.

The fire time is set by hand (UTC), or computed from a suffix **release rule** and the registry data. Switching a rule on applies its default lead and duration:

| Rule | Suffixes | When | Defaults |
|---|---|---|---|
| `.tw` (TWNIC) | `.tw` and all its second-level suffixes (`.com.tw`, `.net.tw`, `.org.tw`, `.idv.tw`, …) | 33rd day after the expiry **date in Taiwan time (UTC+8)**, at 06:00:00 UTC. Example: expiry 2026-10-27 00:00 UTC+8 → release 2026-11-29 06:00:00 UTC | lead 10 s, 5 min |
| `.lu` (DNS-LU) | `.lu` | `ACTIVE (PENDING_DELETE)` for 29 days, then deleted in a **sweep on the End Date** (UTC day it entered pending delete + 29; ExpiredDomains' End Date): most names between 00:00 and ~01:00 UTC, some later in the morning, a few a day early. **No blind orders**: the registry is watched from End Date -1 day 23:00 to 12:00 UTC (every 60 s 00:00-06:00, else 2 min; `whois.dns.lu` is rate-limited, so `.lu` lookups are spaced ≥ 8 s) and orders start on the first "unregistered". Each drop is logged with its window ("DROP between … and …"). Computed only when the switch to pending delete was observed; otherwise enter the End Date 00:00 UTC by hand (a manual time is fired blind) | watch 00:00-12:00 |
| `.ca` (CIRA TBR) | `.ca` | To-Be-Released session, **every Wednesday 19:00:00 UTC** year-round. The date comes from **CIRA's published TBR list** (`https://www.cira.ca/en/wp-json/cira/v1/domains/tbr`, fetched hourly while a `.ca` domain is tracked); a listed domain gets its fire time even before the monitor sees pending delete. For a domain not on the list yet, it is computed from when the domain turned pending delete (registry "updated" date, else first seen by the monitor): before Monday 07:00 UTC → that Wednesday; Monday 07:00 to Wednesday 19:00 → the following Wednesday. Sessions last up to ~60 min; leftovers reach general availability ~30 min later | lead 10 s, 90 min |

When a domain becomes registered, the event log records the **registry creation time** and how long after it the
monitor noticed.

## Notifications

Telegram and Twilio voice calls are optional, configured in `.env`, and switched per domain. The admin is notified **once per availability episode**, and only when availability is **confirmed**:

> WHOIS/RDAP says available **AND** (Cloudean **OR** Regery **OR** a registrar API that supports the suffix) says available.

Orders don't wait for this confirmation. A setting lets two independent fallbacks confirm on their own for suffixes that WHOIS can't answer. It is optional and off by default.

## Development

```sh
go test ./...
docker run -d -p 18090:80 $(docker build -q https://github.com/reg233/whois-domain-lookup.git#3bfffebbc726fb794cddae19bf8e7fb49059bda7)   # WHOIS sidecar
DB_PATH=./data/dev.db ADMIN_USERNAME=admin ADMIN_PASSWORD=admin-pass-123 \
  WHOIS_URL=http://127.0.0.1:18090 ORDERS_DRY_RUN=true go run ./cmd/dropcatch
```

Layout:

| Path | Contents |
|---|---|
| `internal/domainutil` | name parsing (IDN, public suffix) |
| `internal/monitor` | WHOIS, Cloudean, Regery and registrar sources, per-suffix source selection, confirmation |
| `internal/registrar` | the eight registrar APIs (see [docs/registrars.md](docs/registrars.md)) |
| `internal/engine` | per-domain workers, drop-catch sessions, notifications |
| `internal/pricing` | suffix/registrar cache |
| `internal/notify` | Twilio, Telegram |
| `internal/store` | SQLite |
| `internal/web` | UI |

The WHOIS sidecar is [reg233/whois-domain-lookup](https://github.com/reg233/whois-domain-lookup), used unmodified and pinned to commit `3bfffeb`. `docker compose` builds it straight from that GitHub commit, so a plain clone is enough (no submodules), which suits EasyPanel. `third_party/whois-domain-lookup` is the same commit as an optional git submodule, for reading the code or building offline (`git submodule update --init`, then `WHOIS_BUILD_CONTEXT=./third_party/whois-domain-lookup`). To move the pin, update the commit in `docker-compose.yml` and the submodule together.

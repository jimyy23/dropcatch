# Dropcatch

Self-hosted domain monitor and drop-catcher. You add domains, watch their WHOIS/RDAP state, and the moment one becomes available, it places orders with one or more registrars at the same time.

Single Go binary, SQLite, server-rendered admin UI, and a PHP WHOIS sidecar. It uses the same stack, UI style and authentication as psl-monitor.

## Quick start (Docker)

```sh
git clone --recurse-submodules https://github.com/jimyy23/dropcatch.git
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
- If EasyPanel's git source does not fetch submodules, run `git submodule update --init` in the build context first.

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
- **Global settings page:** non-secret parameters only. Secrets live in `.env`, never in the database.

## How availability is decided

1. **WHOIS/RDAP** (sidecar [reg233/whois-domain-lookup](https://github.com/reg233/whois-domain-lookup), git submodule in `third_party/`) is the primary source. It also supplies status and dates. Empty or unparseable answers never count as "available".
2. When WHOIS errors or is rate-limited for a suffix, the check falls back to **Cloudean** and **Regery**. These are keyless web checkers, which were probed for rate limits before use. After those come the **availability APIs** of configured registrars (Dynadot, Porkbun, Internet.bs, Netim, Cloudflare), which never place orders and are capped per hour.
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

## Notifications

Telegram and Twilio voice calls are optional, configured in `.env`, and switched per domain. The admin is notified **once per availability episode**, and only when availability is **confirmed**:

> WHOIS/RDAP says available **AND** (Cloudean **OR** Regery **OR** a registrar API that supports the suffix) says available.

Orders don't wait for this confirmation. A setting lets two independent fallbacks confirm on their own for suffixes that WHOIS can't answer. It is optional and off by default.

## Development

```sh
go test ./...
docker run -d -p 18090:80 $(docker build -q third_party/whois-domain-lookup)   # WHOIS sidecar
DB_PATH=./data/dev.db ADMIN_USERNAME=admin ADMIN_PASSWORD=admin-pass-123 \
  WHOIS_URL=http://127.0.0.1:18090 ORDERS_DRY_RUN=true go run ./cmd/dropcatch
```

Layout:

| Path | Contents |
|---|---|
| `internal/domainutil` | name parsing (IDN, public suffix) |
| `internal/monitor` | WHOIS, Cloudean, Regery and registrar sources, per-suffix source selection, confirmation |
| `internal/registrar` | the five registrar APIs (see [docs/registrars.md](docs/registrars.md)) |
| `internal/engine` | per-domain workers, drop-catch sessions, notifications |
| `internal/pricing` | suffix/registrar cache |
| `internal/notify` | Twilio, Telegram |
| `internal/store` | SQLite |
| `internal/web` | UI |

`third_party/whois-domain-lookup` is a git submodule pointing at [reg233/whois-domain-lookup](https://github.com/reg233/whois-domain-lookup), pinned to commit `3bfffeb` and used unmodified. If you cloned without `--recurse-submodules`, run `git submodule update --init`. To move the pin: `git -C third_party/whois-domain-lookup pull origin main`, test, then commit the new submodule commit.

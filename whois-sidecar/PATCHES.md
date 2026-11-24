# dropcatch patches to whois-domain-lookup

Vendored from https://github.com/reg233/whois-domain-lookup at commit
`3bfffebbc726fb794cddae19bf8e7fb49059bda7` (no license file upstream; used
unmodified except for the changes below, kept minimal so upstream updates can
be re-applied).

## src/RDAP.php: registry CDN cache busting

TWNIC serves `.tw` RDAP (`https://ccrdap.twnic.tw/tw/domain/<name>`) through
a CDN that caches per exact URL (`x-cache: HIT`). Observed 2026-11-22: copies
over 3 h old ("last update of RDAP database" 18:05Z served at 21:22Z), so a
domain registered at 06:00:52Z was still reported as free/pending delete
hours later. Query strings are rejected (404), but percent-encoding any
character of the name (`s%69na.com.tw`) is decoded by the origin and is a new
cache key (`x-cache: MISS`, current database snapshot).

- `CACHE_BUST_HOSTS` (+ env `CACHE_BUST_RDAP_HOSTS`, comma list): RDAP hosts
  that get a randomly percent-encoded name on every request.
- All RDAP requests: fresh connection, `Cache-Control: no-cache`.

TWNIC's RDAP database itself refreshes about every 30 minutes; the port-43
WHOIS server `whois.twnic.net.tw` is live but is firewalled for some client
networks, so the monitor uses RDAP first for `.tw` and WHOIS as fallback.

## How dropcatch calls the service

dropcatch never uses the merged default mode (WHOIS + RDAP, where RDAP flags
override WHOIS): it asks `whois=1` or `rdap=1` separately and uses one answer.

## Note (2026-11-24): cache busting is not enough for TWNIC

Percent-encoded URLs do reach the origin (`x-cache: MISS`), but the origin is a
set of replicas holding different database snapshots ("last update of RDAP
database" ranged from 30 min to 4 h old across requests at the same moment),
and some URL forms get HTTP 429. dropcatch therefore no longer relies on the
sidecar for `.tw`: it queries TWNIC directly (`internal/monitor/twnic.go`) and
discards answers from older snapshots (`internal/engine/observe.go`).

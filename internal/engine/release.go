package engine

import (
	"fmt"
	"strings"
	"time"

	"dropcatch/internal/store"
)

// ReleaseInput is what a rule may use to compute a release time.
type ReleaseInput struct {
	Suffix             string
	Expires            time.Time // registry expiry
	PendingDelete      bool      // currently in pending delete (TBR for .ca)
	PendingDeleteSince time.Time // when the pending-delete status began (registry "last changed" or first seen)
	Listed             time.Time // session from the registry's published release list (CIRA TBR), if listed
	// PendingDeleteObserved: the monitor saw the switch into pending delete
	// (the domain was tracked before), so PendingDeleteSince is accurate to
	// the monitor interval.
	PendingDeleteObserved bool
}

// ReleaseRule describes when a registry releases a deleted domain, so a
// drop-catch can fire blind at that moment instead of waiting for a monitor
// signal (registry data seen through WHOIS/RDAP caches can lag by hours).
type ReleaseRule struct {
	Name     string   // shown in the UI, e.g. ".tw (TWNIC)"
	Suffixes []string // TLD and its second-level suffixes
	Note     string
	// Defaults applied when the rule is switched on for a domain.
	DefaultLead     int // seconds before release
	DefaultDuration int // minutes after release
	Compute         func(in ReleaseInput) (time.Time, error)
	// NoBlindFire: the release is a window, not an instant, so no blind
	// orders are placed at the computed time; the watch below polls the
	// registry and orders start on the first plausible "available".
	NoBlindFire bool
	// Watch is the intensified polling around a release (nil: default
	// window of 5 min before to 10 min after, every 2 s).
	Watch func(release, now time.Time) (from, to time.Time, every time.Duration)
}

// WatchWindow returns the intensified polling window around a release.
func (r ReleaseRule) WatchWindow(release, now time.Time) (time.Time, time.Time, time.Duration) {
	if r.Watch != nil {
		return r.Watch(release, now)
	}
	return DefaultWatch(release, now)
}

// DefaultWatch: 5 min before to 10 min after, every 2 s.
func DefaultWatch(release, _ time.Time) (time.Time, time.Time, time.Duration) {
	return release.Add(-5 * time.Minute), release.Add(10 * time.Minute), 2 * time.Second
}

var taipei = time.FixedZone("UTC+8", 8*3600)

// ReleaseRules are registry release schedules.
var ReleaseRules = []ReleaseRule{
	{
		Name:            ".tw (TWNIC)",
		Suffixes:        []string{"tw", "com.tw", "net.tw", "org.tw", "idv.tw", "game.tw", "ebiz.tw", "club.tw"},
		Note:            "released 06:00:00 UTC (14:00 Taiwan) on the 33rd day after the expiry DATE in Taiwan time (UTC+8); confirmed on 20+ drops, Nov 2026",
		DefaultLead:     10,
		DefaultDuration: 5,
		Compute:         twRelease,
		// 05:55 to 06:10 UTC: every second (the zone delegation is checked
		// each tick; port-43 WHOIS as often as TWNIC's per-IP limit allows)
		Watch: func(release, _ time.Time) (time.Time, time.Time, time.Duration) {
			return release.Add(-5 * time.Minute), release.Add(10 * time.Minute), time.Second
		},
	},
	{
		Name:     ".ca (CIRA TBR)",
		Suffixes: []string{"ca"},
		Note: "To-Be-Released session every Wednesday 19:00:00 UTC (year-round). A domain enters TBR when it turns pending delete " +
			"after redemption. The session date comes from CIRA's published TBR list (fetched hourly); for a domain not on the list yet " +
			"it is computed: deleted before Monday 07:00 UTC -> that Wednesday, Monday 07:00 to Wednesday 19:00 -> the following " +
			"Wednesday (2.5 to 9.5 days on the list). Sessions last up to ~60 min; unclaimed names reach general availability about " +
			"30 min after",
		DefaultLead:     10,
		DefaultDuration: 90,
		Compute:         caRelease,
		Watch: func(release, _ time.Time) (time.Time, time.Time, time.Duration) {
			return release.Add(-2 * time.Minute), release.Add(90 * time.Minute), 10 * time.Second
		},
	},
	{
		Name:     ".lu (DNS-LU)",
		Suffixes: []string{"lu"},
		Note: "WHOIS shows ACTIVE (PENDING_DELETE) for 29 days, then the domain is deleted in a sweep on the End Date " +
			"(= day it entered pending delete + 29, UTC; ExpiredDomains' End Date): most names go between 00:00 and ~01:00 UTC, " +
			"some later in the morning, a few a day early. No blind orders: the registry is polled from End Date -1 day 23:00 to " +
			"End Date 12:00 UTC (every 60 s 00:00-06:00, else every 2 min; whois.dns.lu is rate-limited) and orders start on " +
			"the first 'unregistered'. The flip time is logged to narrow the window. Computed only when the switch to pending " +
			"delete was observed; otherwise enter the End Date (00:00 UTC) as the fire time",
		DefaultLead:     0,
		DefaultDuration: 720,
		Compute:         luRelease,
		NoBlindFire:     true,
		Watch: func(release, now time.Time) (time.Time, time.Time, time.Duration) {
			from, to := release.Add(-time.Hour), release.Add(12*time.Hour)
			every := 2 * time.Minute
			if !now.Before(release) && now.Before(release.Add(6*time.Hour)) {
				every = time.Minute
			}
			return from, to, every
		},
	},
}

// luRelease: End Date 00:00 UTC = the UTC day the domain turned pending
// delete + 29 days. Needs an observed transition (a domain added while
// already pending delete has an unknown start).
func luRelease(in ReleaseInput) (time.Time, error) {
	if !in.PendingDelete {
		return time.Time{}, fmt.Errorf("not in pending delete yet")
	}
	if in.PendingDeleteSince.IsZero() || !in.PendingDeleteObserved {
		return time.Time{}, fmt.Errorf("pending-delete start not observed (domain added while already pending delete): enter ExpiredDomains' End Date, 00:00 UTC, as the fire time")
	}
	t := in.PendingDeleteSince.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 29), nil
}

// RuleFor returns the release rule of a suffix.
func RuleFor(suffix string) (ReleaseRule, bool) {
	suffix = strings.ToLower(suffix)
	for _, r := range ReleaseRules {
		for _, s := range r.Suffixes {
			if s == suffix {
				return r, true
			}
		}
	}
	return ReleaseRule{}, false
}

// ExpectedRelease computes the release instant for a domain, or an error
// when the suffix has no rule or the rule's input is missing.
func ExpectedRelease(in ReleaseInput) (time.Time, error) {
	r, ok := RuleFor(in.Suffix)
	if !ok {
		return time.Time{}, fmt.Errorf("no release rule for .%s", in.Suffix)
	}
	return r.Compute(in)
}

// twRelease: expiry date in UTC+8, plus 33 days, at 06:00:00 UTC.
// Example: expiry 2026-10-27 00:00:00 UTC+8 (= 2026-10-26T16:00:00Z)
// -> 2026-11-29 06:00:00 UTC.
func twRelease(in ReleaseInput) (time.Time, error) {
	if !in.PendingDelete {
		// a registered domain's expiry is a year away and may be renewed:
		// no release until the registry shows pending delete
		return time.Time{}, fmt.Errorf("not in pending delete")
	}
	if in.Expires.IsZero() {
		return time.Time{}, fmt.Errorf("expiry date unknown")
	}
	local := in.Expires.In(taipei)
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 33)
	return day.Add(6 * time.Hour), nil
}

// caRelease: the session from CIRA's TBR list when the domain is on it,
// else computed for a domain that turned pending delete at `since`. Sessions are Wednesdays 19:00 UTC; deletions from Monday 07:00 UTC
// up to the session start go to the following week's session.
func caRelease(in ReleaseInput) (time.Time, error) {
	if !in.Listed.IsZero() {
		return in.Listed, nil // CIRA's published TBR list is authoritative
	}
	if !in.PendingDelete {
		return time.Time{}, fmt.Errorf("not in pending delete (TBR) yet")
	}
	if in.PendingDeleteSince.IsZero() {
		return time.Time{}, fmt.Errorf("pending-delete start unknown")
	}
	return caSession(in.PendingDeleteSince), nil
}

// caSession returns the TBR session for a deletion at t.
func caSession(t time.Time) time.Time {
	t = t.UTC()
	d := time.Date(t.Year(), t.Month(), t.Day(), 19, 0, 0, 0, time.UTC)
	for d.Weekday() != time.Wednesday || !d.After(t) {
		d = d.AddDate(0, 0, 1)
	}
	// cutoff: Monday 07:00 UTC of the session's week (2.5 days before it)
	if !t.Before(d.Add(-60 * time.Hour)) {
		d = d.AddDate(0, 0, 7)
	}
	return d
}

// ReleaseInputFor builds the rule input from a domain's stored registry data.
// The pending-delete start is the registry "updated" date when it plausibly
// marks the deletion (not after we first saw the status, and at most 10 days
// before it), else the time the monitor first saw pending delete.
func ReleaseInputFor(d *store.Domain) ReleaseInput {
	in := ReleaseInput{Suffix: d.Suffix, Expires: d.Expires, PendingDelete: d.PendingDelete || d.Status == store.StatusPendingDelete}
	if in.PendingDelete {
		if d.Status == store.StatusPendingDelete {
			in.PendingDeleteSince = d.StatusSince
			in.PendingDeleteObserved = d.StatusSince.After(d.CreatedAt.Add(2 * time.Minute))
		}
		if u := d.Updated; !u.IsZero() && (in.PendingDeleteSince.IsZero() ||
			!u.After(in.PendingDeleteSince) && in.PendingDeleteSince.Sub(u) <= 10*24*time.Hour) {
			in.PendingDeleteSince = u
		}
	}
	return in
}

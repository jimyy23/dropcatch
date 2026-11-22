package engine

import (
	"fmt"
	"strings"
	"time"
)

// ReleaseRule describes when a registry releases a pendingDelete domain, so
// a drop-catch can fire blind at that moment instead of waiting for a
// monitor signal (registry data seen through WHOIS/RDAP caches can lag by
// hours).
type ReleaseRule struct {
	Suffixes []string       // TLD and its second-level suffixes, e.g. tw, com.tw
	Zone     *time.Location // zone in which the registry's expiry DATE counts
	Days     int            // release = expiry date (in Zone) + Days ...
	At       string         // ... at this UTC time of day, "HH:MM:SS"
	Note     string
}

var taipei = time.FixedZone("UTC+8", 8*3600)

// ReleaseRules are empirically confirmed registry release schedules.
var ReleaseRules = []ReleaseRule{{
	Suffixes: []string{"tw", "com.tw", "net.tw", "org.tw", "idv.tw", "game.tw", "ebiz.tw", "club.tw"},
	Zone:     taipei,
	Days:     33,
	At:       "06:00:00",
	Note:     "TWNIC: 33rd day after the expiry date in Taiwan time (UTC+8), 06:00:00 UTC (14:00 Taiwan); confirmed on 20+ drops, Nov 2026",
}}

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

// ExpectedRelease computes the release instant from the registry expiry.
// Example (.tw): expiry 2026-10-27 00:00:00 UTC+8 (= 2026-10-26T16:00:00Z)
// -> 2026-11-29 06:00:00 UTC.
func ExpectedRelease(suffix string, expires time.Time) (time.Time, error) {
	r, ok := RuleFor(suffix)
	if !ok {
		return time.Time{}, fmt.Errorf("no release rule for .%s", suffix)
	}
	if expires.IsZero() {
		return time.Time{}, fmt.Errorf("expiry date unknown")
	}
	local := expires.In(r.Zone)
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, r.Days)
	var hh, mm, ss int
	if _, err := fmt.Sscanf(r.At, "%d:%d:%d", &hh, &mm, &ss); err != nil {
		return time.Time{}, err
	}
	return day.Add(time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute + time.Duration(ss)*time.Second), nil
}

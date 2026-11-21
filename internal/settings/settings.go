// Package settings defines admin-editable global settings stored in the DB.
// Secrets are never settings: they come from .env.
package settings

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"dropcatch/internal/engine"
	"dropcatch/internal/monitor"
	"dropcatch/internal/store"
)

// Def is one editable setting.
type Def struct {
	Key     string
	Label   string
	Default string
	Help    string
	Kind    string // int, text, bool
	Min     int
	Max     int
	Group   string
}

var Defs = []Def{
	{Group: "Defaults for new domains", Key: "default_monitor_interval", Label: "Monitor interval (s)", Default: "3600", Kind: "int", Min: 30, Max: 7 * 86400},
	{Group: "Defaults for new domains", Key: "default_catch_interval", Label: "Monitor interval while armed (s)", Default: "60", Kind: "int", Min: 5, Max: 3600},
	{Group: "Defaults for new domains", Key: "default_catch_duration", Label: "Order attempt duration (min)", Default: "10", Kind: "int", Min: 1, Max: 1440},

	{Group: "Engine", Key: "min_monitor_interval", Label: "Minimum monitor interval (s)", Default: "60", Kind: "int", Min: 5, Max: 3600, Help: "Floor for every domain's normal monitor interval"},
	{Group: "Engine", Key: "min_catch_interval", Label: "Minimum armed interval (s)", Default: "15", Kind: "int", Min: 2, Max: 600, Help: "Floor while a domain is armed for drop-catch"},
	{Group: "Engine", Key: "order_gap_ms", Label: "Gap between orders per registrar (ms)", Default: "1500", Kind: "int", Min: 200, Max: 60000, Help: "Each registrar also enforces its own documented minimum (≥1 s)"},
	{Group: "Engine", Key: "error_backoff_max", Label: "Max back-off when every source fails (s)", Default: "1800", Kind: "int", Min: 60, Max: 86400},
	{Group: "Engine", Key: "confirm_cooldown", Label: "Re-confirm unconfirmed signals after (s)", Default: "900", Kind: "int", Min: 30, Max: 86400, Help: "Flapping WHOIS answers are cross-checked at most this often"},
	{Group: "Engine", Key: "allow_no_whois_confirm", Label: "Confirm without WHOIS", Default: "0", Kind: "bool", Help: "When WHOIS cannot answer for a suffix, allow two independent fallback sources to confirm instead"},
	{Group: "Engine", Key: "notify_on_catch", Label: "Notify on catch result", Default: "1", Kind: "bool", Help: "Also notify (per-domain channels) when a drop-catch is won, pending or lost"},
	{Group: "Engine", Key: "retention_days", Label: "History retention (days)", Default: "180", Kind: "int", Min: 7, Max: 3650},

	{Group: "Monitor sources", Key: "whois_enabled", Label: "WHOIS/RDAP (primary)", Default: "1", Kind: "bool"},
	{Group: "Monitor sources", Key: "whois_gap_ms", Label: "WHOIS gap per suffix (ms)", Default: "2000", Kind: "int", Min: 0, Max: 60000, Help: "Registry WHOIS servers ban aggressive clients; armed domains jump the queue"},
	{Group: "Monitor sources", Key: "whois_timeout_s", Label: "WHOIS request timeout (s)", Default: "40", Kind: "int", Min: 5, Max: 120},
	{Group: "Monitor sources", Key: "fallback_order", Label: "Keyless fallbacks (order)", Default: "cloudean,regery", Kind: "text", Help: "Comma separated: cloudean, regery. Remove one to disable it"},
	{Group: "Monitor sources", Key: "cloudean_gap_ms", Label: "Cloudean gap between requests (ms)", Default: "1000", Kind: "int", Min: 0, Max: 60000, Help: "Probed: no limit seen in ~200 requests; responses take 1.5–6 s"},
	{Group: "Monitor sources", Key: "regery_per_hour", Label: "Regery budget (requests/hour)", Default: "60", Kind: "int", Min: 1, Max: 100, Help: "Probed per-IP limit ≈100/hour with 5-min cooldowns; 5 requests are kept for armed domains"},
	{Group: "Monitor sources", Key: "registrar_monitors", Label: "Registrar APIs as monitors", Default: "1", Kind: "bool", Help: "Configured registrars' availability APIs are a last-resort monitor and a confirmation source (never place orders)"},
	{Group: "Monitor sources", Key: "registrar_checks_per_hour", Label: "Registrar API checks per hour (each)", Default: "60", Kind: "int", Min: 1, Max: 3600, Help: "Porkbun flags accounts that check many names without registering"},
	{Group: "Monitor sources", Key: "source_cooldown", Label: "Bench time after rate limit / errors (s)", Default: "600", Kind: "int", Min: 30, Max: 86400},
	{Group: "Monitor sources", Key: "source_error_streak", Label: "Consecutive errors before benching", Default: "3", Kind: "int", Min: 1, Max: 20},

	{Group: "Pricing", Key: "pricing_ttl_hours", Label: "Suffix price cache (hours)", Default: "24", Kind: "int", Min: 1, Max: 720},
}

func Get(st *store.Store, key string) string {
	for _, d := range Defs {
		if d.Key == key {
			return st.GetSetting(key, d.Default)
		}
	}
	return st.GetSetting(key, "")
}

func Int(st *store.Store, key string) int {
	n, _ := strconv.Atoi(Get(st, key))
	return n
}

func Bool(st *store.Store, key string) bool { return Get(st, key) == "1" }

func Secs(st *store.Store, key string) time.Duration {
	return time.Duration(Int(st, key)) * time.Second
}

// Validate checks a submitted value.
func Validate(d Def, v string) (string, error) {
	v = strings.TrimSpace(v)
	switch d.Kind {
	case "int":
		n, err := strconv.Atoi(v)
		if err != nil || n < d.Min || n > d.Max {
			return "", fmt.Errorf("%s: must be an integer in [%d, %d]", d.Label, d.Min, d.Max)
		}
	case "bool":
		if v != "1" {
			v = "0"
		}
	}
	if d.Key == "fallback_order" {
		var keep []string
		for _, p := range strings.Split(v, ",") {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if p != monitor.SrcCloudean && p != monitor.SrcRegery {
				return "", fmt.Errorf("unknown fallback %q (use cloudean, regery)", p)
			}
			keep = append(keep, p)
		}
		v = strings.Join(keep, ",")
	}
	return v, nil
}

func Fallbacks(st *store.Store) []string {
	var out []string
	for _, p := range strings.Split(Get(st, "fallback_order"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// EngineConfig builds the engine config from settings.
func EngineConfig(st *store.Store) engine.Config {
	return engine.Config{
		MinMonitorInterval:  Secs(st, "min_monitor_interval"),
		MinCatchInterval:    Secs(st, "min_catch_interval"),
		OrderGap:            time.Duration(Int(st, "order_gap_ms")) * time.Millisecond,
		ConfirmCooldown:     Secs(st, "confirm_cooldown"),
		ErrorBackoffMax:     Secs(st, "error_backoff_max"),
		NotifyOnCatch:       Bool(st, "notify_on_catch"),
		AllowNoWhoisConfirm: Bool(st, "allow_no_whois_confirm"),
		RetentionDays:       Int(st, "retention_days"),
	}
}

// MonitorConfig builds the monitor manager config.
func MonitorConfig(st *store.Store) monitor.Config {
	return monitor.Config{
		WhoisEnabled:      Bool(st, "whois_enabled"),
		Fallbacks:         Fallbacks(st),
		RegistrarMonitors: Bool(st, "registrar_monitors"),
		Cooldown:          Secs(st, "source_cooldown"),
		ErrorStreak:       Int(st, "source_error_streak"),
	}
}

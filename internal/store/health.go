package store

import (
	"strings"
	"time"
)

// SourceHealth tracks how reliable one availability source is for one suffix.
type SourceHealth struct {
	Suffix           string
	Source           string
	OK               int64
	Errors           int64
	Streak           int // consecutive errors
	LastOK           time.Time
	LastErr          time.Time
	LastError        string
	CooldownUntil    time.Time
	UnsupportedUntil time.Time
	AvgMS            int64
}

func (h SourceHealth) Usable(now time.Time) bool {
	return now.After(h.CooldownUntil) && now.After(h.UnsupportedUntil)
}

func (s *Store) Health(suffix, source string) SourceHealth {
	h := SourceHealth{Suffix: suffix, Source: source}
	var lo, le, cu, uu int64
	s.R.QueryRow(`SELECT ok,errors,streak,last_ok,last_err,last_error,cooldown_until,unsupported_until,avg_ms FROM source_health WHERE suffix=? AND source=?`, suffix, source).
		Scan(&h.OK, &h.Errors, &h.Streak, &lo, &le, &h.LastError, &cu, &uu, &h.AvgMS)
	h.LastOK, h.LastErr, h.CooldownUntil, h.UnsupportedUntil = FromUnix(lo), FromUnix(le), FromUnix(cu), FromUnix(uu)
	return h
}

func (s *Store) ensureHealth(suffix, source string) {
	s.W.Exec(`INSERT OR IGNORE INTO source_health(suffix,source) VALUES(?,?)`, suffix, source)
}

// HealthOK records a successful answer and clears any cooldown.
func (s *Store) HealthOK(suffix, source string, ms int64) {
	s.ensureHealth(suffix, source)
	s.W.Exec(`UPDATE source_health SET ok=ok+1, streak=0, last_ok=?, cooldown_until=0, unsupported_until=0,
		avg_ms=CASE WHEN avg_ms=0 THEN ? ELSE (avg_ms*4+?)/5 END WHERE suffix=? AND source=?`, time.Now().Unix(), ms, ms, suffix, source)
}

// HealthErr records a failure; cooldown (if >0) benches the source for the suffix.
func (s *Store) HealthErr(suffix, source, msg string, cooldown time.Duration) {
	s.ensureHealth(suffix, source)
	until := int64(0)
	if cooldown > 0 {
		until = time.Now().Add(cooldown).Unix()
	}
	s.W.Exec(`UPDATE source_health SET errors=errors+1, streak=streak+1, last_err=?, last_error=?, cooldown_until=MAX(cooldown_until,?) WHERE suffix=? AND source=?`,
		time.Now().Unix(), msg, until, suffix, source)
}

// HealthUnsupported marks a source as not covering the suffix for a while.
func (s *Store) HealthUnsupported(suffix, source string, d time.Duration) {
	s.ensureHealth(suffix, source)
	s.W.Exec(`UPDATE source_health SET unsupported_until=?, last_error='suffix not supported' WHERE suffix=? AND source=?`, time.Now().Add(d).Unix(), suffix, source)
}

func (s *Store) ClearHealth(suffix, source string) {
	s.W.Exec(`UPDATE source_health SET cooldown_until=0, unsupported_until=0, streak=0 WHERE suffix=? AND source=?`, suffix, source)
}

func (s *Store) ListHealth() []SourceHealth {
	rows, err := s.R.Query(`SELECT suffix,source,ok,errors,streak,last_ok,last_err,last_error,cooldown_until,unsupported_until,avg_ms FROM source_health ORDER BY suffix,source`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []SourceHealth
	for rows.Next() {
		var h SourceHealth
		var lo, le, cu, uu int64
		if rows.Scan(&h.Suffix, &h.Source, &h.OK, &h.Errors, &h.Streak, &lo, &le, &h.LastError, &cu, &uu, &h.AvgMS) == nil {
			h.LastOK, h.LastErr, h.CooldownUntil, h.UnsupportedUntil = FromUnix(lo), FromUnix(le), FromUnix(cu), FromUnix(uu)
			out = append(out, h)
		}
	}
	return out
}

// ---- suffix pricing / registrar support cache

type SuffixInfo struct {
	Suffix     string
	Source     string
	FetchedAt  time.Time
	Registrars []string // registrar keys selling the suffix (price-DB naming)
	Prices     string   // JSON: key -> {register,renew,transfer,currency}
	Error      string
}

func (s *Store) GetSuffixInfo(suffix string) (SuffixInfo, bool) {
	var si SuffixInfo
	var fa int64
	var regs string
	err := s.R.QueryRow(`SELECT suffix,source,fetched_at,registrars,prices,error FROM suffix_info WHERE suffix=?`, suffix).Scan(&si.Suffix, &si.Source, &fa, &regs, &si.Prices, &si.Error)
	if err != nil {
		return si, false
	}
	si.FetchedAt, si.Registrars = FromUnix(fa), SplitList(regs)
	return si, true
}

func (s *Store) PutSuffixInfo(si SuffixInfo) {
	s.W.Exec(`INSERT INTO suffix_info(suffix,source,fetched_at,registrars,prices,error) VALUES(?,?,?,?,?,?)
		ON CONFLICT(suffix) DO UPDATE SET source=excluded.source, fetched_at=excluded.fetched_at, registrars=excluded.registrars, prices=excluded.prices, error=excluded.error`,
		si.Suffix, si.Source, Unix(si.FetchedAt), strings.Join(si.Registrars, ","), si.Prices, si.Error)
}

func (s *Store) ListSuffixInfo() []SuffixInfo {
	rows, err := s.R.Query(`SELECT suffix,source,fetched_at,registrars,prices,error FROM suffix_info ORDER BY suffix`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []SuffixInfo
	for rows.Next() {
		var si SuffixInfo
		var fa int64
		var regs string
		if rows.Scan(&si.Suffix, &si.Source, &fa, &regs, &si.Prices, &si.Error) == nil {
			si.FetchedAt, si.Registrars = FromUnix(fa), SplitList(regs)
			out = append(out, si)
		}
	}
	return out
}

// Suffixes returns the distinct suffixes of monitored domains.
func (s *Store) Suffixes() []string {
	rows, err := s.R.Query(`SELECT DISTINCT suffix FROM domains ORDER BY suffix`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var x string
		if rows.Scan(&x) == nil {
			out = append(out, x)
		}
	}
	return out
}

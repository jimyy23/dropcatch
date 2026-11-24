package monitor

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/store"
)

// Config tunes source selection.
type Config struct {
	WhoisEnabled      bool
	Fallbacks         []string      // keyless web sources in preference order
	RegistrarMonitors bool          // use registrar availability APIs as last-resort monitors
	Cooldown          time.Duration // base bench time after rate limits / error streaks
	ErrorStreak       int           // consecutive errors before benching
	UnsupportedFor    time.Duration
}

// Manager picks, per suffix, the most reliable available source.
type Manager struct {
	st *store.Store

	mu         sync.RWMutex
	cfg        Config
	whois      *Whois
	extWhois   []*Whois // external sidecars, in configured order
	web        map[string]Source
	registrars []*RegistrarSource
	twnic      *TWNIC // direct .tw registry source
}

// SetTWNIC sets the direct .tw registry source (nil disables it).
func (m *Manager) SetTWNIC(t *TWNIC) {
	m.mu.Lock()
	m.twnic = t
	m.mu.Unlock()
}

// TWNIC returns the direct .tw source, if enabled.
func (m *Manager) TWNIC() *TWNIC {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.twnic
}

func NewManager(st *store.Store) *Manager { return &Manager{st: st, web: map[string]Source{}} }

// whoisNames lists WHOIS sources in order: internal, then external.
func (m *Manager) whoisNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	if m.twnic != nil {
		out = append(out, SrcTWNIC)
	}
	if m.whois != nil {
		out = append(out, SrcWhois)
	}
	for _, w := range m.extWhois {
		out = append(out, w.Name())
	}
	return out
}

// SetExternalWhois sets the external WHOIS sidecars (fallbacks to the internal one).
func (m *Manager) SetExternalWhois(ext []*Whois) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extWhois = nil
	for _, w := range ext {
		if w != nil {
			m.extWhois = append(m.extWhois, w)
		}
	}
}

// ExternalWhois returns the configured external sidecars.
func (m *Manager) ExternalWhois() []*Whois {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]*Whois(nil), m.extWhois...)
}

func (m *Manager) Configure(cfg Config, whois *Whois, web []Source, regs []*RegistrarSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg.ErrorStreak < 1 {
		cfg.ErrorStreak = 3
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 10 * time.Minute
	}
	if cfg.UnsupportedFor <= 0 {
		cfg.UnsupportedFor = 7 * 24 * time.Hour
	}
	m.cfg, m.whois, m.registrars = cfg, whois, regs
	m.web = map[string]Source{}
	for _, s := range web {
		m.web[s.Name()] = s
	}
}

func (m *Manager) Whois() *Whois {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.whois
}

// SourceNames lists configured sources (for the UI).
func (m *Manager) SourceNames() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	if m.cfg.WhoisEnabled {
		if m.twnic != nil {
			out = append(out, SrcTWNIC)
		}
		if m.whois != nil {
			out = append(out, SrcWhois)
		}
		for _, w := range m.extWhois {
			out = append(out, w.Name())
		}
	}
	for _, f := range m.cfg.Fallbacks {
		if _, ok := m.web[f]; ok {
			out = append(out, f)
		}
	}
	if m.cfg.RegistrarMonitors {
		for _, r := range m.registrars {
			out = append(out, r.Name())
		}
	}
	return out
}

func (m *Manager) source(name string) Source {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if name == SrcTWNIC {
		if m.twnic == nil {
			return nil
		}
		return m.twnic
	}
	if name == SrcWhois {
		if m.whois == nil {
			return nil
		}
		return m.whois
	}
	for _, w := range m.extWhois {
		if w.Name() == name {
			return w
		}
	}
	if s, ok := m.web[name]; ok {
		return s
	}
	for _, r := range m.registrars {
		if r.Name() == name {
			return r
		}
	}
	return nil
}

// Plan returns the sources to try for a suffix, best first. WHOIS stays first
// whenever it is usable (it carries status and dates); benched sources are
// skipped until their cooldown ends, after which they are probed again.
func (m *Manager) Plan(suffix string) []string {
	now := time.Now()
	names := m.SourceNames()
	type cand struct {
		name  string
		score float64
	}
	var cs []cand
	for i, n := range names {
		if n == SrcTWNIC && !IsTW(suffix) {
			continue
		}
		h := m.st.Health(suffix, n)
		if !h.Usable(now) {
			continue
		}
		score := float64(i) * 10 // configured preference
		if !IsWhois(n) {
			total := h.OK + h.Errors
			if total > 0 {
				score += 20 * float64(h.Errors) / float64(total) // historical failure rate for this suffix
			}
			score += float64(h.Streak) * 15
			score += float64(h.AvgMS) / 2000
		}
		cs = append(cs, cand{n, score})
	}
	// WHOIS/RDAP sources (internal first, then external in configured order)
	// always come before web checkers and registrar APIs: they carry the
	// registration data. The others are ordered by their track record.
	sort.SliceStable(cs, func(i, j int) bool {
		wi, wj := IsWhois(cs[i].name), IsWhois(cs[j].name)
		if wi != wj {
			return wi
		}
		if wi && wj {
			return false // keep configured order
		}
		return cs[i].score < cs[j].score
	})
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.name)
	}
	return out
}

// record updates source health from an observation.
func (m *Manager) record(suffix string, o Observation) {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()
	if o.Err == nil {
		m.st.HealthOK(suffix, o.Source, o.Elapsed.Milliseconds())
		return
	}
	var le *LookupError
	msg := o.Err.Error()
	switch KindOf(o.Err) {
	case ErrRateLimited:
		cool := cfg.Cooldown
		if asLE(o.Err, &le) && le.RetryAfter > cool {
			cool = le.RetryAfter
		}
		m.st.HealthErr(suffix, o.Source, msg, cool)
	case ErrUnsupported:
		m.st.HealthUnsupported(suffix, o.Source, cfg.UnsupportedFor)
	case ErrTransient, ErrUnparsed:
		h := m.st.Health(suffix, o.Source)
		cool := time.Duration(0)
		if h.Streak+1 >= cfg.ErrorStreak {
			// back off progressively: 1x, 2x, ... capped at 6x the base cooldown
			mult := h.Streak + 2 - cfg.ErrorStreak
			if mult > 6 {
				mult = 6
			}
			cool = cfg.Cooldown * time.Duration(mult)
		}
		m.st.HealthErr(suffix, o.Source, msg, cool)
	}
}

// stamp fills request timing when a source did not.
func stamp(o *Observation, t0 time.Time) {
	if o.Start.IsZero() {
		o.Start = t0
	}
	if o.Elapsed == 0 {
		o.Elapsed = time.Since(o.Start)
	}
	if o.Via == "" {
		o.Via = "api"
	}
}

func asLE(err error, out **LookupError) bool {
	le, ok := err.(*LookupError)
	if ok {
		*out = le
	}
	return ok
}

// Result of a monitor check.
type Result struct {
	Obs      Observation   // the answer used (Err set if every source failed)
	Attempts []Observation // every source tried, in order
}

// Check asks the best source for the suffix and falls back down the plan on
// errors. Invalid-name errors stop immediately.
func (m *Manager) Check(ctx context.Context, d domainutil.Name, prio bool) Result {
	var res Result
	plan := m.Plan(d.Suffix)
	if len(plan) == 0 {
		res.Obs = Observation{Err: lerr(ErrBusy, "no usable source for .%s (all benched or unsupported)", d.Suffix)}
		return res
	}
	for _, name := range plan {
		src := m.source(name)
		if src == nil {
			continue
		}
		t0 := time.Now()
		o := src.Check(ctx, d, prio)
		stamp(&o, t0)
		m.record(d.Suffix, o)
		res.Attempts = append(res.Attempts, o)
		if o.Err == nil {
			res.Obs = o
			return res
		}
		if KindOf(o.Err) == ErrInvalid || ctx.Err() != nil {
			break
		}
	}
	var msgs []string
	for _, a := range res.Attempts {
		msgs = append(msgs, a.Source+": "+a.Err.Error())
	}
	res.Obs = Observation{Err: lerr(ErrTransient, "%s", strings.Join(msgs, " | "))}
	return res
}

// Confirmation is the outcome of a cross-check.
type Confirmation struct {
	WhoisAvail     bool
	WhoisChecked   bool
	SecondaryAvail string // source that confirmed
	Observations   []Observation
	FromTrigger    []bool // Observations[i] is the trigger itself (not a new lookup)
	Confirmed      bool
}

func (c *Confirmation) add(o Observation, trigger bool) {
	c.Observations = append(c.Observations, o)
	c.FromTrigger = append(c.FromTrigger, trigger)
}

func (c Confirmation) Summary() string {
	var p []string
	for _, o := range c.Observations {
		switch {
		case o.Err != nil:
			p = append(p, o.Source+"="+KindOf(o.Err).String())
		default:
			p = append(p, o.Source+"="+o.Status)
		}
	}
	return strings.Join(p, ", ")
}

// Confirm cross-checks an availability signal. Human notification needs
// WHOIS/RDAP saying available AND at least one independent source that
// supports the suffix (Cloudean, Regery or a registrar API) agreeing. When
// allowWithoutWhois is set and WHOIS cannot answer for the suffix, two
// independent sources must agree instead.
func (m *Manager) Confirm(ctx context.Context, d domainutil.Name, trigger *Observation, allowWithoutWhois bool) Confirmation {
	var c Confirmation
	var whoisObs *Observation
	m.mu.RLock()
	whoisOn := m.cfg.WhoisEnabled
	m.mu.RUnlock()
	if trigger != nil && IsWhois(trigger.Source) && trigger.Err == nil {
		whoisObs = trigger
		c.add(*whoisObs, true)
	} else if whoisOn {
		// internal sidecar first, then external sidecars until one answers
		for _, name := range m.whoisNames() {
			if !m.st.Health(d.Suffix, name).Usable(time.Now()) {
				continue
			}
			if name == SrcTWNIC && !IsTW(d.Suffix) {
				continue
			}
			src := m.source(name)
			if src == nil {
				continue
			}
			t0 := time.Now()
			o := src.Check(ctx, d, true)
			stamp(&o, t0)
			m.record(d.Suffix, o)
			c.add(o, false)
			if o.Err == nil {
				whoisObs = &o
				break
			}
		}
	}
	if whoisObs != nil {
		c.WhoisChecked = whoisObs.Err == nil
		c.WhoisAvail = whoisObs.Available()
		if c.WhoisChecked && !c.WhoisAvail {
			return c // WHOIS positively says not available: no confirmation
		}
	}
	m.mu.RLock()
	var secondaries []string
	secondaries = append(secondaries, m.cfg.Fallbacks...)
	for _, r := range m.registrars {
		secondaries = append(secondaries, r.Name())
	}
	m.mu.RUnlock()
	agree := 0
	for _, name := range secondaries {
		if !m.st.Health(d.Suffix, name).Usable(time.Now()) {
			continue
		}
		var o Observation
		fromTrigger := trigger != nil && trigger.Source == name && trigger.Err == nil
		if fromTrigger {
			o = *trigger
		} else {
			src := m.source(name)
			if src == nil {
				continue
			}
			t0 := time.Now()
			o = src.Check(ctx, d, true)
			stamp(&o, t0)
			m.record(d.Suffix, o)
		}
		c.add(o, fromTrigger)
		if o.Available() {
			agree++
			if c.SecondaryAvail == "" {
				c.SecondaryAvail = name
			}
			if c.WhoisAvail || (allowWithoutWhois && !c.WhoisChecked && agree >= 2) {
				break
			}
		}
		// a disagreeing or failing source: keep asking the next one
	}
	c.Confirmed = (c.WhoisAvail && agree >= 1) || (allowWithoutWhois && !c.WhoisChecked && agree >= 2)
	return c
}

// Probe runs every source once (manual "test all sources" from the UI).
func (m *Manager) Probe(ctx context.Context, d domainutil.Name) []Observation {
	names := m.SourceNames()
	out := make([]Observation, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		src := m.source(n)
		if src == nil {
			continue
		}
		wg.Add(1)
		go func(i int, src Source) {
			defer wg.Done()
			o := src.Check(ctx, d, false)
			m.record(d.Suffix, o)
			out[i] = o
		}(i, src)
	}
	wg.Wait()
	return out
}

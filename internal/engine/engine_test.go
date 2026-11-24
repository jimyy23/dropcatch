package engine

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dropcatch/internal/config"
	"dropcatch/internal/domainutil"
	"dropcatch/internal/monitor"
	"dropcatch/internal/notify"
	"dropcatch/internal/pricing"
	"dropcatch/internal/registrar"
	"dropcatch/internal/store"
)

// scripted monitor source
type src struct {
	mu     sync.Mutex
	status string
}

func (s *src) Name() string  { return monitor.SrcCloudean }
func (s *src) Label() string { return "fake" }
func (s *src) set(v string)  { s.mu.Lock(); s.status = v; s.mu.Unlock() }
func (s *src) Check(ctx context.Context, d domainutil.Name, prio bool) monitor.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return monitor.Observation{Source: monitor.SrcCloudean, Status: s.status, Elapsed: time.Millisecond}
}

// scripted registrar
type reg struct {
	key      string
	winAfter int64 // succeed on this attempt (0 = never)
	fatal    bool
	calls    atomic.Int64
}

func (r *reg) Key() string           { return r.key }
func (r *reg) Label() string         { return r.key }
func (r *reg) PriceKey() string      { return r.key }
func (r *reg) Configured() bool      { return true }
func (r *reg) Problem() string       { return "" }
func (r *reg) MinGap() time.Duration { return 20 * time.Millisecond }
func (r *reg) Check(context.Context, string) (registrar.Availability, error) {
	return registrar.Availability{}, registrar.ErrUnsupported
}
func (r *reg) Register(ctx context.Context, domain string) registrar.Result {
	n := r.calls.Add(1)
	if r.fatal {
		return registrar.Result{Outcome: registrar.Fatal, Message: "insufficient funds"}
	}
	if r.winAfter > 0 && n >= r.winAfter {
		return registrar.Result{Outcome: registrar.Success, Ref: "order-1"}
	}
	return registrar.Result{Outcome: registrar.Unavailable, Message: "not yet"}
}

func setup(t *testing.T, regs ...registrar.Registrar) (*Engine, *store.Store, *src, int64) {
	st, err := store.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &src{status: store.StatusRegistered}
	mon := monitor.NewManager(st)
	mon.Configure(monitor.Config{Fallbacks: []string{monitor.SrcCloudean}}, nil, []monitor.Source{s}, nil)
	var keys []string
	for _, r := range regs {
		keys = append(keys, r.Key())
	}
	e := New(st, mon, registrar.NewSet(regs...), notify.New(config.Twilio{}, config.Telegram{}), pricing.New(st, time.Hour), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetConfig(Config{MinMonitorInterval: time.Second, MinCatchInterval: 50 * time.Millisecond, OrderGap: 20 * time.Millisecond, ConfirmCooldown: time.Minute})
	id, err := st.AddDomain(store.NewDomain{Name: "foobar123.lu", UName: "foobar123.lu", Suffix: "lu", MonitorEnabled: true, MonitorInterval: 3600, CatchInterval: 1, CatchDuration: 1, CatchRegistrars: keys})
	if err != nil {
		t.Fatal(err)
	}
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchEnabled: true, CatchInterval: 1, CatchDuration: 1, CatchRegistrars: keys})
	return e, st, s, id
}

func waitState(t *testing.T, st *store.Store, id int64, want string) *store.Domain {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		d, _ := st.GetDomain(id)
		if d != nil && d.CatchState == want {
			return d
		}
		time.Sleep(50 * time.Millisecond)
	}
	d, _ := st.GetDomain(id)
	t.Fatalf("catch state %q, want %q (result %q)", d.CatchState, want, d.CatchResult)
	return nil
}

func TestCatchWinsWithAllRegistrarsInParallel(t *testing.T) {
	a := &reg{key: "a", winAfter: 3}
	b := &reg{key: "b"}
	broke := &reg{key: "broke", fatal: true}
	e, st, s, id := setup(t, a, b, broke)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(200 * time.Millisecond)
	s.set(store.StatusAvailable)
	e.CheckNow(id)
	d := waitState(t, st, id, store.CatchWon)
	if d.CatchWonBy != "a" {
		t.Fatalf("won by %q", d.CatchWonBy)
	}
	if b.calls.Load() == 0 {
		t.Fatal("registrar b should have been tried in parallel")
	}
	if broke.calls.Load() != 1 {
		t.Fatalf("fatal registrar must be dropped after one attempt, got %d", broke.calls.Load())
	}
	// after winning, no further orders
	n := a.calls.Load() + b.calls.Load()
	time.Sleep(300 * time.Millisecond)
	if a.calls.Load()+b.calls.Load() != n {
		t.Fatal("orders continued after success")
	}
}

func TestCatchStopsWhenRegisteredBySomeoneElse(t *testing.T) {
	a := &reg{key: "a"}
	e, st, s, id := setup(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(200 * time.Millisecond)
	s.set(store.StatusAvailable)
	e.CheckNow(id)
	waitState(t, st, id, store.CatchActive)
	time.Sleep(200 * time.Millisecond)
	s.set(store.StatusRegistered) // someone else got it
	waitState(t, st, id, store.CatchLost)
	n := a.calls.Load()
	time.Sleep(300 * time.Millisecond)
	if a.calls.Load() != n {
		t.Fatal("orders continued after the domain was lost")
	}
}

func TestExpiredSessionNotRestartedInSameEpisode(t *testing.T) {
	a := &reg{key: "a"}
	e, st, s, id := setup(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(200 * time.Millisecond)
	s.set(store.StatusAvailable)
	e.CheckNow(id)
	waitState(t, st, id, store.CatchActive)
	e.StopCatch(id)
	waitState(t, st, id, store.CatchExpired)
	n := a.calls.Load()
	e.CheckNow(id) // still available: same episode
	time.Sleep(500 * time.Millisecond)
	if d, _ := st.GetDomain(id); d.CatchState != store.CatchExpired || a.calls.Load() != n {
		t.Fatalf("session restarted within the same availability episode (state %s)", d.CatchState)
	}
	// new episode: registered (two agreeing answers commit it), then available again
	s.set(store.StatusRegistered)
	e.CheckNow(id)
	time.Sleep(300 * time.Millisecond)
	e.CheckNow(id)
	time.Sleep(300 * time.Millisecond)
	if d, _ := st.GetDomain(id); d.Status != store.StatusRegistered {
		t.Fatalf("two registered answers must commit: %s", d.Status)
	}
	s.set(store.StatusAvailable)
	e.CheckNow(id)
	waitState(t, st, id, store.CatchActive)
}

func TestCatchEndsWhenAllRegistrarsFatal(t *testing.T) {
	broke := &reg{key: "broke", fatal: true}
	e, st, s, id := setup(t, broke)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(200 * time.Millisecond)
	s.set(store.StatusAvailable)
	start := time.Now()
	e.CheckNow(id)
	d := waitState(t, st, id, store.CatchExpired)
	if time.Since(start) > 10*time.Second || !strings.Contains(d.CatchResult, "every registrar failed") {
		t.Fatalf("session should end promptly with a clear result, got %q after %s", d.CatchResult, time.Since(start))
	}
}

func TestManualRegisterIgnoresAvailability(t *testing.T) {
	a := &reg{key: "a", winAfter: 2}
	b := &reg{key: "b"}
	e, st, s, id := setup(t, a, b)
	st.SetToggle(id, "catch", false) // drop-catch off: manual still works
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(200 * time.Millisecond)
	s.set(store.StatusRegistered) // monitor says taken: manual orders anyway
	if err := e.RegisterNow(id, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := e.RegisterNow(id, "tester"); err == nil {
		t.Error("a second manual register while one runs must be refused")
	}
	d := waitState(t, st, id, store.CatchWon)
	if d.CatchWonBy != "a" || !strings.HasPrefix(d.CatchResult, "manual register") || b.calls.Load() == 0 {
		t.Fatalf("won by %q result %q b=%d", d.CatchWonBy, d.CatchResult, b.calls.Load())
	}
}

func TestManualRegisterNeedsRegistrar(t *testing.T) {
	e, st, _, id := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(100 * time.Millisecond)
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchInterval: 1, CatchDuration: 1})
	if err := e.RegisterNow(id, "tester"); err == nil {
		t.Fatal("manual register without registrars must fail")
	}
}

func TestNotArmedPlacesNoOrders(t *testing.T) {
	a := &reg{key: "a", winAfter: 1}
	e, st, s, id := setup(t, a)
	st.SetToggle(id, "catch", false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	s.set(store.StatusAvailable)
	e.CheckNow(id)
	time.Sleep(time.Second)
	if a.calls.Load() != 0 {
		t.Fatal("orders placed while drop-catch is off")
	}
	d, _ := st.GetDomain(id)
	if d.Status != store.StatusAvailable {
		t.Fatalf("monitor should still update status, got %s", d.Status)
	}
}

func TestKeepSpecific(t *testing.T) {
	o := monitor.Observation{Source: monitor.SrcCloudean, Status: store.StatusRegistered}
	if keepSpecific(store.StatusPendingDelete, o) != store.StatusPendingDelete {
		t.Fatal("fallback 'registered' must not erase pending delete")
	}
	o.Status = store.StatusAvailable
	if keepSpecific(store.StatusPendingDelete, o) != store.StatusAvailable {
		t.Fatal("available must win")
	}
}

func TestExpectedReleaseTW(t *testing.T) {
	// sina.com.tw: "Record expires on 2026-10-27 00:00:00 (UTC+8)" = RDAP 2026-10-26T16:00:00Z
	exp := time.Date(2026, 10, 26, 16, 0, 0, 0, time.UTC)
	at, err := ExpectedRelease(ReleaseInput{Suffix: "com.tw", Expires: exp, PendingDelete: true})
	if err != nil || !at.Equal(time.Date(2026, 11, 29, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("sina.com.tw release = %s %v, want 2026-11-29 06:00:00 UTC", at, err)
	}
	// the Taiwan date counts, not the UTC date: 2026-10-27 23:30 UTC is 10-28 in Taiwan
	at, _ = ExpectedRelease(ReleaseInput{Suffix: "tw", Expires: time.Date(2026, 10, 27, 23, 30, 0, 0, time.UTC), PendingDelete: true})
	if !at.Equal(time.Date(2026, 11, 30, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("Taiwan-date rule: %s", at)
	}
	if _, err := ExpectedRelease(ReleaseInput{Suffix: "com", Expires: exp}); err == nil {
		t.Fatal(".com has no rule")
	}
	// mbjq.tw re-registered: expiry 2027-11-23 must not yield a release
	if _, err := ExpectedRelease(ReleaseInput{Suffix: "tw", Expires: time.Date(2027, 11, 23, 6, 0, 42, 0, time.UTC)}); err == nil {
		t.Fatal("registered .tw must not get a release time")
	}
	if r, _ := RuleFor("com.tw"); r.Name != ".tw (TWNIC)" {
		t.Fatalf("rule name %q", r.Name)
	}
}

func TestExpectedReleaseCA(t *testing.T) {
	utc := func(d, h, m int) time.Time { return time.Date(2026, 11, d, h, m, 0, 0, time.UTC) }
	// Nov 2026: Mon 16, Wed 18, Sun 22, Mon 23, Wed 25, Dec 2 (Wed)
	cases := []struct {
		deleted, want time.Time
	}{
		{utc(15, 12, 0), utc(18, 19, 0)},                               // Sunday -> that Wednesday
		{utc(16, 6, 59), utc(18, 19, 0)},                               // just before the Monday cutoff
		{utc(16, 7, 0), utc(25, 19, 0)},                                // Monday 07:00 -> following Wednesday
		{utc(17, 12, 0), utc(25, 19, 0)},                               // Tuesday
		{utc(18, 18, 59), utc(25, 19, 0)},                              // Wednesday before the session
		{utc(18, 19, 0), utc(25, 19, 0)},                               // at the session start
		{utc(18, 20, 0), utc(25, 19, 0)},                               // Wednesday evening: 6.9 days
		{utc(23, 7, 0), time.Date(2026, 12, 2, 19, 0, 0, 0, time.UTC)}, // Monday 07:00 (week of Nov 25) -> Dec 2
	}
	for _, c := range cases {
		at, err := ExpectedRelease(ReleaseInput{Suffix: "ca", PendingDelete: true, PendingDeleteSince: c.deleted})
		if err != nil || !at.Equal(c.want) {
			t.Errorf("deleted %s: got %s %v, want %s", c.deleted, at, err, c.want)
		}
		if d := at.Sub(c.deleted); d < 60*time.Hour || d > 228*time.Hour {
			t.Errorf("deleted %s: %s on the list, outside 2.5-9.5 days", c.deleted, d)
		}
	}
	if _, err := ExpectedRelease(ReleaseInput{Suffix: "ca", Expires: utc(1, 0, 0)}); err == nil {
		t.Fatal(".ca needs pending delete")
	}
	// ReleaseInputFor: registry "updated" marks the deletion when plausible
	d := &store.Domain{Suffix: "ca", Status: store.StatusPendingDelete, StatusSince: utc(17, 12, 0), Updated: utc(15, 12, 0)}
	if at, _ := ExpectedRelease(ReleaseInputFor(d)); !at.Equal(utc(18, 19, 0)) {
		t.Fatalf("from updated date: %s", at)
	}
	d.Updated = utc(1, 0, 0) // too old to be the deletion: use first seen
	if at, _ := ExpectedRelease(ReleaseInputFor(d)); !at.Equal(utc(25, 19, 0)) {
		t.Fatalf("from first seen: %s", at)
	}
}

func TestScheduledFireIgnoresMonitor(t *testing.T) {
	a := &reg{key: "a", winAfter: 3}
	e, st, s, id := setup(t, a)
	s.set(store.StatusPendingDelete) // the monitor never sees it free
	fireAt := time.Now().Add(1500 * time.Millisecond).Truncate(time.Second)
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchEnabled: true, CatchInterval: 1,
		CatchDuration: 1, CatchRegistrars: []string{"a"}, FireAt: fireAt, FireLead: 1, FireDuration: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	d := waitState(t, st, id, store.CatchWon)
	if !strings.HasPrefix(d.CatchResult, "scheduled fire") || d.CatchStartedAt.Before(fireAt.Add(-2*time.Second)) {
		t.Fatalf("result %q started %s (fire %s)", d.CatchResult, d.CatchStartedAt, fireAt)
	}
	if !d.FireDoneAt.Equal(fireAt) {
		t.Fatalf("fire must be marked done: %s", d.FireDoneAt)
	}
	n := a.calls.Load()
	time.Sleep(500 * time.Millisecond)
	if a.calls.Load() != n {
		t.Fatal("fire must not repeat")
	}
}

func TestFireNotArmedDoesNothing(t *testing.T) {
	a := &reg{key: "a", winAfter: 1}
	e, st, _, id := setup(t, a)
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchInterval: 1, CatchDuration: 1,
		CatchRegistrars: []string{"a"}, FireAt: time.Now().Add(500 * time.Millisecond), FireLead: 1, FireDuration: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(2 * time.Second)
	if a.calls.Load() != 0 {
		t.Fatal("fire must not run while drop-catch is off")
	}
}

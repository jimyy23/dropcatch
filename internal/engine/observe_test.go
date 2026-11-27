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

func ts(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

// replays the mbjq.tw report: fresh "registered" answers alternating with
// RDAP copies from older snapshots (pendingDelete, old expiry).
func TestGuardNoFlapOnStaleSnapshots(t *testing.T) {
	e, st, _, id := setup(t)
	st.SaveObservation(id, store.StatusPendingDelete, "whois", "", &store.Info{Expires: ts("2026-10-21T16:00:00Z"),
		Created: ts("2015-10-21T16:14:20Z"), PendingDelete: true, Snapshot: ts("2026-11-23T05:39:00Z")})
	st.SetSnapshotMax(id, ts("2026-11-23T05:39:00Z"))
	fresh := monitor.Observation{Source: monitor.SrcTWNIC, Via: "rdap", Status: store.StatusRegistered, Start: time.Now(),
		Info: &store.Info{Created: ts("2026-11-23T06:00:42Z"), Expires: ts("2027-11-23T06:00:42Z"), Snapshot: ts("2026-11-23T06:09:00Z"), Registrar: "Dynadot LLC"}}
	stale := monitor.Observation{Source: monitor.SrcWhois, Via: "sidecar-rdap", Status: store.StatusPendingDelete, Start: time.Now(),
		Info: &store.Info{Created: ts("2015-10-21T16:14:20Z"), Expires: ts("2026-10-21T16:00:00Z"), PendingDelete: true, Snapshot: ts("2026-11-23T05:39:00Z")}}
	staleNoSnap := monitor.Observation{Source: monitor.SrcWhois, Via: "sidecar-rdap", Status: store.StatusAvailable, Weak: true, Start: time.Now()}

	seq := []monitor.Observation{fresh, stale, fresh, stale, staleNoSnap, fresh, stale, staleNoSnap}
	for _, o := range seq {
		d, _ := st.GetDomain(id)
		e.observe(d, o, "monitor")
	}
	d, _ := st.GetDomain(id)
	if d.Status != store.StatusRegistered || !d.Expires.Equal(ts("2027-11-23T06:00:42Z")) || !d.Created.Equal(ts("2026-11-23T06:00:42Z")) {
		t.Fatalf("final %s exp %s created %s", d.Status, d.Expires, d.Created)
	}
	ev, _ := st.ListEvents(id, "", 50, 0)
	var changes []string
	for _, x := range ev {
		if x.Type == "status_change" || x.Type == "expiry_change" {
			changes = append(changes, x.Type+": "+x.Detail)
		}
	}
	if len(changes) != 2 { // one status change + one expiry change
		t.Fatalf("want exactly one transition, got %d:\n%s", len(changes), strings.Join(changes, "\n"))
	}
	if !strings.Contains(changes[1], "pending_delete → registered") || !strings.Contains(changes[1], "registry creation 2026-11-23 06:00:42") {
		t.Fatalf("transition: %s", changes[1])
	}
	// detection lag measured from the first fresh answer, not a stale date
	if strings.Contains(changes[1], "h after") {
		t.Fatalf("nonsense lag: %s", changes[1])
	}
	polls := st.ListPolls(id, 50)
	stales := 0
	for _, p := range polls {
		if strings.HasPrefix(p.Verdict, "stale") || strings.HasPrefix(p.Verdict, "weak") {
			stales++
		}
	}
	if stales != 5 {
		t.Fatalf("5 rejected answers expected in the poll log, got %d", stales)
	}
}

// costa.com.tw: never registered; RDAP 404 (weak) alternating with an old
// pendingDelete copy after the release.
func TestGuardReleasedDoesNotFlapBack(t *testing.T) {
	e, st, _, id := setup(t)
	st.SaveObservation(id, store.StatusPendingDelete, "whois", "", &store.Info{PendingDelete: true, Snapshot: ts("2026-11-23T05:39:00Z")})
	st.SetSnapshotMax(id, ts("2026-11-23T05:39:00Z"))
	st.SetFireAt(id, ts("2026-11-23T06:00:00Z"))
	free := monitor.Observation{Source: monitor.SrcTWNIC, Via: "port43", Status: store.StatusAvailable, Start: time.Now()}
	old := monitor.Observation{Source: monitor.SrcWhois, Via: "sidecar-rdap", Status: store.StatusPendingDelete, Start: time.Now(),
		Info: &store.Info{PendingDelete: true, Snapshot: ts("2026-11-23T05:39:00Z")}}
	for _, o := range []monitor.Observation{free, old, old, free, old} {
		d, _ := st.GetDomain(id)
		e.observe(d, o, "monitor")
	}
	d, _ := st.GetDomain(id)
	if d.Status != store.StatusAvailable {
		t.Fatalf("status %s", d.Status)
	}
	ev, _ := st.ListEvents(id, "", 50, 0)
	n := 0
	for _, x := range ev {
		if x.Type == "status_change" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d status changes, want 1", n)
	}
}

// a single weak/undated answer never commits; two agreeing ones do
func TestGuardNeedsAgreement(t *testing.T) {
	e, st, _, id := setup(t)
	st.SaveObservation(id, store.StatusPendingDelete, "whois", "", &store.Info{PendingDelete: true})
	avail := monitor.Observation{Source: monitor.SrcCloudean, Status: store.StatusAvailable, Start: time.Now()}
	d, _ := st.GetDomain(id)
	if r := e.observe(d, avail, "monitor"); r.Changed || !r.Accepted || r.Status != store.StatusPendingDelete {
		t.Fatalf("first answer: %+v", r)
	}
	d, _ = st.GetDomain(id)
	if r := e.observe(d, avail, "monitor"); !r.Changed || r.Status != store.StatusAvailable {
		t.Fatalf("second answer: %+v", r)
	}
	// candidate reset by a disagreeing answer
	reg := monitor.Observation{Source: monitor.SrcCloudean, Status: store.StatusRegistered, Start: time.Now()}
	d, _ = st.GetDomain(id)
	e.observe(d, reg, "monitor")
	d, _ = st.GetDomain(id)
	e.observe(d, avail, "monitor")
	d, _ = st.GetDomain(id)
	if d.Status != store.StatusAvailable || d.CandStatus != "" {
		t.Fatalf("status %s cand %q", d.Status, d.CandStatus)
	}
}

func TestReleaseLU(t *testing.T) {
	r, ok := RuleFor("lu")
	if !ok || !r.NoBlindFire || !r.WatchFast {
		t.Fatal(".lu rule must exist, not fire blind, and watch with fast checkers")
	}
	// quarantine entered 2026-10-26 13:20 UTC (observed) -> estimate +30 days
	at, err := ExpectedRelease(ReleaseInput{Suffix: "lu", PendingDelete: true, PendingDeleteSince: ts("2026-10-26T13:20:37Z"), PendingDeleteObserved: true})
	if err != nil || !at.Equal(ts("2026-11-25T13:20:00Z")) {
		t.Fatalf("%s %v", at, err)
	}
	// not observed: expiry + 30 days is the upper bound
	at, err = ExpectedRelease(ReleaseInput{Suffix: "lu", PendingDelete: true, PendingDeleteSince: ts("2026-10-26T13:20:00Z"), Expires: ts("2026-10-30T08:00:00Z")})
	if err != nil || !at.Equal(ts("2026-11-29T08:00:00Z")) {
		t.Fatalf("expiry bound: %s %v", at, err)
	}
	if _, err := ExpectedRelease(ReleaseInput{Suffix: "lu", PendingDelete: true}); err == nil {
		t.Fatal("no data: no estimate")
	}
	rel := ts("2026-11-25T13:20:00Z")
	from, to, every := r.WatchWindow(rel, rel)
	if !from.Equal(rel.Add(-24*time.Hour)) || !to.Equal(rel.Add(24*time.Hour)) || every != 45*time.Second {
		t.Fatalf("window %s %s %s", from, to, every)
	}
}

func TestLUNoBlindFireButWatch(t *testing.T) {
	e, st, _, id := setup(t) // setup uses foobar123.lu
	at := time.Now().Add(30 * time.Minute)
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchEnabled: true, CatchInterval: 60,
		CatchDuration: 1, CatchRegistrars: []string{"a"}, FireAt: at, FireAuto: true, FireLead: 0, FireDuration: 30})
	d, _ := st.GetDomain(id)
	if _, ok := e.fireDue(d, time.Now()); ok {
		t.Fatal(".lu computed window must not fire blind")
	}
	if _, watching, _ := e.watchWindow(d, time.Now()); !watching {
		t.Fatal("must watch from a day before the estimate")
	}
	// a manual fire time is still honoured
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchEnabled: true, CatchInterval: 60,
		CatchDuration: 1, CatchRegistrars: []string{"a"}, FireAt: at, FireLead: 0, FireDuration: 5})
	d, _ = st.GetDomain(id)
	if _, ok := e.fireDue(d, time.Now()); !ok {
		t.Fatal("manual fire time must fire")
	}
}

// fake .tw registry for the watch path
type fakeTW struct {
	mu      sync.Mutex
	answers []monitor.Observation // returned in rotation
	i       int
}

func (f *fakeTW) Name() string  { return monitor.SrcCloudean }
func (f *fakeTW) Label() string { return "fake" }
func (f *fakeTW) Check(ctx context.Context, d domainutil.Name, prio bool) monitor.Observation {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.answers[f.i%len(f.answers)]
	f.i++
	o.Start = time.Now()
	return o
}
func (f *fakeTW) set(a ...monitor.Observation) { f.mu.Lock(); f.answers, f.i = a, 0; f.mu.Unlock() }

// The release watch polls fast; a registration seen right after the release
// is committed once, with the detection time from the first fresh answer,
// while stale copies interleaved with it are ignored.
func TestWatchDetectsReleaseOnce(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	f := &fakeTW{}
	pd := monitor.Observation{Source: monitor.SrcCloudean, Status: store.StatusPendingDelete,
		Info: &store.Info{PendingDelete: true, Expires: ts("2026-10-21T16:00:00Z"), Created: ts("2015-10-21T16:14:20Z"), Snapshot: ts("2026-11-23T05:39:00Z")}}
	f.set(pd)
	mon := monitor.NewManager(st)
	mon.Configure(monitor.Config{Fallbacks: []string{monitor.SrcCloudean}}, nil, []monitor.Source{f}, nil)
	e := New(st, mon, registrar.NewSet(), notify.New(config.Twilio{}, config.Telegram{}), pricing.New(st, time.Hour), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetConfig(Config{MinMonitorInterval: time.Second, MinCatchInterval: 50 * time.Millisecond, OrderGap: 20 * time.Millisecond, ConfirmCooldown: time.Minute})
	id, _ := st.AddDomain(store.NewDomain{Name: "wx8668.com.tw", UName: "wx8668.com.tw", Suffix: "com.tw", MonitorEnabled: true, MonitorInterval: 3600, CatchInterval: 60, CatchDuration: 1})
	release := time.Now().Add(2 * time.Second)
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchInterval: 60, CatchDuration: 1, FireAt: release, FireLead: 10, FireDuration: 5})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(500 * time.Millisecond)
	if d, _ := st.GetDomain(id); d.Status != store.StatusPendingDelete {
		t.Fatalf("initial %s", d.Status)
	}
	time.Sleep(time.Until(release.Add(500 * time.Millisecond)))
	created := time.Now().UTC().Truncate(time.Second)
	fresh := monitor.Observation{Source: monitor.SrcCloudean, Status: store.StatusRegistered,
		Info: &store.Info{Created: created, Expires: created.AddDate(1, 0, 0), Snapshot: created.Add(time.Second), Registrar: "Dynadot LLC"}}
	registeredAt := time.Now()
	f.set(fresh, pd, fresh, pd, pd)
	var d *store.Domain
	for time.Since(registeredAt) < 10*time.Second {
		d, _ = st.GetDomain(id)
		if d.Status == store.StatusRegistered {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if d.Status != store.StatusRegistered {
		t.Fatalf("not detected: %s", d.Status)
	}
	if lag := time.Since(registeredAt); lag > 5*time.Second {
		t.Fatalf("detected after %s, want < 5 s", lag)
	}
	time.Sleep(4 * time.Second) // stale copies keep coming
	ev, _ := st.ListEvents(id, "", 100, 0)
	var ch []string
	for _, x := range ev {
		if x.Type == "status_change" {
			ch = append(ch, x.Detail)
		}
	}
	if len(ch) != 2 || !strings.Contains(ch[0], "pending_delete → registered") {
		t.Fatalf("transitions:\n%s", strings.Join(ch, "\n"))
	}
	if d, _ = st.GetDomain(id); d.Status != store.StatusRegistered {
		t.Fatalf("reverted to %s", d.Status)
	}
}

func TestDropWindowLogged(t *testing.T) {
	e, st, _, id := setup(t) // foobar123.lu
	st.SaveObservation(id, store.StatusPendingDelete, "whois", "", &store.Info{PendingDelete: true})
	st.SetFireAt(id, time.Now().Add(-30*time.Minute).Truncate(time.Second))
	pd := monitor.Observation{Source: monitor.SrcWhois, Via: "sidecar-whois", Status: store.StatusPendingDelete, Start: time.Now().Add(-2 * time.Minute)}
	d, _ := st.GetDomain(id)
	e.observe(d, pd, "watch")
	for i := 0; i < 2; i++ {
		d, _ = st.GetDomain(id)
		e.observe(d, monitor.Observation{Source: monitor.SrcWhois, Via: "sidecar-whois", Status: store.StatusAvailable, Start: time.Now()}, "watch")
	}
	ev, _ := st.ListEvents(id, "status_change", 10, 0)
	_ = ev
	all, _ := st.ListEvents(id, "", 20, 0)
	var got string
	for _, x := range all {
		if x.Type == "status_change" {
			got = x.Detail
			break
		}
	}
	want := "DROP between " + pd.Start.UTC().Format("2006-01-02 15:04:05") + " (last pending_delete answer)"
	if !strings.Contains(got, want) || !strings.Contains(got, "vs expected release") {
		t.Fatalf("%s\nwant %s", got, want)
	}
}

// fake registrar that also answers availability checks (monitor source)
type availReg struct {
	reg
	avail atomic.Bool
}

func (r *availReg) Check(context.Context, string) (registrar.Availability, error) {
	return registrar.Availability{Available: r.avail.Load()}, nil
}

// .lu drop: the registrar check sees it free while WHOIS still shows pending
// delete. Orders start on the first signal; availability is confirmed by
// cloudean + the registrar within seconds, not after WHOIS catches up.
func TestLUDropRegistrarFirst(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "lu.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	whois := &fakeTW{}
	pd := monitor.Observation{Source: monitor.SrcWhois, Status: store.StatusPendingDelete, Info: &store.Info{PendingDelete: true}}
	whois.set(pd)
	web := &src{status: store.StatusPendingDelete} // cloudean
	nt := &availReg{reg: reg{key: "netim"}}
	mon := monitor.NewManager(st)
	mon.Configure(monitor.Config{Fallbacks: []string{monitor.SrcCloudean}, RegistrarMonitors: true}, nil,
		[]monitor.Source{web}, []*monitor.RegistrarSource{monitor.NewRegistrarSource(nt, time.Millisecond, 1000)})
	_ = whois
	e := New(st, mon, registrar.NewSet(nt), notify.New(config.Twilio{}, config.Telegram{}), pricing.New(st, time.Hour), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.SetConfig(Config{MinMonitorInterval: time.Second, MinCatchInterval: 50 * time.Millisecond, OrderGap: 20 * time.Millisecond,
		ConfirmCooldown: 15 * time.Minute, ConfirmRetry: time.Second, RegistrarConfirm: true})
	id, _ := st.AddDomain(store.NewDomain{Name: "cag.lu", UName: "cag.lu", Suffix: "lu", MonitorEnabled: true, MonitorInterval: 3600, CatchInterval: 60, CatchDuration: 1})
	st.SaveObservation(id, store.StatusPendingDelete, "whois", "", &store.Info{PendingDelete: true})
	rel := time.Now().Add(time.Hour)
	// armed interval 1 s (the user's own setting is the floor; the .lu watch
	// tick of 45 s only applies when it is faster)
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchEnabled: true, CatchInterval: 1,
		CatchDuration: 1, CatchRegistrars: []string{"netim"}, FireAt: rel, FireAuto: true, FireDuration: 30})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Run(ctx)
	time.Sleep(1500 * time.Millisecond)
	if nt.calls.Load() != 0 {
		t.Fatal("no orders before the drop")
	}
	// the drop: registrar API and cloudean see it, WHOIS would still lag
	dropAt := time.Now()
	nt.avail.Store(true)
	web.set(store.StatusAvailable)
	deadline := time.Now().Add(20 * time.Second)
	var d *store.Domain
	for time.Now().Before(deadline) {
		d, _ = st.GetDomain(id)
		if !d.ConfirmedAvailAt.IsZero() && nt.calls.Load() > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if nt.calls.Load() == 0 {
		for _, c := range st.ListChecks(id, 30) {
			t.Logf("check %s %s %s %s", c.TS.Format("15:04:05"), c.Purpose, c.Source, c.Result+" "+c.Detail)
		}
		evs, _ := st.ListEvents(id, "", 30, 0)
		for _, x := range evs {
			t.Logf("event %s %s", x.Type, x.Detail)
		}
		dd, _ := st.GetDomain(id)
		t.Logf("status %s cand %s/%d catch %s fire %s", dd.Status, dd.CandStatus, dd.CandCount, dd.CatchState, dd.FireAt)
		t.Fatal("orders must start on the registrar signal")
	}
	if d.ConfirmedAvailAt.IsZero() {
		for _, c := range st.ListChecks(id, 40) {
			t.Logf("check %s %s %s %s", c.TS.Format("15:04:05"), c.Purpose, c.Source, c.Result+" "+c.Detail)
		}
		evs, _ := st.ListEvents(id, "", 30, 0)
		for _, x := range evs {
			t.Logf("event %s %s", x.Type, x.Detail)
		}
		t.Logf("status %s cand %s catch %s", d.Status, d.CandStatus, d.CatchState)
	}
	if d.ConfirmedAvailAt.IsZero() || d.ConfirmedAvailAt.Sub(dropAt) > 10*time.Second {
		t.Fatalf("confirmation %s after the drop (want seconds)", d.ConfirmedAvailAt.Sub(dropAt))
	}
	if !strings.Contains(d.ConfirmDetail, "reg:netim=available") {
		t.Fatalf("confirmed by %q", d.ConfirmDetail)
	}
	ev, _ := st.ListEvents(id, "", 100, 0)
	unconf := 0
	for _, x := range ev {
		if x.Type == "unconfirmed" {
			unconf++
		}
	}
	if unconf > 1 {
		t.Fatalf("%d unconfirmed events, want at most one per episode", unconf)
	}
}

package engine

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
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
	if !ok || !r.NoBlindFire {
		t.Fatal(".lu rule must exist and not fire blind")
	}
	// entered pending delete 2026-10-26 (any time, UTC) -> End Date 2026-11-24
	at, err := ExpectedRelease(ReleaseInput{Suffix: "lu", PendingDelete: true, PendingDeleteSince: ts("2026-10-26T13:20:00Z"), PendingDeleteObserved: true})
	if err != nil || !at.Equal(ts("2026-11-24T00:00:00Z")) {
		t.Fatalf("%s %v", at, err)
	}
	if _, err := ExpectedRelease(ReleaseInput{Suffix: "lu", PendingDelete: true, PendingDeleteSince: ts("2026-10-26T13:20:00Z")}); err == nil {
		t.Fatal("unobserved start must not be guessed")
	}
	rel := ts("2026-11-24T00:00:00Z")
	from, to, every := r.WatchWindow(rel, ts("2026-11-24T01:00:00Z"))
	if !from.Equal(ts("2026-11-23T23:00:00Z")) || !to.Equal(ts("2026-11-24T12:00:00Z")) || every != time.Minute {
		t.Fatalf("window %s %s %s", from, to, every)
	}
	if _, _, every := r.WatchWindow(rel, ts("2026-11-24T08:00:00Z")); every != 2*time.Minute {
		t.Fatalf("late interval %s", every)
	}
}

func TestLUNoBlindFireButWatch(t *testing.T) {
	e, st, _, id := setup(t) // setup uses foobar123.lu
	at := time.Now().Add(30 * time.Minute)
	st.UpdateDomainSettings(id, store.DomainSettings{MonitorEnabled: true, MonitorInterval: 3600, CatchEnabled: true, CatchInterval: 60,
		CatchDuration: 1, CatchRegistrars: []string{"a"}, FireAt: at, FireAuto: true, FireLead: 0, FireDuration: 720})
	d, _ := st.GetDomain(id)
	if _, ok := e.fireDue(d, time.Now()); ok {
		t.Fatal(".lu computed window must not fire blind")
	}
	if _, watching, _ := e.watchWindow(d, time.Now()); !watching {
		t.Fatal("must watch from release -1h")
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

package monitor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/store"
)

func TestParseWhoisSamples(t *testing.T) {
	cases := map[string]struct {
		status string
		kind   ErrKind
	}{
		"foobar123.lu":   {status: store.StatusAvailable},
		"bankbazaar.tw":  {status: store.StatusRegistered},
		"google.com":     {status: store.StatusRegistered},
		"walfer-lsap.lu": {kind: ErrRateLimited},
	}
	for name, want := range cases {
		b, err := os.ReadFile(filepath.Join("testdata", "whois_"+name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		st, info, err := parseWhois(b)
		if KindOf(err) != want.kind {
			t.Errorf("%s: kind %v, want %v (%v)", name, KindOf(err), want.kind, err)
		}
		if st != want.status {
			t.Errorf("%s: status %q, want %q", name, st, want.status)
		}
		if name == "bankbazaar.tw" {
			if info == nil || info.Registrar != "GoDaddy" || info.Expires.Year() != 2027 || len(info.Nameservers) != 2 {
				t.Errorf("bankbazaar.tw info: %+v", info)
			}
		}
	}
}

func TestParseWhoisEdgeCases(t *testing.T) {
	cases := []struct {
		body   string
		status string
		kind   ErrKind
	}{
		// unknown with no raw data must never read as available
		{`{"code":0,"msg":"ok","data":{"unknown":true,"registered":false,"whoisData":"","rdapData":""}}`, "", ErrUnparsed},
		// unparseable but non-empty registry answer (e.g. .ch): never available
		{`{"code":0,"msg":"ok","data":{"unknown":true,"registered":false,"whoisData":"Domain name:\nnic.ch\nRegistrar:\nnone","rdapData":""}}`, "", ErrUnparsed},
		{`{"code":0,"msg":"ok","data":{"registered":true,"pendingDelete":true,"status":[{"text":"Pending Delete"}]}}`, store.StatusPendingDelete, ErrNone},
		{`{"code":0,"msg":"ok","data":{"registered":true,"redemptionPeriod":true}}`, store.StatusRedemption, ErrNone},
		{`{"code":0,"msg":"ok","data":{"reserved":true}}`, store.StatusReserved, ErrNone},
		{`{"code":1,"msg":"No WHOIS or RDAP server found for 'x.zz'.","data":null}`, "", ErrUnsupported},
		{`{"code":1,"msg":"'x' is not a valid domain.","data":null}`, "", ErrInvalid},
		{`{"code":1,"msg":"WHOIS and RDAP lookups failed for 'x.lu'.","data":null}`, "", ErrTransient},
		{`not json`, "", ErrTransient},
	}
	for i, c := range cases {
		st, _, err := parseWhois([]byte(c.body))
		if st != c.status || KindOf(err) != c.kind {
			t.Errorf("case %d: got (%q, %v %v), want (%q, %v)", i, st, KindOf(err), err, c.status, c.kind)
		}
	}
}

func TestParseCloudean(t *testing.T) {
	d, _ := domainutil.Parse("foobar123.lu")
	cases := []struct {
		body   string
		status string
		kind   ErrKind
	}{
		{`{"sld":"foobar123","tld":".lu","premium":false,"status":"ok"}`, store.StatusAvailable, ErrNone},
		{`{"sld":"foobar123","tld":".lu","premium":false,"status":""}`, store.StatusRegistered, ErrNone},
		{`{"status":"notsuppoerted"}`, "", ErrUnsupported},
		{`[]`, "", ErrUnsupported},
		{`{"sld":"foobar","tld":".lu","status":"ok"}`, "", ErrInvalid}, // Cloudean mangled the name
	}
	for i, c := range cases {
		st, _, err := parseCloudean([]byte(c.body), d)
		if st != c.status || KindOf(err) != c.kind {
			t.Errorf("case %d: got (%q, %v), want (%q, %v)", i, st, KindOf(err), c.status, c.kind)
		}
	}
	bad, _ := domainutil.Parse("a-.com")
	if bad.Label != "" {
		if err := checkLabel(bad); KindOf(err) != ErrInvalid {
			t.Errorf("invalid label accepted")
		}
	}
}

func TestGatePriority(t *testing.T) {
	g := NewGate(150 * time.Millisecond)
	ctx := context.Background()
	g.Wait(ctx, false) // consume the first slot
	order := make(chan string, 2)
	go func() { g.Wait(ctx, false); order <- "low" }()
	time.Sleep(20 * time.Millisecond)
	go func() { g.Wait(ctx, true); order <- "high" }()
	if first := <-order; first != "high" {
		t.Fatalf("priority waiter should go first, got %s", first)
	}
	<-order
}

func TestRegeryBudget(t *testing.T) {
	r := NewRegery(time.Second, 60)
	r.bucket = 6
	for i := 0; i < 1; i++ {
		if err := r.take(false); err != nil {
			t.Fatalf("routine take %d: %v", i, err)
		}
	}
	// 5 left = reserve: routine checks are refused, priority still allowed
	if err := r.take(false); KindOf(err) != ErrBusy {
		t.Fatalf("routine check should be refused when only the reserve is left, got %v", err)
	}
	if err := r.take(true); err != nil {
		t.Fatalf("priority check should use the reserve: %v", err)
	}
	r.blocked = time.Now().Add(time.Minute)
	if err := r.take(true); KindOf(err) != ErrRateLimited {
		t.Fatalf("blocked source should report rate limit, got %v", err)
	}
}

// fakeSource returns scripted observations.
type fakeSource struct {
	name   string
	status string
	kind   ErrKind
	calls  int
}

func (f *fakeSource) Name() string  { return f.name }
func (f *fakeSource) Label() string { return f.name }
func (f *fakeSource) Check(ctx context.Context, d domainutil.Name, prio bool) Observation {
	f.calls++
	o := Observation{Source: f.name, Elapsed: time.Millisecond}
	if f.kind != ErrNone {
		o.Err = lerr(f.kind, "%s failed", f.name)
		return o
	}
	o.Status = f.status
	return o
}

func newTestStore(t *testing.T) *store.Store {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestManagerFallbackAndBench(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)
	cl := &fakeSource{name: SrcCloudean, status: store.StatusAvailable}
	rg := &fakeSource{name: SrcRegery, status: store.StatusAvailable}
	m.Configure(Config{Fallbacks: []string{SrcCloudean, SrcRegery}, ErrorStreak: 2, Cooldown: time.Minute}, nil, []Source{cl, rg}, nil)
	d, _ := domainutil.Parse("foobar123.lu")

	cl.kind = ErrRateLimited
	res := m.Check(context.Background(), d, false)
	if res.Obs.Err != nil || res.Obs.Source != SrcRegery {
		t.Fatalf("expected fallback to regery, got %+v", res.Obs)
	}
	if h := st.Health("lu", SrcCloudean); h.Usable(time.Now()) {
		t.Fatal("rate-limited source should be benched for the suffix")
	}
	if h := st.Health("com", SrcCloudean); !h.Usable(time.Now()) {
		t.Fatal("bench must be per suffix")
	}
	calls := cl.calls
	m.Check(context.Background(), d, false)
	if cl.calls != calls {
		t.Fatal("benched source must be skipped")
	}
	st.ClearHealth("lu", SrcCloudean)
	cl.kind = ErrNone
	if p := m.Plan("lu"); len(p) != 2 {
		t.Fatalf("plan after un-bench: %v", p)
	}
}

func TestConfirmRule(t *testing.T) {
	st := newTestStore(t)
	m := NewManager(st)
	cl := &fakeSource{name: SrcCloudean, status: store.StatusRegistered}
	rg := &fakeSource{name: SrcRegery, status: store.StatusAvailable}
	m.Configure(Config{Fallbacks: []string{SrcCloudean, SrcRegery}}, nil, []Source{cl, rg}, nil)
	d, _ := domainutil.Parse("foobar123.lu")

	whoisAvail := Observation{Source: SrcWhois, Status: store.StatusAvailable}
	c := m.Confirm(context.Background(), d, &whoisAvail, false)
	if !c.Confirmed || c.SecondaryAvail != SrcRegery {
		t.Fatalf("whois avail + regery avail should confirm: %+v", c)
	}

	rg.status = store.StatusRegistered
	c = m.Confirm(context.Background(), d, &whoisAvail, false)
	if c.Confirmed {
		t.Fatal("no secondary agreement must not confirm")
	}

	// a fallback signal alone (no WHOIS configured) never confirms by default
	rg.status, cl.status = store.StatusAvailable, store.StatusAvailable
	fb := Observation{Source: SrcCloudean, Status: store.StatusAvailable}
	if c = m.Confirm(context.Background(), d, &fb, false); c.Confirmed {
		t.Fatal("without WHOIS, confirmation needs the opt-in")
	}
	if c = m.Confirm(context.Background(), d, &fb, true); !c.Confirmed {
		t.Fatalf("opt-in: two fallbacks agreeing should confirm: %s", c.Summary())
	}

	// unsupported secondaries do not count
	rg.kind, cl.kind = ErrUnsupported, ErrUnsupported
	st.ClearHealth("lu", SrcCloudean)
	st.ClearHealth("lu", SrcRegery)
	if c = m.Confirm(context.Background(), d, &whoisAvail, false); c.Confirmed {
		t.Fatal("unsupported sources must not confirm")
	}
}

func TestExternalWhoisFallbackOrder(t *testing.T) {
	st := newTestStore(t)
	internalHits, ext1Hits, ext2Hits := 0, 0, 0
	mk := func(hits *int, body string, status int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*hits++
			if r.URL.Path != "/src/index.php" || r.URL.Query().Get("json") != "1" {
				t.Errorf("unexpected path %s", r.URL)
			}
			w.WriteHeader(status)
			io.WriteString(w, body)
		}))
	}
	registered := `{"code":0,"msg":"Query successful.","data":{"registered":true,"registrar":"GoDaddy","status":[{"text":"Client Hold"}],"nameServers":["a.ns"],"expirationDateISO8601":"2027-03-12T06:40:45Z"}}`
	rateLimited := `{"code":1,"msg":"WHOIS and RDAP lookups failed for 'x.tw': temporarily unavailable due to rate limiting.","data":{"rateLimited":true}}`
	internal := mk(&internalHits, rateLimited, 200)
	defer internal.Close()
	ext1 := mk(&ext1Hits, ``, 502)
	defer ext1.Close()
	ext2 := mk(&ext2Hits, registered, 200)
	defer ext2.Close()

	m := NewManager(st)
	cl := &fakeSource{name: SrcCloudean, status: store.StatusAvailable}
	m.SetExternalWhois([]*Whois{NewExternalWhois(ext1.URL+"/", "", 5*time.Second, 0), NewExternalWhois(ext2.URL, "", 5*time.Second, 0)})
	m.Configure(Config{WhoisEnabled: true, Fallbacks: []string{SrcCloudean}, ErrorStreak: 3, Cooldown: time.Minute}, NewWhois(internal.URL, "", 5*time.Second, 0), []Source{cl}, nil)

	plan := m.Plan("tw")
	if len(plan) != 4 || plan[0] != SrcWhois || !IsWhois(plan[1]) || !IsWhois(plan[2]) || plan[3] != SrcCloudean {
		t.Fatalf("plan should be internal, ext1, ext2, cloudean: %v", plan)
	}
	d, _ := domainutil.Parse("bankbazaar.tw")
	res := m.Check(context.Background(), d, false)
	if res.Obs.Err != nil || !IsWhois(res.Obs.Source) || res.Obs.Source == SrcWhois || res.Obs.Info == nil || res.Obs.Info.Registrar != "GoDaddy" {
		t.Fatalf("expected registration data from the second external sidecar, got %+v", res.Obs)
	}
	// each failing sidecar is asked twice (preferred source, then the other)
	if internalHits != 2 || ext1Hits != 2 || ext2Hits != 1 || cl.calls != 0 {
		t.Fatalf("hits internal=%d ext1=%d ext2=%d cloudean=%d", internalHits, ext1Hits, ext2Hits, cl.calls)
	}
	// the rate-limited internal sidecar is benched for .tw; next check starts at the externals
	if h := st.Health("tw", SrcWhois); h.Usable(time.Now()) {
		t.Fatal("rate-limited internal sidecar should be benched for the suffix")
	}
	if p := m.Plan("tw"); p[0] == SrcWhois || !IsWhois(p[0]) {
		t.Fatalf("plan after bench: %v", p)
	}
	// confirmation can use an external sidecar's WHOIS answer
	ext := Observation{Source: res.Obs.Source, Status: store.StatusAvailable}
	cl.status = store.StatusAvailable
	if c := m.Confirm(context.Background(), d, &ext, false); !c.Confirmed {
		t.Fatalf("external WHOIS + Cloudean should confirm: %s", c.Summary())
	}
}

func TestWhoisSourceOrder(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		src := "merged"
		if q.Get("whois") == "1" {
			src = "whois"
		} else if q.Get("rdap") == "1" {
			src = "rdap"
		}
		got = append(got, src)
		if src == "merged" {
			t.Errorf("the merged WHOIS+RDAP mode must never be used")
		}
		if src == "whois" {
			// port 43 unreachable from this host
			io.WriteString(w, `{"code":1,"msg":"WHOIS lookup failed for 'x': Operation timed out.","data":null}`)
			return
		}
		io.WriteString(w, `{"code":0,"msg":"ok","data":{"registered":true,"pendingDelete":true,"creationDateISO8601":"1998-08-21T10:19:34Z","expirationDateISO8601":"2026-10-26T16:00:00Z","status":[{"text":"pendingdelete"}]}}`)
	}))
	defer srv.Close()
	w := NewWhois(srv.URL, "", 5*time.Second, 0)
	d, _ := domainutil.Parse("sina.com.tw")
	o := w.Check(context.Background(), d, true)
	if o.Err != nil || o.Status != store.StatusPendingDelete || o.Info.Source != "rdap" || len(got) != 1 || got[0] != "rdap" {
		t.Fatalf(".tw must ask RDAP first: %v %+v", got, o)
	}
	got = nil
	d, _ = domainutil.Parse("example.com")
	o = w.Check(context.Background(), d, true)
	if o.Err != nil || len(got) != 2 || got[0] != "whois" || got[1] != "rdap" {
		t.Fatalf(".com: WHOIS first, RDAP when WHOIS fails: %v %+v", got, o)
	}
}

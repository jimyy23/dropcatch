package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"dropcatch/internal/store"
)

func TestCIRATBRList(t *testing.T) {
	body := `[{"name":"tamimahmed.ca","date":"2026-11-25"},{"name":"XN--CAMPUSSANSFUME-NKB.ca","date":"2026-11-25"},{"name":"later.ca","date":"2026-12-02"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.UserAgent(), "Mozilla/") {
			w.WriteHeader(403) // Cloudflare blocks non-browser agents
			io.WriteString(w, "<html>Just a moment...</html>")
			return
		}
		io.WriteString(w, body)
	}))
	defer srv.Close()

	e, st, _, _ := setup(t)
	e.SetTBRList(NewTBRList(srv.URL))
	ca, _ := st.AddDomain(store.NewDomain{Name: "tamimahmed.ca", UName: "tamimahmed.ca", Suffix: "ca", MonitorInterval: 3600, CatchInterval: 1, CatchDuration: 1})
	other, _ := st.AddDomain(store.NewDomain{Name: "notlisted.ca", UName: "notlisted.ca", Suffix: "ca", MonitorInterval: 3600, CatchInterval: 1, CatchDuration: 1})

	e.RefreshTBR(context.Background(), time.Hour)
	if s := e.TBR().Status(); s.Count != 3 || s.Err != "" || len(s.Sessions) != 2 {
		t.Fatalf("status %+v", s)
	}
	if at, ok := e.TBR().Lookup("xn--campussansfume-nkb.ca"); !ok || !at.Equal(time.Date(2026, 11, 25, 19, 0, 0, 0, time.UTC)) {
		t.Fatalf("case-insensitive lookup: %s %v", at, ok)
	}
	// listed: the list date wins, even before the monitor saw pending delete
	d, _ := st.GetDomain(ca)
	if !d.FireAt.Equal(time.Date(2026, 11, 25, 19, 0, 0, 0, time.UTC)) {
		t.Fatalf("listed fire_at %s", d.FireAt)
	}
	// not listed and not pending delete: no fire time
	d, _ = st.GetDomain(other)
	if !d.FireAt.IsZero() {
		t.Fatalf("unlisted fire_at %s", d.FireAt)
	}
	// the list overrides the computed week
	in := e.ReleaseInput(&store.Domain{Name: "later.ca", Suffix: "ca", PendingDelete: true, Updated: time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)})
	if at, _ := ExpectedRelease(in); !at.Equal(time.Date(2026, 12, 2, 19, 0, 0, 0, time.UTC)) {
		t.Fatalf("list must override computed session: %s", at)
	}

	// a blocked or broken fetch keeps the previous list
	body = `<html>Just a moment...</html>`
	if err := e.TBR().Refresh(context.Background()); err == nil {
		t.Fatal("non-JSON must be an error")
	}
	if s := e.TBR().Status(); s.Count != 3 || s.Err == "" {
		t.Fatalf("previous list must be kept: %+v", s)
	}
}

// Fetches the real list (read-only).
//
//	LIVE_CIRA_TBR=1 go test ./internal/engine -run LiveCIRATBR -v
func TestLiveCIRATBR(t *testing.T) {
	if !liveEnv("LIVE_CIRA_TBR") {
		t.Skip("set LIVE_CIRA_TBR=1")
	}
	l := NewTBRList(CIRATBRURL)
	if err := l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", l.Status())
}

func liveEnv(k string) bool { return os.Getenv(k) == "1" || os.Getenv("LIVE_ALL") == "1" }

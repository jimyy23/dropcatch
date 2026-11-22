package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"dropcatch/internal/config"
	"dropcatch/internal/engine"
	"dropcatch/internal/monitor"
	"dropcatch/internal/notify"
	"dropcatch/internal/pricing"
	"dropcatch/internal/registrar"
	"dropcatch/internal/store"
)

func TestPagesRenderAndAuth(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.CreateUser("admin", "admin-pass-123"); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mon := monitor.NewManager(st)
	mon.Configure(monitor.Config{Fallbacks: []string{monitor.SrcCloudean}}, nil, nil, nil)
	regs := registrar.NewSet(registrar.NewPorkbun(config.Porkbun{}, true))
	eng := engine.New(st, mon, regs, notify.New(config.Twilio{}, config.Telegram{}), pricing.New(st, time.Hour), log)
	srv := &Server{St: st, Eng: eng, Log: log, ApplySettings: func() {}}
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(h)
	defer ts.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	resp, _ := c.Get(ts.URL + "/settings")
	resp.Body.Close()
	if !strings.HasPrefix(resp.Request.URL.Path, "/login") {
		t.Fatalf("expected redirect to login, got %s", resp.Request.URL)
	}
	resp, err = c.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"admin-pass-123"}})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("login: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(string(body))
	if m == nil {
		t.Fatal("no csrf token on dashboard")
	}
	csrf := m[1]

	resp, _ = c.PostForm(ts.URL+"/domains", url.Values{"names": {"example.com"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without csrf: HTTP %d", resp.StatusCode)
	}

	resp, _ = c.PostForm(ts.URL+"/domains", url.Values{"csrf": {csrf}, "names": {"müller-example.de\nwww.sub.example.com"}, "registrar": {"porkbun", "bogus"}})
	resp.Body.Close()
	ds := st.ListDomains()
	if len(ds) != 1 || ds[0].UName != "müller-example.de" || len(ds[0].CatchRegistrars) != 1 {
		t.Fatalf("domains: %+v", ds)
	}
	id := strconv.FormatInt(ds[0].ID, 10)

	resp, _ = c.PostForm(ts.URL+"/domain/"+id+"/settings", url.Values{"csrf": {csrf}, "monitor_enabled": {"1"}, "monitor_interval": {"600"},
		"catch_enabled": {"1"}, "catch_start": {"2030-01-02T03:04"}, "catch_end": {"2030-01-02T05:00"}, "catch_duration": {"15"}, "registrar": {"porkbun"}})
	resp.Body.Close()
	d, _ := st.GetDomain(ds[0].ID)
	if !d.CatchStart.Equal(time.Date(2030, 1, 2, 3, 4, 0, 0, time.UTC)) || d.CatchDuration != 15 || !d.CatchEnabled {
		t.Fatalf("settings not saved: start=%s dur=%d", d.CatchStart, d.CatchDuration)
	}
	resp, _ = c.PostForm(ts.URL+"/domain/"+id+"/settings", url.Values{"csrf": {csrf}, "monitor_enabled": {"1"}, "catch_enabled": {"1"}, "catch_interval": {"1"}, "registrar": {"porkbun"}, "catch_start": {"2030-01-02T03:04"}, "catch_end": {"2030-01-02T05:00"}})
	resp.Body.Close()
	if d, _ := st.GetDomain(ds[0].ID); d.CatchInterval != 1 {
		t.Fatalf("armed interval of 1 s should be accepted, got %d", d.CatchInterval)
	}
	resp, _ = c.PostForm(ts.URL+"/domain/"+id+"/settings", url.Values{"csrf": {csrf}, "catch_interval": {"0"}, "catch_start": {"2030-01-02T03:04"}, "catch_end": {"2030-01-02T05:00"}})
	resp.Body.Close()
	if d, _ := st.GetDomain(ds[0].ID); d.CatchInterval != 1 {
		t.Fatalf("armed interval below 1 s must clamp to 1, got %d", d.CatchInterval)
	}
	resp, _ = c.PostForm(ts.URL+"/domain/"+id+"/settings", url.Values{"csrf": {csrf}, "catch_start": {"2030-01-02T03:04"}, "catch_end": {"2030-01-01T00:00"}})
	resp.Body.Close()
	if !strings.Contains(resp.Request.URL.RawQuery, "err=") {
		t.Fatal("end before start should be rejected")
	}

	// manual register starts without any typed confirmation (registrar keys
	// are not configured here, so the session ends at once with no orders)
	resp, _ = c.PostForm(ts.URL+"/domain/"+id+"/register-now", url.Values{"csrf": {csrf}})
	resp.Body.Close()
	if strings.Contains(resp.Request.URL.RawQuery, "type+the+domain") {
		t.Fatal("register-now must not ask for a typed confirmation")
	}

	for _, p := range []string{"/", "/?f=armed", "/domain/" + id, "/orders", "/registrars", "/events", "/events?level=alert", "/sources", "/settings", "/users", "/account", "/help", "/domains.json"} {
		resp, err := c.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s: HTTP %d", p, resp.StatusCode)
		}
		if p == "/domain/"+id && !strings.Contains(string(b), "2030-01-02T03:04") {
			t.Errorf("domain page should show the saved UTC window")
		}
	}
}

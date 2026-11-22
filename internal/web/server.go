// Package web is the admin UI.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"dropcatch/internal/config"
	"dropcatch/internal/engine"
	"dropcatch/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Server holds web dependencies.
type Server struct {
	St            *store.Store
	Eng           *engine.Engine
	Env           config.Env
	Log           *slog.Logger
	ApplySettings func()

	tmpl      map[string]*template.Template
	loginMu   sync.Mutex
	loginFail map[string][]time.Time
}

type ctxKey int

const (
	keyUser ctxKey = iota
	keyCSRF
)

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"date":     fmtDate,
		"datetime": fmtDateTime,
		"iso":      func(t time.Time) string { return isoOrEmpty(t) },
		"local":    fmtLocalInput,
		"ago":      ago,
		"until":    until,
		"join":     strings.Join,
		"isZero":   func(t time.Time) bool { return t.IsZero() },
		"days": func(t time.Time) int {
			if t.IsZero() {
				return 0
			}
			return int(time.Until(t).Hours() / 24)
		},
		"secs":   fmtSecs,
		"ms":     func(n int64) string { return fmt.Sprintf("%.1fs", float64(n)/1000) },
		"has":    func(list []string, x string) bool { return contains(list, x) },
		"add":    func(a, b int) int { return a + b },
		"sub":    func(a, b int) int { return a - b },
		"now":    func() time.Time { return time.Now().UTC() },
		"lower":  strings.ToLower,
		"srcLbl": srcLabel,
		"query":  func(v url.Values, kv ...string) template.URL { return template.URL(withQuery(v, kv...)) },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
	}
	s.tmpl = map[string]*template.Template{}
	pages, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return err
	}
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" || strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/_partials.html", p)
		if err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.tmpl[name] = t
	}
	return nil
}

// Handler builds the HTTP handler.
func (s *Server) Handler() (http.Handler, error) {
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.loginFail = map[string][]time.Time{}
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServer(http.FS(static)))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.St.R.PingContext(r.Context()); err != nil {
			http.Error(w, "db: "+err.Error(), 503)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupPost)

	auth := func(p string, h http.HandlerFunc) { mux.Handle(p, s.requireAuth(h)) }
	auth("POST /logout", s.logout)
	auth("GET /{$}", s.dashboard)
	auth("GET /domains.json", s.domainsJSON)
	auth("POST /domains", s.domainsAdd)
	auth("POST /domains/bulk", s.domainsBulk)
	auth("GET /domain/{id}", s.domainDetail)
	auth("POST /domain/{id}/settings", s.domainSettings)
	auth("POST /domain/{id}/toggle", s.domainToggle)
	auth("POST /domain/{id}/check", s.domainCheck)
	auth("POST /domain/{id}/probe", s.domainProbe)
	auth("POST /domain/{id}/catch/stop", s.domainCatchStop)
	auth("POST /domain/{id}/register-now", s.domainRegisterNow)
	auth("POST /domain/{id}/catch/reset", s.domainCatchReset)
	auth("POST /domain/{id}/pricing", s.domainPricing)
	auth("POST /domain/{id}/delete", s.domainDelete)
	auth("GET /orders", s.orders)
	auth("GET /registrars", s.registrarsPage)
	auth("GET /events", s.events)
	auth("GET /sources", s.sources)
	auth("POST /sources/reset", s.sourcesReset)
	auth("GET /settings", s.settingsPage)
	auth("POST /settings", s.settingsPost)
	auth("POST /settings/test-notify", s.testNotify)
	auth("GET /users", s.users)
	auth("POST /users", s.usersCreate)
	auth("POST /users/{id}/toggle", s.usersToggle)
	auth("POST /users/{id}/delete", s.usersDelete)
	auth("POST /users/{id}/password", s.usersPassword)
	auth("GET /account", s.account)
	auth("POST /account/password", s.accountPassword)
	auth("GET /help", s.help)
	return s.secHeaders(s.recoverer(mux)), nil
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) secHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.Log.Error("http panic", "path", r.URL.Path, "panic", v)
				http.Error(w, "internal error", 500)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

const cookieName = "dropcatch_session"

func (s *Server) requireAuth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.St.CountUsers() == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil {
			s.toLogin(w, r)
			return
		}
		u, csrf, err := s.St.Session(c.Value)
		if err != nil {
			s.toLogin(w, r)
			return
		}
		if r.Method == http.MethodPost {
			r.ParseMultipartForm(1 << 20)
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(csrf)) != 1 {
				http.Error(w, "invalid CSRF token; reload the page and retry", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), keyUser, u)
		ctx = context.WithValue(ctx, keyCSRF, csrf)
		h(w, r.WithContext(ctx))
	})
}

func (s *Server) toLogin(w http.ResponseWriter, r *http.Request) {
	next := r.URL.RequestURI()
	if r.Method != http.MethodGet {
		next = "/"
	}
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
}

func user(r *http.Request) *store.User {
	u, _ := r.Context().Value(keyUser).(*store.User)
	return u
}

// page is the common template payload.
type page struct {
	Title  string
	Nav    string
	User   *store.User
	CSRF   string
	Flash  string
	Error  string
	DryRun bool
	Q      url.Values
	Data   any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	t, ok := s.tmpl[name]
	if !ok {
		http.Error(w, "template not found: "+name, 500)
		return
	}
	p.User = user(r)
	p.CSRF, _ = r.Context().Value(keyCSRF).(string)
	p.DryRun = s.Env.OrdersDryRun
	if p.Q == nil {
		p.Q = r.URL.Query()
	}
	if p.Flash == "" {
		p.Flash = r.URL.Query().Get("flash")
	}
	if p.Error == "" {
		p.Error = r.URL.Query().Get("err")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := t.Execute(w, p); err != nil {
		s.Log.Error("render", "template", name, "err", err)
	}
}

func redirect(w http.ResponseWriter, r *http.Request, to, flash, errMsg string) {
	u, _ := url.Parse(to)
	q := u.Query()
	if flash != "" {
		q.Set("flash", flash)
	}
	if errMsg != "" {
		q.Set("err", errMsg)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func backTo(r *http.Request, def string) string {
	if b := r.FormValue("back"); strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
		return b
	}
	return def
}

// ---- login / setup

func (s *Server) clientIP(r *http.Request) string {
	if s.Env.TrustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			return strings.TrimSpace(strings.Split(xf, ",")[0])
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (s *Server) throttled(ip string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	var keep []time.Time
	for _, t := range s.loginFail[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.loginFail[ip] = keep
	return len(keep) >= 10
}

func (s *Server) noteFail(ip string) {
	s.loginMu.Lock()
	s.loginFail[ip] = append(s.loginFail[ip], time.Now())
	s.loginMu.Unlock()
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.St.CountUsers() == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", page{Title: "Login"})
}

func (s *Server) setCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.Env.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.throttled(ip) {
		s.render(w, r, "login", page{Title: "Login", Error: "Too many failed attempts. Try again in 15 minutes."})
		return
	}
	u, err := s.St.Authenticate(strings.TrimSpace(r.FormValue("username")), r.FormValue("password"))
	if err != nil {
		s.noteFail(ip)
		s.Log.Warn("login failed", "ip", ip, "user", r.FormValue("username"))
		s.render(w, r, "login", page{Title: "Login", Error: err.Error()})
		return
	}
	tok, _, err := s.St.CreateSession(u.ID, 7*24*time.Hour)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	s.setCookie(w, tok, 7*24*3600)
	s.Log.Info("login", "user", u.Username, "ip", ip)
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.St.DeleteSession(c.Value)
	}
	s.setCookie(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if s.St.CountUsers() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, "setup", page{Title: "Initial setup"})
}

func (s *Server) setupPost(w http.ResponseWriter, r *http.Request) {
	if s.St.CountUsers() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if r.FormValue("password") != r.FormValue("password2") {
		s.render(w, r, "setup", page{Title: "Initial setup", Error: "passwords do not match"})
		return
	}
	id, err := s.St.CreateUser(strings.TrimSpace(r.FormValue("username")), r.FormValue("password"))
	if err != nil {
		s.render(w, r, "setup", page{Title: "Initial setup", Error: err.Error()})
		return
	}
	tok, _, _ := s.St.CreateSession(id, 7*24*time.Hour)
	s.setCookie(w, tok, 7*24*3600)
	redirect(w, r, "/", "Admin account created. Add your first domain below.", "")
}

// ---- helpers

func pathID(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return n
}

func withQuery(v url.Values, kv ...string) string {
	q := url.Values{}
	for k, vs := range v {
		q[k] = append([]string(nil), vs...)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			q.Del(kv[i])
		} else {
			q.Set(kv[i], kv[i+1])
		}
	}
	return "?" + q.Encode()
}

func contains(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

func fmtDate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02")
}

func fmtDateTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func isoOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// fmtLocalInput renders a UTC time for <input type=datetime-local> (which we
// always interpret as UTC).
func fmtLocalInput(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04")
}

func fmtSecs(n int) string {
	d := time.Duration(n) * time.Second
	switch {
	case n%86400 == 0 && n >= 86400:
		return fmt.Sprintf("%dd", n/86400)
	case n%3600 == 0 && n >= 3600:
		return fmt.Sprintf("%dh", n/3600)
	case n%60 == 0 && n >= 60:
		return fmt.Sprintf("%dm", n/60)
	}
	return d.String()
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < 0:
		return "in " + until(t)
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func until(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Until(t)
	if d < 0 {
		return "due"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds())+1)
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func srcLabel(s string) string {
	switch s {
	case "whois":
		return "WHOIS/RDAP"
	case "cloudean":
		return "Cloudean"
	case "regery":
		return "Regery (web)"
	case "":
		return "—"
	}
	if strings.HasPrefix(s, "reg:") {
		return strings.TrimPrefix(s, "reg:") + " API"
	}
	return s
}

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/engine"
	"dropcatch/internal/monitor"
	"dropcatch/internal/pricing"
	"dropcatch/internal/registrar"
	"dropcatch/internal/settings"
	"dropcatch/internal/store"
)

// ---- dashboard / domain list

type domainRow struct {
	*store.Domain
	Armed     bool
	ArmReason string
	Worker    engine.WorkerState
}

type dashData struct {
	Rows       []domainRow
	Registrars []registrar.Info
	Defaults   map[string]int
	Counts     map[string]int
	Events     []store.Event
	CallOK     bool
	TelegramOK bool
	WhoisURL   string
	Filter     string
}

func (s *Server) rows(filter string) ([]domainRow, map[string]int) {
	now := time.Now()
	states := s.Eng.States()
	counts := map[string]int{}
	var out []domainRow
	for _, d := range s.St.ListDomains() {
		armed := d.Armed(now)
		counts["all"]++
		counts[d.Status]++
		if armed {
			counts["armed"]++
		}
		if d.CatchState == store.CatchActive {
			counts["catching"]++
		}
		if d.LastError != "" {
			counts["failing"]++
		}
		row := domainRow{Domain: d, Armed: armed, ArmReason: d.ArmReason(now), Worker: states[d.ID]}
		switch filter {
		case "armed":
			if !armed {
				continue
			}
		case "available", "registered", "pending_delete", "redemption", "unknown":
			if d.Status != filter {
				continue
			}
		case "failing":
			if d.LastError == "" {
				continue
			}
		}
		out = append(out, row)
	}
	return out, counts
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("f")
	rows, counts := s.rows(f)
	ev, _ := s.St.ListEvents(0, "", 15, 0)
	n := s.Eng.Notifier()
	d := dashData{
		Rows: rows, Counts: counts, Registrars: s.Eng.Registrars().Infos(), Events: ev, Filter: f,
		CallOK: n.CallConfigured(), TelegramOK: n.TelegramConfigured(), WhoisURL: s.Env.WhoisURL,
		Defaults: map[string]int{
			"monitor": settings.Int(s.St, "default_monitor_interval"),
			"catch":   settings.Int(s.St, "default_catch_interval"),
			"dur":     settings.Int(s.St, "default_catch_duration"),
		},
	}
	s.render(w, r, "dashboard", page{Title: "Domains", Nav: "domains", Data: d})
}

// domainsJSON feeds live refresh of the list (status, next check, catch state).
func (s *Server) domainsJSON(w http.ResponseWriter, r *http.Request) {
	rows, _ := s.rows("")
	type item struct {
		ID         int64  `json:"id"`
		Status     string `json:"status"`
		Source     string `json:"source"`
		Checked    string `json:"checked"`
		Next       string `json:"next"`
		Phase      string `json:"phase"`
		CatchState string `json:"catch"`
		Attempts   int    `json:"attempts"`
		Armed      bool   `json:"armed"`
		Error      string `json:"error"`
	}
	out := []item{}
	for _, d := range rows {
		out = append(out, item{ID: d.ID, Status: d.Status, Source: srcLabel(d.StatusSource), Checked: ago(d.CheckedAt), Next: until(d.Worker.NextAt),
			Phase: d.Worker.Phase, CatchState: d.CatchState, Attempts: d.CatchAttempts, Armed: d.Armed, Error: d.LastError})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}

func formInt(r *http.Request, key string, def, min, max int) int {
	n, err := strconv.Atoi(strings.TrimSpace(r.FormValue(key)))
	if err != nil {
		return def
	}
	if n < min {
		n = min
	}
	if n > max {
		n = max
	}
	return n
}

func (s *Server) selectedRegistrars(r *http.Request) []string {
	var out []string
	for _, k := range r.Form["registrar"] {
		if s.Eng.Registrars().Get(k) != nil && !contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// domainsAdd adds one or many domains (one per line / comma separated).
func (s *Server) domainsAdd(w http.ResponseWriter, r *http.Request) {
	raw := strings.NewReplacer(",", "\n", ";", "\n", " ", "\n", "\t", "\n").Replace(r.FormValue("names"))
	nd := store.NewDomain{
		Note:            strings.TrimSpace(r.FormValue("note")),
		MonitorEnabled:  true,
		MonitorInterval: formInt(r, "monitor_interval", settings.Int(s.St, "default_monitor_interval"), 30, 7*86400),
		CatchInterval:   formInt(r, "catch_interval", settings.Int(s.St, "default_catch_interval"), 1, 3600),
		CatchDuration:   formInt(r, "catch_duration", settings.Int(s.St, "default_catch_duration"), 1, 1440),
		CatchRegistrars: s.selectedRegistrars(r),
		AutoCatchPD:     r.FormValue("auto_catch_pd") == "1",
		NotifyCall:      r.FormValue("notify_call") == "1",
		NotifyTelegram:  r.FormValue("notify_telegram") == "1",
	}
	var added, errs []string
	var firstID int64
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		n, err := domainutil.Parse(line)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		nd.Name, nd.UName, nd.Suffix = n.ASCII, n.Unicode, n.Suffix
		id, err := s.St.AddDomain(nd)
		if err != nil {
			errs = append(errs, n.Unicode+": "+err.Error())
			continue
		}
		if firstID == 0 {
			firstID = id
		}
		added = append(added, n.Unicode)
		s.St.AddEvent(id, "added", "info", "added by "+user(r).Username)
		s.Eng.Start(id)
		go func(sfx string) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			s.Eng.Pricing().Get(ctx, sfx, false)
		}(n.Suffix)
	}
	flash := ""
	if len(added) > 0 {
		flash = fmt.Sprintf("Added %d: %s. First check is running now.", len(added), strings.Join(added, ", "))
	}
	to := "/"
	if len(added) == 1 && len(errs) == 0 {
		to = fmt.Sprintf("/domain/%d", firstID)
	}
	redirect(w, r, to, flash, strings.Join(errs, "; "))
}

func (s *Server) domainsBulk(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	var n int
	for _, v := range r.Form["id"] {
		id, _ := strconv.ParseInt(v, 10, 64)
		if id == 0 {
			continue
		}
		switch action {
		case "monitor_on", "monitor_off", "catch_on", "catch_off", "telegram_on", "telegram_off", "call_on", "call_off":
			field, val, _ := strings.Cut(action, "_")
			s.St.SetToggle(id, field, val == "on")
			s.Eng.Wake(id)
		case "check":
			s.Eng.CheckNow(id)
		case "delete":
			s.Eng.StopCatch(id)
			s.Eng.Stop(id)
			s.St.DeleteDomain(id)
		default:
			redirect(w, r, "/", "", "unknown action")
			return
		}
		n++
	}
	redirect(w, r, backTo(r, "/"), fmt.Sprintf("%s applied to %d domain(s).", action, n), "")
}

// ---- domain detail

type detailData struct {
	D          *store.Domain
	Armed      bool
	ArmReason  string
	Worker     engine.WorkerState
	Checks     []store.Check
	Orders     []store.Order
	Events     []store.Event
	Registrars []regOption
	Book       *pricing.Book
	Plan       []string
	Health     []store.SourceHealth
	Probe      []monitor.Observation
	CallOK     bool
	TelegramOK bool
}

type regOption struct {
	registrar.Info
	Selected bool
	Sells    string // yes | no | unknown
	Price    *pricing.Price
}

func (s *Server) domainDetail(w http.ResponseWriter, r *http.Request) {
	d, err := s.St.GetDomain(pathID(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.renderDetail(w, r, d, nil)
}

func (s *Server) renderDetail(w http.ResponseWriter, r *http.Request, d *store.Domain, probe []monitor.Observation) {
	now := time.Now()
	book, _ := s.Eng.Pricing().Cached(d.Suffix)
	var opts []regOption
	for _, info := range s.Eng.Registrars().Infos() {
		o := regOption{Info: info, Selected: contains(d.CatchRegistrars, info.Key), Sells: "unknown"}
		if book != nil && len(book.Prices) > 0 {
			if p := book.Price(info.PriceKey); p != nil {
				o.Sells, o.Price = "yes", p
			} else if book.Complete {
				o.Sells = "no"
			}
		}
		if hl := s.St.Health(d.Suffix, "reg:"+info.Key); !hl.UnsupportedUntil.IsZero() && now.Before(hl.UnsupportedUntil) {
			o.Sells = "no"
		}
		opts = append(opts, o)
	}
	var health []store.SourceHealth
	for _, n := range s.Eng.Monitor().SourceNames() {
		health = append(health, s.St.Health(d.Suffix, n))
	}
	ev, _ := s.St.ListEvents(d.ID, "", 50, 0)
	n := s.Eng.Notifier()
	data := detailData{
		D: d, Armed: d.Armed(now), ArmReason: d.ArmReason(now), Worker: s.Eng.States()[d.ID],
		Checks: s.St.ListChecks(d.ID, 60), Orders: s.St.ListOrders(d.ID, 100), Events: ev,
		Registrars: opts, Book: book, Plan: s.Eng.Monitor().Plan(d.Suffix), Health: health, Probe: probe,
		CallOK: n.CallConfigured(), TelegramOK: n.TelegramConfigured(),
	}
	s.render(w, r, "domain", page{Title: d.UName, Nav: "domains", Data: data})
}

// parseUTC reads a datetime-local value as UTC.
func parseUTC(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	for _, f := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(f, v, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid date/time %q (use YYYY-MM-DD HH:MM, UTC)", v)
}

func (s *Server) domainSettings(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	d, err := s.St.GetDomain(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	back := fmt.Sprintf("/domain/%d", id)
	start, err := parseUTC(r.FormValue("catch_start"))
	if err != nil {
		redirect(w, r, back, "", "start: "+err.Error())
		return
	}
	end, err := parseUTC(r.FormValue("catch_end"))
	if err != nil {
		redirect(w, r, back, "", "end: "+err.Error())
		return
	}
	if !start.IsZero() && !end.IsZero() && !end.After(start) {
		redirect(w, r, back, "", "the catch window end must be after its start")
		return
	}
	x := store.DomainSettings{
		Note:            strings.TrimSpace(r.FormValue("note")),
		MonitorEnabled:  r.FormValue("monitor_enabled") == "1",
		MonitorInterval: formInt(r, "monitor_interval", d.MonitorInterval, 30, 7*86400),
		CatchEnabled:    r.FormValue("catch_enabled") == "1",
		CatchInterval:   formInt(r, "catch_interval", d.CatchInterval, 1, 3600),
		CatchStart:      start,
		CatchEnd:        end,
		CatchDuration:   formInt(r, "catch_duration", d.CatchDuration, 1, 1440),
		CatchRegistrars: s.selectedRegistrars(r),
		AutoCatchPD:     r.FormValue("auto_catch_pd") == "1",
		NotifyCall:      r.FormValue("notify_call") == "1",
		NotifyTelegram:  r.FormValue("notify_telegram") == "1",
	}
	if err := s.St.UpdateDomainSettings(id, x); err != nil {
		redirect(w, r, back, "", err.Error())
		return
	}
	var warn []string
	if (x.CatchEnabled || x.AutoCatchPD) && len(x.CatchRegistrars) == 0 {
		warn = append(warn, "drop-catch needs at least one registrar")
	}
	for _, k := range x.CatchRegistrars {
		if rg := s.Eng.Registrars().Get(k); rg != nil && (!rg.Configured() || rg.Problem() != "") {
			warn = append(warn, rg.Label()+" is not configured in .env")
		}
	}
	if !end.IsZero() && end.Before(time.Now()) {
		warn = append(warn, "the catch window end is in the past")
	}
	s.St.AddEvent(id, "settings", "info", "settings updated by "+user(r).Username)
	s.Eng.Wake(id)
	redirect(w, r, back, "Settings saved.", strings.Join(warn, "; "))
}

func (s *Server) domainToggle(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	field := r.FormValue("field")
	on := r.FormValue("on") == "1"
	if err := s.St.SetToggle(id, field, on); err != nil {
		redirect(w, r, backTo(r, "/"), "", err.Error())
		return
	}
	state := map[bool]string{true: "on", false: "off"}[on]
	s.St.AddEvent(id, "toggle", "info", fmt.Sprintf("%s %s by %s", field, state, user(r).Username))
	s.Eng.Wake(id)
	if r.Header.Get("X-Requested-With") == "fetch" {
		w.WriteHeader(204)
		return
	}
	redirect(w, r, backTo(r, "/"), "", "")
}

func (s *Server) domainCheck(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	s.Eng.CheckNow(id)
	redirect(w, r, backTo(r, fmt.Sprintf("/domain/%d", id)), "Check queued; refresh in a few seconds.", "")
}

// domainProbe asks every source once and shows the answers side by side.
func (s *Server) domainProbe(w http.ResponseWriter, r *http.Request) {
	d, err := s.St.GetDomain(pathID(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	n, err := domainutil.Parse(d.Name)
	if err != nil {
		redirect(w, r, fmt.Sprintf("/domain/%d", d.ID), "", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	obs := s.Eng.Monitor().Probe(ctx, n)
	for _, o := range obs {
		if o.Source == "" {
			continue
		}
		c := store.Check{Purpose: "probe", Source: o.Source, MS: o.Elapsed.Milliseconds(), Detail: o.Detail, Result: o.Status}
		if o.Err != nil {
			c.Result, c.Detail = "error", o.Err.Error()
		}
		s.St.AddCheck(d.ID, c)
	}
	s.renderDetail(w, r, d, obs)
}

func (s *Server) domainCatchStop(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	msg := "No catch session running."
	if s.Eng.StopCatch(id) {
		msg = "Stopping the drop-catch session."
	}
	redirect(w, r, fmt.Sprintf("/domain/%d", id), msg, "")
}

func (s *Server) domainCatchReset(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	s.St.ResetCatch(id)
	s.St.AddEvent(id, "catch_reset", "info", "catch state reset by "+user(r).Username)
	s.Eng.Wake(id)
	redirect(w, r, fmt.Sprintf("/domain/%d", id), "Catch state reset; the domain will re-arm.", "")
}

func (s *Server) domainPricing(w http.ResponseWriter, r *http.Request) {
	d, err := s.St.GetDomain(pathID(r))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	b, err := s.Eng.Pricing().Get(ctx, d.Suffix, true)
	back := fmt.Sprintf("/domain/%d", d.ID)
	if err != nil {
		redirect(w, r, back, "", "pricing: "+err.Error())
		return
	}
	redirect(w, r, back, fmt.Sprintf("Pricing refreshed from %s: %d registrars sell .%s.", b.Source, len(b.Prices), d.Suffix), "")
}

func (s *Server) domainDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	s.Eng.StopCatch(id)
	s.Eng.Stop(id)
	if err := s.St.DeleteDomain(id); err != nil {
		redirect(w, r, fmt.Sprintf("/domain/%d", id), "", err.Error())
		return
	}
	redirect(w, r, "/", "Domain deleted.", "")
}

// ---- orders / events / sources

func (s *Server) orders(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "orders", page{Title: "Orders", Nav: "orders", Data: s.St.ListOrders(0, 500)})
}

type eventsData struct {
	Events []store.Event
	Page   int
	Pages  int
	Level  string
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pg < 1 {
		pg = 1
	}
	lvl := r.URL.Query().Get("level")
	ev, total := s.St.ListEvents(0, lvl, 100, (pg-1)*100)
	s.render(w, r, "events", page{Title: "Events", Nav: "events", Data: eventsData{Events: ev, Page: pg, Pages: (total + 99) / 100, Level: lvl}})
}

type sourcesData struct {
	Health   []store.SourceHealth
	Sources  []string
	Plans    map[string][]string
	Suffixes []store.SuffixInfo
}

func (s *Server) sources(w http.ResponseWriter, r *http.Request) {
	plans := map[string][]string{}
	for _, sfx := range s.St.Suffixes() {
		plans[sfx] = s.Eng.Monitor().Plan(sfx)
	}
	h := s.St.ListHealth()
	sort.SliceStable(h, func(i, j int) bool { return h[i].Suffix < h[j].Suffix })
	s.render(w, r, "sources", page{Title: "Sources", Nav: "sources", Data: sourcesData{Health: h, Sources: s.Eng.Monitor().SourceNames(), Plans: plans, Suffixes: s.St.ListSuffixInfo()}})
}

func (s *Server) sourcesReset(w http.ResponseWriter, r *http.Request) {
	s.St.ClearHealth(r.FormValue("suffix"), r.FormValue("source"))
	redirect(w, r, "/sources", "Source un-benched for ."+r.FormValue("suffix"), "")
}

// ---- settings

type settingsData struct {
	Groups     []string
	Defs       []settings.Def
	Values     map[string]string
	Env        [][2]string
	Registrars []registrar.Info
	CallOK     bool
	TelegramOK bool
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	d := settingsData{Defs: settings.Defs, Values: map[string]string{}, Registrars: s.Eng.Registrars().Infos(),
		CallOK: s.Eng.Notifier().CallConfigured(), TelegramOK: s.Eng.Notifier().TelegramConfigured()}
	for _, def := range settings.Defs {
		d.Values[def.Key] = settings.Get(s.St, def.Key)
		if !contains(d.Groups, def.Group) {
			d.Groups = append(d.Groups, def.Group)
		}
	}
	set := func(v string) string {
		if v == "" {
			return "—"
		}
		return "(set)"
	}
	e := s.Env
	d.Env = [][2]string{
		{"BASE_URL", e.BaseURL}, {"LISTEN_ADDR", e.Listen}, {"DB_PATH", e.DBPath}, {"TRUST_PROXY", fmt.Sprint(e.TrustProxy)},
		{"SECURE_COOKIES", fmt.Sprint(e.SecureCookies)}, {"WHOIS_URL", e.WhoisURL}, {"WHOIS_PASSWORD", set(e.WhoisPassword)},
		{"ORDERS_DRY_RUN", fmt.Sprint(e.OrdersDryRun)},
		{"REGISTRANT contact", map[bool]string{true: "complete", false: "incomplete"}[e.Contact.Complete()]},
		{"TWILIO_FROM / TO", e.Twilio.From + " → " + strings.Join(e.Twilio.To, ", ")}, {"TWILIO_AUTH_TOKEN", set(e.Twilio.AuthToken)},
		{"TELEGRAM_BOT_TOKEN", set(e.Telegram.BotToken)}, {"TELEGRAM_CHAT_IDS", strings.Join(e.Telegram.ChatIDs, ", ")},
	}
	s.render(w, r, "settings", page{Title: "Settings", Nav: "settings", Data: d})
}

func (s *Server) settingsPost(w http.ResponseWriter, r *http.Request) {
	for _, def := range settings.Defs {
		v := r.FormValue(def.Key)
		if def.Kind != "bool" && !r.Form.Has(def.Key) {
			continue
		}
		nv, err := settings.Validate(def, v)
		if err != nil {
			redirect(w, r, "/settings", "", err.Error())
			return
		}
		if nv == def.Default {
			s.St.DeleteSetting(def.Key)
		} else {
			s.St.SetSetting(def.Key, nv)
		}
	}
	s.ApplySettings()
	redirect(w, r, "/settings", "Settings saved and applied.", "")
}

func (s *Server) testNotify(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	res := s.Eng.TestNotify(ctx, r.FormValue("call") == "1", r.FormValue("telegram") == "1")
	redirect(w, r, "/settings", strings.Join(res, "; "), "")
}

// ---- users / account

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "users", page{Title: "Users", Nav: "users", Data: s.St.ListUsers()})
}

func (s *Server) usersCreate(w http.ResponseWriter, r *http.Request) {
	if _, err := s.St.CreateUser(strings.TrimSpace(r.FormValue("username")), r.FormValue("password")); err != nil {
		redirect(w, r, "/users", "", err.Error())
		return
	}
	redirect(w, r, "/users", "User created.", "")
}

func (s *Server) usersToggle(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if id == user(r).ID {
		redirect(w, r, "/users", "", "you cannot disable yourself")
		return
	}
	u, err := s.St.GetUser(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.St.SetUserActive(id, !u.Active); err != nil {
		redirect(w, r, "/users", "", err.Error())
		return
	}
	redirect(w, r, "/users", "Updated.", "")
}

func (s *Server) usersDelete(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	if id == user(r).ID {
		redirect(w, r, "/users", "", "you cannot delete yourself")
		return
	}
	if err := s.St.DeleteUser(id); err != nil {
		redirect(w, r, "/users", "", err.Error())
		return
	}
	redirect(w, r, "/users", "User deleted.", "")
}

func (s *Server) usersPassword(w http.ResponseWriter, r *http.Request) {
	if err := s.St.SetPassword(pathID(r), r.FormValue("password")); err != nil {
		redirect(w, r, "/users", "", err.Error())
		return
	}
	redirect(w, r, "/users", "Password reset; the user's sessions were signed out.", "")
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "account", page{Title: "Account", Nav: "account"})
}

func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	if !s.St.CheckPassword(u.ID, r.FormValue("current")) {
		redirect(w, r, "/account", "", "current password is incorrect")
		return
	}
	if r.FormValue("password") != r.FormValue("password2") {
		redirect(w, r, "/account", "", "new passwords do not match")
		return
	}
	if err := s.St.SetPassword(u.ID, r.FormValue("password")); err != nil {
		redirect(w, r, "/account", "", err.Error())
		return
	}
	tok, _, _ := s.St.CreateSession(u.ID, 7*24*time.Hour)
	s.setCookie(w, tok, 7*24*3600)
	redirect(w, r, "/account", "Password changed; other sessions were signed out.", "")
}

func (s *Server) help(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "help", page{Title: "Help", Nav: "help"})
}

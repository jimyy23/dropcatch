package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Availability states.
const (
	StatusUnknown       = "unknown"
	StatusRegistered    = "registered"
	StatusAvailable     = "available"
	StatusPendingDelete = "pending_delete"
	StatusRedemption    = "redemption"
	StatusReserved      = "reserved"
)

// Catch states.
const (
	CatchIdle    = "idle"
	CatchActive  = "active"
	CatchWon     = "won"
	CatchLost    = "lost"    // registered by someone else (master monitor)
	CatchExpired = "expired" // duration elapsed without success
	CatchPending = "pending" // a registrar accepted the order asynchronously
)

// Domain is one monitored domain with its settings and last known state.
type Domain struct {
	ID        int64
	Name      string // ASCII
	UName     string // Unicode
	Suffix    string
	Note      string
	CreatedAt time.Time

	MonitorEnabled  bool
	MonitorInterval int // seconds

	CatchEnabled    bool
	CatchInterval   int // seconds, monitor interval while armed
	CatchStart      time.Time
	CatchEnd        time.Time
	CatchDuration   int // minutes of order attempts
	CatchRegistrars []string
	AutoCatchPD     bool

	NotifyCall     bool
	NotifyTelegram bool

	Status       string
	StatusSource string
	StatusSince  time.Time
	CheckedAt    time.Time
	LastError    string
	ErrorStreak  int

	InfoSource    string
	InfoAt        time.Time
	Registrar     string
	Created       time.Time
	Expires       time.Time
	Updated       time.Time
	AvailableDate time.Time
	Statuses      []string
	Nameservers   []string
	PendingDelete bool
	Redemption    bool
	WhoisServer   string
	RawWhois      string

	ConfirmedAvailAt time.Time
	ConfirmTriedAt   time.Time
	ConfirmDetail    string

	CatchState     string
	CatchStartedAt time.Time
	CatchDeadline  time.Time
	CatchEndedAt   time.Time
	CatchAttempts  int
	CatchResult    string
	CatchWonBy     string
}

// InWindow reports whether t is inside the optional catch window.
func (d *Domain) InWindow(t time.Time) bool {
	if !d.CatchStart.IsZero() && t.Before(d.CatchStart) {
		return false
	}
	if !d.CatchEnd.IsZero() && !t.Before(d.CatchEnd) {
		return false
	}
	return true
}

// Armed reports whether the domain is in drop-catch mode: catching enabled
// and inside its window, or auto-catch on pending delete with a pending
// delete status seen. Registrars must be selected either way.
func (d *Domain) Armed(t time.Time) bool {
	if len(d.CatchRegistrars) == 0 {
		return false
	}
	if d.CatchEnabled && d.InWindow(t) {
		return true
	}
	return d.AutoCatchPD && (d.PendingDelete || d.Status == StatusPendingDelete)
}

// ArmReason explains Armed for the UI.
func (d *Domain) ArmReason(t time.Time) string {
	switch {
	case len(d.CatchRegistrars) == 0 && (d.CatchEnabled || d.AutoCatchPD):
		return "no registrar selected"
	case d.CatchEnabled && d.InWindow(t):
		return "catch window"
	case d.AutoCatchPD && (d.PendingDelete || d.Status == StatusPendingDelete):
		return "pending delete (auto)"
	case d.CatchEnabled && !d.CatchStart.IsZero() && t.Before(d.CatchStart):
		return "window not started"
	case d.CatchEnabled && !d.CatchEnd.IsZero() && !t.Before(d.CatchEnd):
		return "window ended"
	}
	return ""
}

const domainCols = `id,name,uname,suffix,note,created_at,monitor_enabled,monitor_interval,
catch_enabled,catch_interval,catch_start,catch_end,catch_duration,catch_registrars,auto_catch_pd,
notify_call,notify_telegram,status,status_source,status_since,checked_at,last_error,error_streak,
info_source,info_at,registrar,created,expires,updated,available_date,statuses,nameservers,pending_delete,redemption,whois_server,raw_whois,
confirmed_avail_at,confirm_tried_at,confirm_detail,
catch_state,catch_started_at,catch_deadline,catch_ended_at,catch_attempts,catch_result,catch_won_by`

func scanDomain(sc interface{ Scan(...any) error }) (*Domain, error) {
	d := &Domain{}
	var ca, cs, ce, ss, chk, ia, cr, ex, up, av, cfa, cft, cst, cdl, cen int64
	var me, cEn, apd, nc, nt, pd, rd int
	var regs, sts, nss string
	err := sc.Scan(&d.ID, &d.Name, &d.UName, &d.Suffix, &d.Note, &ca, &me, &d.MonitorInterval,
		&cEn, &d.CatchInterval, &cs, &ce, &d.CatchDuration, &regs, &apd,
		&nc, &nt, &d.Status, &d.StatusSource, &ss, &chk, &d.LastError, &d.ErrorStreak,
		&d.InfoSource, &ia, &d.Registrar, &cr, &ex, &up, &av, &sts, &nss, &pd, &rd, &d.WhoisServer, &d.RawWhois,
		&cfa, &cft, &d.ConfirmDetail,
		&d.CatchState, &cst, &cdl, &cen, &d.CatchAttempts, &d.CatchResult, &d.CatchWonBy)
	if err != nil {
		return nil, err
	}
	d.CreatedAt, d.CatchStart, d.CatchEnd, d.StatusSince, d.CheckedAt = FromUnix(ca), FromUnix(cs), FromUnix(ce), FromUnix(ss), FromUnix(chk)
	d.InfoAt, d.Created, d.Expires, d.Updated, d.AvailableDate = FromUnix(ia), FromUnix(cr), FromUnix(ex), FromUnix(up), FromUnix(av)
	d.ConfirmedAvailAt, d.ConfirmTriedAt = FromUnix(cfa), FromUnix(cft)
	d.CatchStartedAt, d.CatchDeadline, d.CatchEndedAt = FromUnix(cst), FromUnix(cdl), FromUnix(cen)
	d.MonitorEnabled, d.CatchEnabled, d.AutoCatchPD, d.NotifyCall, d.NotifyTelegram = me == 1, cEn == 1, apd == 1, nc == 1, nt == 1
	d.PendingDelete, d.Redemption = pd == 1, rd == 1
	d.CatchRegistrars, d.Statuses, d.Nameservers = SplitList(regs), splitLines(sts), SplitList(nss)
	return d, nil
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// NewDomain holds the fields set when adding a domain.
type NewDomain struct {
	Name, UName, Suffix, Note string
	MonitorEnabled            bool
	MonitorInterval           int
	CatchInterval             int
	CatchDuration             int
	CatchRegistrars           []string
	AutoCatchPD               bool
	NotifyCall                bool
	NotifyTelegram            bool
}

var ErrExists = errors.New("domain already exists")

func (s *Store) AddDomain(n NewDomain) (int64, error) {
	res, err := s.W.Exec(`INSERT INTO domains(name,uname,suffix,note,created_at,monitor_enabled,monitor_interval,catch_interval,catch_duration,catch_registrars,auto_catch_pd,notify_call,notify_telegram)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, n.Name, n.UName, n.Suffix, n.Note, time.Now().Unix(), b2i(n.MonitorEnabled), n.MonitorInterval,
		n.CatchInterval, n.CatchDuration, JoinList(n.CatchRegistrars), b2i(n.AutoCatchPD), b2i(n.NotifyCall), b2i(n.NotifyTelegram))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrExists
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) GetDomain(id int64) (*Domain, error) {
	return scanDomain(s.R.QueryRow(`SELECT `+domainCols+` FROM domains WHERE id=?`, id))
}

func (s *Store) ListDomains() []*Domain {
	rows, err := s.R.Query(`SELECT ` + domainCols + ` FROM domains ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*Domain
	for rows.Next() {
		if d, err := scanDomain(rows); err == nil {
			out = append(out, d)
		}
	}
	return out
}

func (s *Store) DomainIDs() []int64 {
	rows, err := s.R.Query(`SELECT id FROM domains`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out
}

func (s *Store) DeleteDomain(id int64) error {
	return s.Tx(context.Background(), func(tx *sql.Tx) error {
		for _, q := range []string{`DELETE FROM checks WHERE domain_id=?`, `DELETE FROM orders WHERE domain_id=?`, `DELETE FROM events WHERE domain_id=?`, `DELETE FROM domains WHERE id=?`} {
			if _, err := tx.Exec(q, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// DomainSettings are the per-domain controls editable in the UI.
type DomainSettings struct {
	Note            string
	MonitorEnabled  bool
	MonitorInterval int
	CatchEnabled    bool
	CatchInterval   int
	CatchStart      time.Time
	CatchEnd        time.Time
	CatchDuration   int
	CatchRegistrars []string
	AutoCatchPD     bool
	NotifyCall      bool
	NotifyTelegram  bool
}

func (s *Store) UpdateDomainSettings(id int64, x DomainSettings) error {
	_, err := s.W.Exec(`UPDATE domains SET note=?,monitor_enabled=?,monitor_interval=?,catch_enabled=?,catch_interval=?,catch_start=?,catch_end=?,
		catch_duration=?,catch_registrars=?,auto_catch_pd=?,notify_call=?,notify_telegram=? WHERE id=?`,
		x.Note, b2i(x.MonitorEnabled), x.MonitorInterval, b2i(x.CatchEnabled), x.CatchInterval, Unix(x.CatchStart), Unix(x.CatchEnd),
		x.CatchDuration, JoinList(x.CatchRegistrars), b2i(x.AutoCatchPD), b2i(x.NotifyCall), b2i(x.NotifyTelegram), id)
	return err
}

// SetToggle flips one boolean switch (used by the list page quick toggles).
func (s *Store) SetToggle(id int64, field string, on bool) error {
	col := map[string]string{"monitor": "monitor_enabled", "catch": "catch_enabled", "autopd": "auto_catch_pd", "call": "notify_call", "telegram": "notify_telegram"}[field]
	if col == "" {
		return errors.New("unknown switch")
	}
	_, err := s.W.Exec(`UPDATE domains SET `+col+`=? WHERE id=?`, b2i(on), id)
	return err
}

// Info is registration data reported by the WHOIS/RDAP service.
type Info struct {
	Source        string
	Registrar     string
	Created       time.Time
	Expires       time.Time
	Updated       time.Time
	AvailableDate time.Time
	Statuses      []string
	Nameservers   []string
	PendingDelete bool
	Redemption    bool
	WhoisServer   string
	Raw           string
}

// SaveObservation stores the outcome of a monitor check. status=="" means the
// check failed (only the error and timestamps change). info is optional; when
// the domain is no longer registered the registration data is cleared.
func (s *Store) SaveObservation(id int64, status, source, errMsg string, info *Info) error {
	now := time.Now().Unix()
	return s.Tx(context.Background(), func(tx *sql.Tx) error {
		if status == "" {
			_, err := tx.Exec(`UPDATE domains SET checked_at=?, last_error=?, error_streak=error_streak+1 WHERE id=?`, now, errMsg, id)
			return err
		}
		if _, err := tx.Exec(`UPDATE domains SET status_since=CASE WHEN status<>? THEN ? ELSE status_since END, status=?, status_source=?,
			checked_at=?, last_error='', error_streak=0 WHERE id=?`, status, now, status, source, now, id); err != nil {
			return err
		}
		if info != nil {
			raw := info.Raw
			if len(raw) > 64<<10 {
				raw = raw[:64<<10]
			}
			_, err := tx.Exec(`UPDATE domains SET info_source=?, info_at=?, registrar=?, created=?, expires=?, updated=?, available_date=?, statuses=?,
				nameservers=?, pending_delete=?, redemption=?, whois_server=?, raw_whois=? WHERE id=?`,
				info.Source, now, info.Registrar, Unix(info.Created), Unix(info.Expires), Unix(info.Updated), Unix(info.AvailableDate),
				strings.Join(info.Statuses, "\n"), JoinList(info.Nameservers), b2i(info.PendingDelete), b2i(info.Redemption), info.WhoisServer, raw, id)
			return err
		}
		if status == StatusAvailable {
			_, err := tx.Exec(`UPDATE domains SET pending_delete=0, redemption=0 WHERE id=?`, id)
			return err
		}
		return nil
	})
}

func (s *Store) SetConfirmed(id int64, at time.Time, detail string) {
	s.W.Exec(`UPDATE domains SET confirmed_avail_at=?, confirm_detail=? WHERE id=?`, Unix(at), detail, id)
}

func (s *Store) SetConfirmTried(id int64, detail string) {
	s.W.Exec(`UPDATE domains SET confirm_tried_at=?, confirm_detail=? WHERE id=?`, time.Now().Unix(), detail, id)
}

func (s *Store) StartCatch(id int64, deadline time.Time) {
	s.W.Exec(`UPDATE domains SET catch_state=?, catch_started_at=?, catch_deadline=?, catch_ended_at=0, catch_attempts=0, catch_result='', catch_won_by='' WHERE id=?`,
		CatchActive, time.Now().Unix(), deadline.Unix(), id)
}

func (s *Store) IncCatchAttempts(id int64) {
	s.W.Exec(`UPDATE domains SET catch_attempts=catch_attempts+1 WHERE id=?`, id)
}

func (s *Store) EndCatch(id int64, state, result, wonBy string) {
	s.W.Exec(`UPDATE domains SET catch_state=?, catch_ended_at=?, catch_result=?, catch_won_by=? WHERE id=?`, state, time.Now().Unix(), result, wonBy, id)
}

// ResetCatch re-arms a domain whose catch session ended.
func (s *Store) ResetCatch(id int64) {
	s.W.Exec(`UPDATE domains SET catch_state=?, catch_result='', catch_won_by='' WHERE id=? AND catch_state<>?`, CatchIdle, id, CatchActive)
}

// MarkInterruptedCatches ends sessions left active by a restart.
func (s *Store) MarkInterruptedCatches() {
	s.W.Exec(`UPDATE domains SET catch_state=?, catch_result='interrupted by restart', catch_ended_at=? WHERE catch_state=?`, CatchExpired, time.Now().Unix(), CatchActive)
}

// ---- checks history

type Check struct {
	TS      time.Time
	Purpose string // monitor | confirm | probe
	Source  string
	Result  string
	MS      int64
	Detail  string
}

func (s *Store) AddCheck(domainID int64, c Check) {
	s.W.Exec(`INSERT INTO checks(domain_id,ts,purpose,source,result,ms,detail) VALUES(?,?,?,?,?,?,?)`, domainID, time.Now().Unix(), c.Purpose, c.Source, c.Result, c.MS, c.Detail)
}

func (s *Store) ListChecks(domainID int64, limit int) []Check {
	rows, err := s.R.Query(`SELECT ts,purpose,source,result,ms,detail FROM checks WHERE domain_id=? ORDER BY id DESC LIMIT ?`, domainID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Check
	for rows.Next() {
		var c Check
		var ts int64
		if rows.Scan(&ts, &c.Purpose, &c.Source, &c.Result, &c.MS, &c.Detail) == nil {
			c.TS = FromUnix(ts)
			out = append(out, c)
		}
	}
	return out
}

// ---- orders

type Order struct {
	ID             int64
	DomainID       int64
	SessionStarted time.Time
	TS             time.Time
	Registrar      string
	Attempt        int
	Outcome        string
	MS             int64
	Ref            string
	Message        string
	Name           string // joined
}

func (s *Store) AddOrder(o Order) {
	s.W.Exec(`INSERT INTO orders(domain_id,session_started,ts,registrar,attempt,outcome,ms,ref,message) VALUES(?,?,?,?,?,?,?,?,?)`,
		o.DomainID, Unix(o.SessionStarted), time.Now().Unix(), o.Registrar, o.Attempt, o.Outcome, o.MS, o.Ref, o.Message)
}

func (s *Store) ListOrders(domainID int64, limit int) []Order {
	where, args := "1=1", []any{}
	if domainID > 0 {
		where, args = "o.domain_id=?", append(args, domainID)
	}
	rows, err := s.R.Query(`SELECT o.id,o.domain_id,o.session_started,o.ts,o.registrar,o.attempt,o.outcome,o.ms,o.ref,o.message,COALESCE(d.name,'')
		FROM orders o LEFT JOIN domains d ON d.id=o.domain_id WHERE `+where+` ORDER BY o.id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Order
	for rows.Next() {
		var o Order
		var ss, ts int64
		if rows.Scan(&o.ID, &o.DomainID, &ss, &ts, &o.Registrar, &o.Attempt, &o.Outcome, &o.MS, &o.Ref, &o.Message, &o.Name) == nil {
			o.SessionStarted, o.TS = FromUnix(ss), FromUnix(ts)
			out = append(out, o)
		}
	}
	return out
}

// ---- events

type Event struct {
	ID       int64
	TS       time.Time
	DomainID int64
	Type     string
	Level    string // info | warn | alert
	Detail   string
	Name     string // joined
}

func (s *Store) AddEvent(domainID int64, typ, level, detail string) {
	s.W.Exec(`INSERT INTO events(ts,domain_id,type,level,detail) VALUES(?,?,?,?,?)`, time.Now().Unix(), domainID, typ, level, detail)
}

func (s *Store) ListEvents(domainID int64, level string, limit, offset int) ([]Event, int) {
	where, args := []string{"1=1"}, []any{}
	if domainID > 0 {
		where, args = append(where, "e.domain_id=?"), append(args, domainID)
	}
	if level != "" {
		where, args = append(where, "e.level=?"), append(args, level)
	}
	w := strings.Join(where, " AND ")
	var total int
	s.R.QueryRow(`SELECT COUNT(*) FROM events e WHERE `+w, args...).Scan(&total)
	rows, err := s.R.Query(`SELECT e.id,e.ts,e.domain_id,e.type,e.level,e.detail,COALESCE(d.name,'') FROM events e LEFT JOIN domains d ON d.id=e.domain_id
		WHERE `+w+` ORDER BY e.id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		if rows.Scan(&e.ID, &ts, &e.DomainID, &e.Type, &e.Level, &e.Detail, &e.Name) == nil {
			e.TS = FromUnix(ts)
			out = append(out, e)
		}
	}
	return out, total
}

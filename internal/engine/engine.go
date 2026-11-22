// Package engine runs one independent worker goroutine per domain. A worker
// monitors availability at the domain's own interval and, when the domain is
// armed for drop-catching and becomes available, places orders with all
// selected registrars concurrently until one succeeds, the domain is
// registered by someone else, or the catch duration elapses.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/monitor"
	"dropcatch/internal/notify"
	"dropcatch/internal/pricing"
	"dropcatch/internal/registrar"
	"dropcatch/internal/store"
)

// Config holds global engine parameters (from the Settings page).
type Config struct {
	MinMonitorInterval  time.Duration // floor for normal monitoring
	MinCatchInterval    time.Duration // floor while armed
	OrderGap            time.Duration // spacing between order attempts per registrar
	ConfirmCooldown     time.Duration // re-confirm at most this often for flapping signals
	ErrorBackoffMax     time.Duration
	NotifyOnCatch       bool // also notify on order success / loss
	AllowNoWhoisConfirm bool
	RetentionDays       int
}

// Engine supervises domain workers.
type Engine struct {
	st    *store.Store
	mon   *monitor.Manager
	regs  *registrar.Set
	note  *notify.Notifier
	price *pricing.Service
	log   *slog.Logger

	mu      sync.Mutex
	cfg     Config
	workers map[int64]*worker
	ctx     context.Context
}

type worker struct {
	id     int64
	cancel context.CancelFunc
	wake   chan struct{}

	mu       sync.Mutex
	phase    string
	nextAt   time.Time
	catching bool
}

// WorkerState is shown on the Workers page.
type WorkerState struct {
	ID       int64
	Phase    string
	NextAt   time.Time
	Catching bool
}

func New(st *store.Store, mon *monitor.Manager, regs *registrar.Set, note *notify.Notifier, price *pricing.Service, log *slog.Logger) *Engine {
	return &Engine{st: st, mon: mon, regs: regs, note: note, price: price, log: log, workers: map[int64]*worker{}}
}

func (e *Engine) SetConfig(c Config) {
	e.mu.Lock()
	e.cfg = c
	e.mu.Unlock()
	e.WakeAll()
}

func (e *Engine) config() Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

func (e *Engine) Registrars() *registrar.Set { return e.regs }
func (e *Engine) Notifier() *notify.Notifier { return e.note }
func (e *Engine) Monitor() *monitor.Manager  { return e.mon }
func (e *Engine) Pricing() *pricing.Service  { return e.price }

// Run starts workers for all domains and blocks until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	e.mu.Lock()
	e.ctx = ctx
	e.mu.Unlock()
	e.st.MarkInterruptedCatches()
	for _, id := range e.st.DomainIDs() {
		e.Start(id)
	}
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.st.Prune(e.config().RetentionDays)
		}
	}
}

// Start launches (or restarts) the worker for a domain.
func (e *Engine) Start(id int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx == nil {
		return
	}
	if w, ok := e.workers[id]; ok {
		select {
		case w.wake <- struct{}{}:
		default:
		}
		return
	}
	ctx, cancel := context.WithCancel(e.ctx)
	w := &worker{id: id, cancel: cancel, wake: make(chan struct{}, 1), phase: "starting"}
	e.workers[id] = w
	go func() {
		defer func() {
			if r := recover(); r != nil {
				e.log.Error("worker panic", "domain", id, "panic", r)
				e.st.AddEvent(id, "worker_crash", "warn", fmt.Sprint(r))
			}
			e.mu.Lock()
			if e.workers[id] == w {
				delete(e.workers, id)
			}
			e.mu.Unlock()
			// restart after a crash unless stopping or deleted
			if ctx.Err() == nil {
				time.Sleep(5 * time.Second)
				if _, err := e.st.GetDomain(id); err == nil {
					e.Start(id)
				}
			}
		}()
		e.loop(ctx, w)
	}()
}

// Stop ends the worker (domain deleted).
func (e *Engine) Stop(id int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if w, ok := e.workers[id]; ok {
		w.cancel()
		delete(e.workers, id)
	}
}

// Wake makes a worker re-read its settings and check now.
func (e *Engine) Wake(id int64) {
	e.mu.Lock()
	w, ok := e.workers[id]
	e.mu.Unlock()
	if !ok {
		e.Start(id)
		return
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (e *Engine) WakeAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, w := range e.workers {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

// States reports worker states for the UI.
func (e *Engine) States() map[int64]WorkerState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[int64]WorkerState{}
	for id, w := range e.workers {
		w.mu.Lock()
		out[id] = WorkerState{ID: id, Phase: w.phase, NextAt: w.nextAt, Catching: w.catching}
		w.mu.Unlock()
	}
	return out
}

func (w *worker) set(phase string, next time.Time) {
	w.mu.Lock()
	w.phase, w.nextAt = phase, next
	w.mu.Unlock()
}

// loop is the per-domain worker.
func (e *Engine) loop(ctx context.Context, w *worker) {
	immediate := true
	for {
		d, err := e.st.GetDomain(w.id)
		if err != nil {
			return // deleted
		}
		now := time.Now()
		cfg := e.config()
		armed := d.Armed(now) && d.CatchState != store.CatchWon
		interval := time.Duration(d.MonitorInterval) * time.Second
		if interval < cfg.MinMonitorInterval {
			interval = cfg.MinMonitorInterval
		}
		if armed {
			ci := time.Duration(d.CatchInterval) * time.Second
			if ci < cfg.MinCatchInterval {
				ci = cfg.MinCatchInterval
			}
			if ci < interval {
				interval = ci
			}
		}
		active := d.MonitorEnabled || armed
		if !active {
			w.set("paused", time.Time{})
			if !e.sleep(ctx, w, time.Hour) {
				return
			}
			immediate = true
			continue
		}
		due := d.CheckedAt.Add(interval)
		if d.ErrorStreak > 0 {
			// back off on repeated failures (all sources failing)
			b := interval * time.Duration(1<<min(d.ErrorStreak, 5))
			if b > cfg.ErrorBackoffMax && cfg.ErrorBackoffMax > 0 {
				b = cfg.ErrorBackoffMax
			}
			if b < interval {
				b = interval
			}
			due = d.CheckedAt.Add(b)
		}
		if !immediate && now.Before(due) {
			wait := time.Until(due)
			// re-evaluate when a catch window opens
			if d.CatchEnabled && !d.CatchStart.IsZero() && now.Before(d.CatchStart) && time.Until(d.CatchStart) < wait {
				wait = time.Until(d.CatchStart)
			}
			phase := "monitoring"
			if armed {
				phase = "armed"
			}
			w.set(phase, due)
			if !e.sleep(ctx, w, wait) {
				return
			}
			immediate = false
			continue
		}
		immediate = false
		w.set("checking", time.Time{})
		e.checkOnce(ctx, w, d, armed)
		if ctx.Err() != nil {
			return
		}
	}
}

// keepSpecific stops a fallback that can only say "not registrable" (no
// registration data) from erasing a more specific lifecycle state seen in
// WHOIS: a pending-delete or redemption domain is still not registrable.
func keepSpecific(prev string, o monitor.Observation) string {
	if o.Info == nil && o.Status == store.StatusRegistered && (prev == store.StatusPendingDelete || prev == store.StatusRedemption) {
		return prev
	}
	return o.Status
}

func (e *Engine) sleep(ctx context.Context, w *worker, d time.Duration) bool {
	if d < 0 {
		d = 0
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-w.wake:
		return true
	case <-t.C:
		return true
	}
}

// RegisterNow starts an admin-initiated register session for a domain: every
// selected, configured registrar receives orders immediately, without an
// availability check, for the domain's order duration. It runs in its own
// goroutine; the domain's worker keeps monitoring.
func (e *Engine) RegisterNow(id int64, by string) error {
	d, err := e.st.GetDomain(id)
	if err != nil {
		return err
	}
	if d.CatchState == store.CatchActive {
		return fmt.Errorf("a drop-catch session is already running for %s", d.UName)
	}
	if len(d.CatchRegistrars) == 0 {
		return fmt.Errorf("select at least one registrar for %s first", d.UName)
	}
	name, err := domainutil.Parse(d.Name)
	if err != nil {
		return err
	}
	e.mu.Lock()
	ctx := e.ctx
	e.mu.Unlock()
	if ctx == nil {
		return fmt.Errorf("engine not running")
	}
	if _, busy := manualSessions.LoadOrStore(id, struct{}{}); busy {
		return fmt.Errorf("a manual register is already starting for %s", d.UName)
	}
	w := &worker{id: id, wake: make(chan struct{}, 1)}
	go func() {
		defer manualSessions.Delete(id)
		e.runSession(ctx, w, d, name, monitor.Observation{Source: "manual", Status: "manual"}, true, by)
	}()
	return nil
}

var manualSessions sync.Map

// CheckNow runs a manual check from the UI (via the worker).
func (e *Engine) CheckNow(id int64) {
	e.st.W.Exec(`UPDATE domains SET checked_at=0 WHERE id=?`, id)
	e.Wake(id)
}

func (e *Engine) checkOnce(ctx context.Context, w *worker, d *store.Domain, armed bool) {
	name, err := domainutil.Parse(d.Name)
	if err != nil {
		e.st.SaveObservation(d.ID, "", "", err.Error(), nil)
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	res := e.mon.Check(cctx, name, armed)
	cancel()
	for _, a := range res.Attempts {
		c := store.Check{Purpose: "monitor", Source: a.Source, MS: a.Elapsed.Milliseconds(), Detail: a.Detail}
		if a.Err != nil {
			c.Result, c.Detail = "error", monitor.KindOf(a.Err).String()+": "+a.Err.Error()
		} else {
			c.Result = a.Status
		}
		e.st.AddCheck(d.ID, c)
	}
	o := res.Obs
	if o.Err != nil {
		e.st.SaveObservation(d.ID, "", "", o.Err.Error(), nil)
		if d.ErrorStreak+1 == 3 {
			e.st.AddEvent(d.ID, "monitor_failing", "warn", "all sources failing: "+o.Err.Error())
		}
		return
	}
	prev := d.Status
	o.Status = keepSpecific(prev, o)
	e.st.SaveObservation(d.ID, o.Status, o.Source, "", o.Info)
	if prev != o.Status {
		lvl := "info"
		if o.Status == store.StatusAvailable || o.Status == store.StatusPendingDelete {
			lvl = "alert"
		}
		e.st.AddEvent(d.ID, "status_change", lvl, fmt.Sprintf("%s → %s (via %s)", prev, o.Status, o.Source))
	}
	if o.Status == store.StatusPendingDelete && prev != store.StatusPendingDelete && d.AutoCatchPD {
		e.st.AddEvent(d.ID, "auto_catch_armed", "alert", "pending delete seen: drop-catch armed automatically")
	}
	if o.Info != nil && !d.Expires.IsZero() && !o.Info.Expires.IsZero() && !o.Info.Expires.Equal(d.Expires) {
		e.st.AddEvent(d.ID, "expiry_change", "info", fmt.Sprintf("%s → %s", d.Expires.Format("2006-01-02"), o.Info.Expires.Format("2006-01-02")))
	}

	d2, err := e.st.GetDomain(d.ID)
	if err != nil {
		return
	}
	armed = d2.Armed(time.Now()) && d2.CatchState != store.CatchWon

	if o.Status == store.StatusAvailable {
		// Human notification needs a cross-check; it runs alongside the catch.
		go e.maybeConfirm(ctx, w, d2, name, o)
		// Fast path: orders start on the first available signal, without
		// waiting for confirmation. A session that ended (lost / expired) is
		// only re-entered for a NEW availability episode (the domain was seen
		// not available in between); a pending order is never re-ordered
		// automatically. "reset & re-arm" in the UI overrides both.
		if armed {
			switch d2.CatchState {
			case store.CatchIdle:
				e.runCatch(ctx, w, d2, name, o)
			case store.CatchLost, store.CatchExpired:
				if prev != store.StatusAvailable {
					e.runCatch(ctx, w, d2, name, o)
				}
			}
		}
	} else if !d2.ConfirmedAvailAt.IsZero() {
		// availability episode over: the next one notifies again
		e.st.SetConfirmed(d.ID, time.Time{}, "")
	}
}

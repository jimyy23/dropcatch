package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/monitor"
	"dropcatch/internal/registrar"
	"dropcatch/internal/store"
)

// catchSessions lets the UI stop a running session.
var catchSessions sync.Map // domain id -> context.CancelCauseFunc

// StopCatch cancels a running drop-catch session.
func (e *Engine) StopCatch(id int64) bool {
	if v, ok := catchSessions.Load(id); ok {
		v.(context.CancelCauseFunc)(errStopped)
		return true
	}
	return false
}

var (
	errStopped     = fmt.Errorf("stopped by admin")
	errWon         = fmt.Errorf("won")
	errLost        = fmt.Errorf("registered by someone else")
	errDisarmed    = fmt.Errorf("drop-catch disarmed")
	errNoRegistrar = fmt.Errorf("no registrar left")
)

// runCatch places orders at every selected registrar concurrently until one
// succeeds, the master monitor shows the domain registered (by someone else),
// the session duration (or catch window) ends, or the admin stops it. It runs
// on the domain's own worker, so other domains are unaffected.
func (e *Engine) runCatch(parent context.Context, w *worker, d *store.Domain, name domainutil.Name, trigger monitor.Observation) {
	e.runSession(parent, w, d, name, trigger, false, "")
}

// runSession is the shared order loop. manual=true is an admin-initiated
// "register now": no availability check, no catch-window limit, and the
// master monitor does not end it (the admin asked to try regardless); it
// still ends on success, pending, all registrars failing, the duration, or
// stop.
func (e *Engine) runSession(parent context.Context, w *worker, d *store.Domain, name domainutil.Name, trigger monitor.Observation, manual bool, by string) {
	deadline := time.Now().Add(time.Duration(d.CatchDuration) * time.Minute)
	if !manual && d.CatchEnabled && !d.CatchEnd.IsZero() && d.CatchEnd.Before(deadline) && !(d.AutoCatchPD && d.PendingDelete) {
		deadline = d.CatchEnd
	}
	mode := ""
	if manual {
		mode = "manual register by " + by
	}
	e.runSessionUntil(parent, w, d, name, trigger, mode, deadline)
}

// runSessionUntil is the order loop. mode "" is a monitor-triggered
// drop-catch; "manual register" and "scheduled fire" are blind sessions: no
// availability check, and the master monitor does not end them.
func (e *Engine) runSessionUntil(parent context.Context, w *worker, d *store.Domain, name domainutil.Name, trigger monitor.Observation, mode string, deadline time.Time) {
	cfg := e.config()
	start := time.Now()
	manual := mode != ""
	var regs []registrar.Registrar
	var skipped []string
	for _, k := range d.CatchRegistrars {
		r := e.regs.Get(k)
		switch {
		case r == nil:
			skipped = append(skipped, k+" (unknown)")
		case !r.Configured():
			skipped = append(skipped, r.Label()+" (no API credentials)")
		case r.Problem() != "":
			skipped = append(skipped, r.Label()+" ("+r.Problem()+")")
		default:
			regs = append(regs, r)
		}
	}
	if len(regs) == 0 {
		why := "domain available but no usable registrar: "
		if manual {
			why = mode + ": no usable registrar: "
		}
		e.st.AddEvent(d.ID, "catch_skipped", "warn", why+strings.Join(skipped, ", "))
		return
	}
	e.st.StartCatch(d.ID, deadline)
	msg := fmt.Sprintf("drop-catch started on %s signal from %s; registrars: %s; until %s UTC", trigger.Status, trigger.Source, labels(regs), deadline.UTC().Format("2006-01-02 15:04:05"))
	if manual {
		msg = fmt.Sprintf("%s started (no availability check); registrars: %s; until %s UTC", mode, labels(regs), deadline.UTC().Format("2006-01-02 15:04:05"))
	}
	if len(skipped) > 0 {
		msg += "; skipped: " + strings.Join(skipped, ", ")
	}
	e.st.AddEvent(d.ID, "catch_started", "alert", msg)
	e.log.Info("drop-catch started", "domain", d.Name, "registrars", labels(regs))

	ctx, cancel := context.WithDeadlineCause(parent, deadline, context.DeadlineExceeded)
	defer cancel()
	cctx, ccancel := context.WithCancelCause(ctx)
	defer ccancel(nil)
	catchSessions.Store(d.ID, ccancel)
	defer catchSessions.Delete(d.ID)
	w.mu.Lock()
	w.catching, w.phase, w.nextAt = true, "catching", deadline
	w.mu.Unlock()
	defer func() {
		w.mu.Lock()
		w.catching = false
		w.mu.Unlock()
	}()

	var (
		mu       sync.Mutex
		winner   string
		winRef   string
		pending  []string
		dryRuns  []string
		attempts atomic.Int64
	)
	var wg sync.WaitGroup
	for _, r := range regs {
		wg.Add(1)
		go func(r registrar.Registrar) {
			defer wg.Done()
			gap := r.MinGap()
			if cfg.OrderGap > gap {
				gap = cfg.OrderGap
			}
			for n := 1; cctx.Err() == nil; n++ {
				t0 := time.Now()
				actx, acancel := context.WithTimeout(cctx, 90*time.Second)
				res := r.Register(actx, name.ASCII)
				acancel()
				if cctx.Err() != nil && res.Outcome != registrar.Success && res.Outcome != registrar.Pending {
					return // session ended while this request was in flight
				}
				attempts.Add(1)
				e.st.IncCatchAttempts(d.ID)
				m := res.Message
				if res.Price != "" {
					m += " [" + res.Price + "]"
				}
				e.st.AddOrder(store.Order{DomainID: d.ID, SessionStarted: start, Registrar: r.Key(), Attempt: n, Outcome: string(res.Outcome), MS: time.Since(t0).Milliseconds(), Ref: res.Ref, Message: m})
				switch res.Outcome {
				case registrar.Success:
					mu.Lock()
					if winner == "" {
						winner, winRef = r.Key(), res.Ref
					}
					mu.Unlock()
					ccancel(errWon)
					return
				case registrar.Pending:
					mu.Lock()
					pending = append(pending, r.Label()+" "+res.Ref)
					mu.Unlock()
					e.st.AddEvent(d.ID, "order_pending", "alert", fmt.Sprintf("%s accepted the order asynchronously (%s): %s", r.Label(), res.Ref, res.Message))
					return // never re-order where an order is in flight
				case registrar.DryRun:
					mu.Lock()
					dryRuns = append(dryRuns, r.Label())
					mu.Unlock()
					return
				case registrar.Fatal:
					e.st.AddEvent(d.ID, "registrar_dropped", "warn", r.Label()+": "+res.Message)
					return
				case registrar.RateLimited:
					wait := res.RetryAfter
					if wait <= 0 {
						wait = 10 * time.Second
					}
					if !sleepCtx(cctx, wait) {
						return
					}
					continue
				}
				// Unavailable / Retryable: keep trying at the registrar's pace
				if !sleepCtx(cctx, gap-time.Since(t0)) {
					return
				}
			}
		}(r)
	}

	// When every registrar loop has ended (won, pending, dry run or all
	// dropped as fatal), stop the session instead of idling to the deadline.
	go func() {
		wg.Wait()
		ccancel(errNoRegistrar)
	}()

	// Master monitor: stop when the domain is registered by someone else.
	// Two consecutive "registered" answers are required because registries
	// flap; one of our own orders succeeding is handled above (won).
	// Manual sessions skip it: the admin asked to order regardless.
	monDone := make(chan struct{})
	go func() {
		defer close(monDone)
		if mode == "scheduled fire" {
			e.fireWatch(cctx, ccancel, w, d)
			return
		}
		if manual {
			<-cctx.Done()
			return
		}
		interval := time.Duration(d.CatchInterval) * time.Second
		if interval < cfg.MinCatchInterval {
			interval = cfg.MinCatchInterval
		}
		regSeen := 0
		for sleepCtx(cctx, interval) {
			cur, err := e.st.GetDomain(d.ID)
			if err != nil {
				ccancel(errStopped)
				return
			}
			if !cur.Armed(time.Now()) {
				ccancel(errDisarmed)
				return
			}
			mctx, mcancel := context.WithTimeout(cctx, time.Minute)
			res := e.mon.Check(mctx, name, true)
			mcancel()
			if cctx.Err() != nil {
				return
			}
			for _, a := range res.Attempts {
				c := store.Check{Purpose: "catch", Source: a.Source, MS: a.Elapsed.Milliseconds(), Detail: a.Detail, Result: a.Status}
				if a.Err != nil {
					c.Result, c.Detail = "error", a.Err.Error()
					e.logPoll(d.ID, "catch", a, "error")
				}
				e.st.AddCheck(d.ID, c)
			}
			o := res.Obs
			if o.Err != nil {
				continue
			}
			prev, err := e.st.GetDomain(d.ID)
			if err != nil {
				continue
			}
			// the guard keeps old copies from ending the session; the
			// status in force (not the raw answer) decides
			o.Status = e.observe(prev, o, "catch").Status
			if o.Status == store.StatusAvailable {
				// keep cross-checking while ordering (notification); it
				// rate-limits itself by the confirm retry interval
				if cur, err := e.st.GetDomain(d.ID); err == nil && cur.ConfirmedAvailAt.IsZero() {
					go e.maybeConfirm(parent, w, cur, name, o)
				}
			}
			if o.Status == store.StatusAvailable || o.Status == store.StatusPendingDelete || o.Status == store.StatusRedemption {
				regSeen = 0
				continue
			}
			regSeen++
			if regSeen >= 2 {
				// give in-flight orders a moment: a "registered" may be our own success
				sleepCtx(cctx, 3*time.Second)
				ccancel(errLost)
				return
			}
		}
	}()
	wg.Wait()
	<-monDone

	cause := context.Cause(cctx)
	state, result, level := store.CatchExpired, "", "warn"
	switch {
	case winner != "":
		state, level = store.CatchWon, "alert"
		result = fmt.Sprintf("registered via %s (ref %s) after %d attempts", e.label(winner), winRef, attempts.Load())
	case len(pending) > 0:
		state, level = store.CatchPending, "alert"
		result = "order pending at " + strings.Join(pending, ", ")
	case cause == errLost:
		state, result = store.CatchLost, fmt.Sprintf("domain registered by someone else (master monitor) after %d attempts", attempts.Load())
	case cause == errStopped:
		result = "stopped by admin"
	case cause == errDisarmed:
		result = "drop-catch disabled or window ended"
	case len(dryRuns) > 0 && len(dryRuns) == len(regs):
		result = "dry run only (ORDERS_DRY_RUN=true): " + strings.Join(dryRuns, ", ")
	case cause == errNoRegistrar:
		result = fmt.Sprintf("every registrar failed permanently after %d attempts (see registrar_dropped events)", attempts.Load())
	default:
		result = fmt.Sprintf("duration elapsed without success (%d attempts)", attempts.Load())
	}
	if manual {
		result = mode + ": " + result
	}
	e.st.EndCatch(d.ID, state, result, winner)
	e.st.AddEvent(d.ID, "catch_"+state, level, result)
	e.log.Info("drop-catch ended", "domain", d.Name, "state", state, "result", result)
	if cfg.NotifyOnCatch && (state == store.CatchWon || state == store.CatchPending || state == store.CatchLost) {
		cur, _ := e.st.GetDomain(d.ID)
		if cur != nil {
			e.notifyDomain(context.Background(), cur, fmt.Sprintf("Drop-catch %s for %s: %s", state, d.UName, result), state == store.CatchWon)
		}
	}
	if state == store.CatchWon || state == store.CatchPending {
		// re-check soon so the dashboard shows the new registration
		e.st.W.Exec(`UPDATE domains SET checked_at=? WHERE id=?`, time.Now().Add(-time.Duration(d.MonitorInterval)*time.Second).Add(2*time.Minute).Unix(), d.ID)
	}
}

func (e *Engine) label(key string) string {
	if r := e.regs.Get(key); r != nil {
		return r.Label()
	}
	return key
}

func labels(rs []registrar.Registrar) string {
	var p []string
	for _, r := range rs {
		p = append(p, r.Label())
	}
	return strings.Join(p, ", ")
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ---- confirmation & human notification

var confirming sync.Map // domain id -> struct{}

// maybeConfirm cross-checks an "available" signal and notifies the admin
// once per availability episode when confirmed:
// WHOIS available AND (Cloudean OR Regery OR a registrar API supporting the
// suffix says available).
func (e *Engine) maybeConfirm(ctx context.Context, w *worker, d *store.Domain, name domainutil.Name, trigger monitor.Observation) {
	if !d.ConfirmedAvailAt.IsZero() {
		return
	}
	if _, busy := confirming.LoadOrStore(d.ID, struct{}{}); busy {
		return
	}
	defer confirming.Delete(d.ID)
	cfg := e.config()
	if !d.ConfirmTriedAt.IsZero() && time.Since(d.ConfirmTriedAt) < confirmRetry(cfg, d) {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	c := e.mon.Confirm(cctx, name, &trigger, cfg.AllowNoWhoisConfirm, cfg.RegistrarConfirm)
	for i, o := range c.Observations {
		if c.FromTrigger[i] {
			continue // the trigger is already in the history
		}
		ch := store.Check{Purpose: "confirm", Source: o.Source, MS: o.Elapsed.Milliseconds(), Detail: o.Detail, Result: o.Status}
		if o.Err != nil {
			ch.Result, ch.Detail = "error", o.Err.Error()
		}
		e.st.AddCheck(d.ID, ch)
	}
	summary := c.Summary()
	if !c.Confirmed {
		// one event per episode; the retries go to the check history
		if d.ConfirmTriedAt.IsZero() || d.ConfirmTriedAt.Before(d.StatusSince) {
			e.st.AddEvent(d.ID, "unconfirmed", "info", fmt.Sprintf("available signal not confirmed yet (retrying every %s): %s", confirmRetry(cfg, d), summary))
		}
		e.st.SetConfirmTried(d.ID, summary)
		return
	}
	e.st.SetConfirmed(d.ID, time.Now(), summary)
	first := trigger.Start
	if first.IsZero() {
		first = time.Now()
	}
	how := ""
	if c.ByRegistrars {
		how = " (registrar checks agree; WHOIS still shows the deletion cycle)"
	}
	e.st.AddEvent(d.ID, "confirmed_available", "alert", fmt.Sprintf("availability confirmed%s %s after the first signal: %s",
		how, time.Since(first).Round(time.Second), summary))
	cur, err := e.st.GetDomain(d.ID)
	if err != nil {
		return
	}
	catch := "drop-catch is OFF"
	if cur.Armed(time.Now()) {
		catch = "drop-catch is running with " + strings.Join(cur.CatchRegistrars, ", ")
	} else if cfg.StopWhenConfirmed && cur.MonitorEnabled && cur.CatchState != store.CatchActive {
		// nothing left to watch: an idle monitor on a free name only adds
		// load and stray errors
		e.st.SetToggle(cur.ID, "monitor", false)
		e.st.AddEvent(cur.ID, "monitor_stopped", "info", "monitoring switched off: availability confirmed and drop-catch is not armed")
		catch += "; monitoring stopped"
	}
	e.notifyDomain(context.Background(), cur, fmt.Sprintf("Domain %s is now AVAILABLE (confirmed by %s). %s.", cur.UName, summary, catch), true)
}

// confirmRetry is how soon an unconfirmed availability signal is
// cross-checked again: ConfirmRetry (default 45 s) while the domain is in
// drop-catch or within a day of the signal, else the long cooldown.
func confirmRetry(cfg Config, d *store.Domain) time.Duration {
	r := cfg.ConfirmRetry
	if r <= 0 {
		r = 45 * time.Second
	}
	if d.Armed(time.Now()) || time.Since(d.StatusSince) < 24*time.Hour || d.CandStatus == store.StatusAvailable {
		return r
	}
	return max(r, cfg.ConfirmCooldown)
}

// notifyDomain sends through the channels enabled for the domain.
func (e *Engine) notifyDomain(ctx context.Context, d *store.Domain, msg string, call bool) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if d.NotifyTelegram {
		if err := e.note.Telegram(ctx, msg); err != nil {
			e.st.AddEvent(d.ID, "notify_failed", "warn", "telegram: "+err.Error())
		} else {
			e.st.AddEvent(d.ID, "notified", "info", "telegram: "+msg)
		}
	}
	if d.NotifyCall && call {
		// spell out the domain for text-to-speech: "example dot com"
		spoken := strings.ReplaceAll(msg, d.UName, strings.ReplaceAll(d.UName, ".", " dot "))
		if err := e.note.Call(ctx, spoken); err != nil {
			e.st.AddEvent(d.ID, "notify_failed", "warn", "twilio: "+err.Error())
		} else {
			e.st.AddEvent(d.ID, "notified", "info", "twilio call placed")
		}
	}
}

// TestNotify sends a test message through both channels (Settings page).
func (e *Engine) TestNotify(ctx context.Context, call, telegram bool) []string {
	var out []string
	if telegram {
		if err := e.note.Telegram(ctx, "Dropcatch test message"); err != nil {
			out = append(out, "telegram: "+err.Error())
		} else {
			out = append(out, "telegram: sent")
		}
	}
	if call {
		if err := e.note.Call(ctx, "This is a drop catch test call."); err != nil {
			out = append(out, "twilio: "+err.Error())
		} else {
			out = append(out, "twilio: call placed")
		}
	}
	return out
}

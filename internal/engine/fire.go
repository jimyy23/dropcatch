package engine

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/monitor"
	"dropcatch/internal/store"
)

// fireDue returns when a scheduled fire session should start (FireAt minus
// the lead time) and whether one is pending: drop-catch armed for the
// domain, a fire time set, not executed yet, and not more than the fire
// duration in the past.
func (e *Engine) fireDue(d *store.Domain, now time.Time) (time.Time, bool) {
	if d.FireAt.IsZero() || !d.FireDoneAt.IsZero() && d.FireDoneAt.Equal(d.FireAt) {
		return time.Time{}, false
	}
	if len(d.CatchRegistrars) == 0 || !(d.CatchEnabled || d.AutoCatchPD) || d.CatchState == store.CatchWon || d.CatchState == store.CatchActive {
		return time.Time{}, false
	}
	if r, ok := RuleFor(d.Suffix); ok && r.NoBlindFire && d.FireAuto {
		return time.Time{}, false // computed release window: watched, not fired blind
	}
	start := d.FireAt.Add(-time.Duration(d.FireLead) * time.Second)
	end := d.FireAt.Add(time.Duration(max(d.FireDuration, 1)) * time.Minute)
	if now.After(end) {
		return time.Time{}, false
	}
	return start, true
}

// fireWait is how long a worker may sleep before it must wake for a fire.
// It wakes slightly early and then sleeps precisely (see fire).
func fireWait(start time.Time, max time.Duration) time.Duration {
	w := time.Until(start) - 3*time.Second
	if w < 0 {
		w = 0
	}
	if w > max {
		w = max
	}
	return w
}

// fire runs a scheduled blind registration session: orders go to every
// selected registrar from FireAt-FireLead until FireAt+FireDuration,
// without waiting for (or being stopped by) the monitor.
func (e *Engine) fire(ctx context.Context, w *worker, d *store.Domain) {
	start := d.FireAt.Add(-time.Duration(d.FireLead) * time.Second)
	if !sleepCtx(ctx, time.Until(start)) {
		return
	}
	cur, err := e.st.GetDomain(d.ID)
	if err != nil || !cur.FireAt.Equal(d.FireAt) {
		return // deleted or rescheduled meanwhile
	}
	name, err := domainutil.Parse(cur.Name)
	if err != nil {
		e.st.AddEvent(cur.ID, "fire_skipped", "warn", err.Error())
		e.st.MarkFired(cur.ID, cur.FireAt)
		return
	}
	e.st.MarkFired(cur.ID, cur.FireAt)
	// The session lasts until FireAt+FireDuration regardless of when it starts.
	end := cur.FireAt.Add(time.Duration(max(cur.FireDuration, 1)) * time.Minute)
	sess := *cur
	sess.CatchDuration = int(time.Until(end).Round(time.Minute) / time.Minute)
	if sess.CatchDuration < 1 {
		sess.CatchDuration = 1
	}
	e.st.AddEvent(cur.ID, "fire", "alert", fmt.Sprintf("scheduled fire at registry release %s UTC: ordering until %s UTC",
		cur.FireAt.UTC().Format("2006-01-02 15:04:05"), end.UTC().Format("15:04:05")))
	e.runSessionUntil(ctx, w, &sess, name, monitor.Observation{Source: "schedule", Status: "release time"}, "scheduled fire", end)
}

// RefreshFireAt recomputes an automatic fire time from the suffix release
// rule and the stored registry data. It returns the new value.
func (e *Engine) RefreshFireAt(d *store.Domain) time.Time {
	if !d.FireAuto {
		return d.FireAt
	}
	rule, ok := RuleFor(d.Suffix)
	if !ok {
		return d.FireAt
	}
	in := e.ReleaseInput(d)
	at, err := ExpectedRelease(in)
	if err != nil {
		// keep a past fire time (history) but drop a future one that no
		// longer applies, e.g. the domain was renewed or re-registered
		if !d.FireAt.IsZero() && d.FireAt.After(time.Now()) && (d.Status == store.StatusRegistered || d.Status == store.StatusAvailable) {
			e.st.SetFireAt(d.ID, time.Time{})
			return time.Time{}
		}
		return d.FireAt
	}
	if !at.Equal(d.FireAt) {
		e.st.SetFireAt(d.ID, at)
		src := rule.Name + " rule"
		if !in.Listed.IsZero() {
			src += ", from CIRA's published TBR list"
		}
		e.st.AddEvent(d.ID, "release_time", "info", fmt.Sprintf("expected registry release %s UTC (%s)",
			at.UTC().Format("2006-01-02 15:04:05"), src))
	}
	return at
}

// watchWindow returns the intensified polling around the expected release
// (FireAt): its start, whether it is active now, and the poll interval.
// Watching ends early once a registration after the release is known.
func (e *Engine) watchWindow(d *store.Domain, now time.Time) (time.Time, bool, time.Duration) {
	if d.FireAt.IsZero() {
		return time.Time{}, false, 0
	}
	from, to, every := DefaultWatch(d.FireAt, now)
	if r, ok := RuleFor(d.Suffix); ok {
		from, to, every = r.WatchWindow(d.FireAt, now)
	}
	if now.After(to) {
		return time.Time{}, false, 0
	}
	if d.Status == store.StatusRegistered && !d.Created.IsZero() && !d.Created.Before(d.FireAt.Add(-time.Hour)) {
		return time.Time{}, false, 0 // already re-registered
	}
	return from, !now.Before(from), every
}

// watchCheck is one tick of the release watch. For .tw it asks the registry
// directly: port-43 WHOIS whenever TWNIC's per-IP budget allows (one query
// per ~6 s, shared by all .tw domains), otherwise the live DNS zone
// (delegation = registered), plus RDAP every 30 s. Other suffixes use the
// normal source plan.
func (e *Engine) watchCheck(ctx context.Context, w *worker, d *store.Domain, armed bool) {
	if r, ok := RuleFor(d.Suffix); ok && r.WatchFast {
		e.watchFast(ctx, w, d, armed)
		return
	}
	tw := e.mon.TWNIC()
	if !monitor.IsTW(d.Suffix) || tw == nil {
		e.checkOnce(ctx, w, d, armed)
		return
	}
	name, err := domainutil.Parse(d.Name)
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var obs []monitor.Observation
	if o, ok := tw.TryPort43(cctx, name.ASCII); ok {
		obs = append(obs, o)
	} else {
		obs = append(obs, tw.DNS(cctx, name.ASCII))
		if tw.RDAPDue(name.ASCII, 30*time.Second) {
			obs = append(obs, tw.RDAP(cctx, name.ASCII))
		}
	}
	for _, o := range obs {
		if o.Err != nil {
			e.logPoll(d.ID, "watch", o, "error")
			continue
		}
		cur, err := e.st.GetDomain(d.ID)
		if err != nil {
			return
		}
		e.apply(ctx, w, cur, name, o, cur.Armed(time.Now()) && cur.CatchState != store.CatchWon, "watch")
	}
	e.st.Touch(d.ID)
}

// fireWatch keeps watching the registry during a scheduled fire, so the
// release and a registration are logged with their times. It ends the
// session when someone else's registration after the release is committed.
func (e *Engine) fireWatch(ctx context.Context, cancel context.CancelCauseFunc, w *worker, d *store.Domain) {
	for ctx.Err() == nil {
		cur, err := e.st.GetDomain(d.ID)
		if err != nil {
			return
		}
		_, watching, every := e.watchWindow(cur, time.Now())
		if !watching {
			every = 10 * time.Second
		} else {
			e.watchCheck(ctx, w, cur, true)
		}
		if cur, err = e.st.GetDomain(d.ID); err == nil && cur.Status == store.StatusRegistered && !cur.Created.IsZero() &&
			!cur.Created.Before(cur.FireAt.Add(-time.Minute)) {
			sleepCtx(ctx, 3*time.Second) // our own order may have won meanwhile
			cancel(errLost)
			return
		}
		if !sleepCtx(ctx, every) {
			return
		}
	}
}

var (
	watchMu     sync.Mutex
	watchWhois  = map[int64]time.Time{} // last WHOIS ask per domain in a fast watch
	watchRotate = map[int64]int{}
)

// watchFast is one tick of a release window without a fixed time (.lu):
// one fast independent checker per tick (rotating over the web checkers
// and registrar APIs, which saw .lu drops 15-32 min before WHOIS), plus
// the normal WHOIS-first check at most every 90 s (registry rate limits).
// Orders start on the first plausible "available" from any of them.
func (e *Engine) watchFast(ctx context.Context, w *worker, d *store.Domain, armed bool) {
	name, err := domainutil.Parse(d.Name)
	if err != nil {
		return
	}
	watchMu.Lock()
	whoisDue := time.Since(watchWhois[d.ID]) >= 90*time.Second
	if whoisDue {
		watchWhois[d.ID] = time.Now()
	}
	i := watchRotate[d.ID]
	watchRotate[d.ID] = i + 1
	watchMu.Unlock()

	var fast []string
	fast = append(fast, e.mon.Fallbacks()...)
	for _, k := range d.CatchRegistrars {
		fast = append(fast, "reg:"+k)
	}
	for _, r := range e.regs.Ready() {
		n := "reg:" + r.Key()
		if !slices.Contains(fast, n) {
			fast = append(fast, n)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	for k := 0; k < len(fast); k++ {
		o, ok := e.mon.CheckSource(cctx, fast[(i+k)%len(fast)], name, true)
		if !ok {
			continue // benched/unsupported: try the next one this tick
		}
		e.st.AddCheck(d.ID, checkOf("watch", o))
		if o.Err != nil {
			e.logPoll(d.ID, "watch", o, "error")
			if monitor.KindOf(o.Err) == monitor.ErrBusy || monitor.KindOf(o.Err) == monitor.ErrUnsupported {
				continue
			}
			break
		}
		cur, err := e.st.GetDomain(d.ID)
		if err != nil {
			return
		}
		e.apply(ctx, w, cur, name, o, cur.Armed(time.Now()) && cur.CatchState != store.CatchWon, "watch")
		break
	}
	if whoisDue {
		cur, err := e.st.GetDomain(d.ID)
		if err != nil {
			return
		}
		e.checkOnce(ctx, w, cur, cur.Armed(time.Now()) && cur.CatchState != store.CatchWon)
		return
	}
	e.st.Touch(d.ID)
}

func checkOf(purpose string, o monitor.Observation) store.Check {
	c := store.Check{Purpose: purpose, Source: o.Source, MS: o.Elapsed.Milliseconds(), Detail: o.Detail, Result: o.Status}
	if o.Err != nil {
		c.Result, c.Detail = "error", monitor.KindOf(o.Err).String()+": "+o.Err.Error()
	}
	return c
}

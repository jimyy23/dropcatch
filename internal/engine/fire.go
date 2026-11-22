package engine

import (
	"context"
	"fmt"
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
	at, err := ExpectedRelease(ReleaseInputFor(d))
	if err != nil {
		return d.FireAt
	}
	if !at.Equal(d.FireAt) {
		e.st.SetFireAt(d.ID, at)
		e.st.AddEvent(d.ID, "release_time", "info", fmt.Sprintf("expected registry release %s UTC (%s rule)",
			at.UTC().Format("2006-01-02 15:04:05"), rule.Name))
	}
	return at
}

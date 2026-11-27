package engine

import (
	"fmt"
	"strings"
	"time"

	"dropcatch/internal/monitor"
	"dropcatch/internal/store"
)

// Freshness guard. Registry answers can come from old copies (TWNIC RDAP
// replicas served snapshots up to 4 h old, alternating with fresh ones), so
// an answer is only allowed to change the stored state when it is not older
// than what was already seen, and a status change is committed only after
// consecutive agreeing answers. Disagreements go to the poll log, not the
// event log.

// verdict of one answer
type verdict struct {
	accept bool   // may update the stored status / data
	why    string // reason when rejected (poll log)
}

// judge decides whether an answer is plausible given what is known.
func judge(d *store.Domain, o monitor.Observation, now time.Time) verdict {
	if o.Status == monitor.StatusNotInZone {
		return verdict{false, "no verdict (not delegated in DNS)"}
	}
	var created, expires, snapshot time.Time
	if o.Info != nil {
		created, expires, snapshot = o.Info.Created, o.Info.Expires, o.Info.Snapshot
	}
	// an answer from an older registry snapshot than one already seen
	if !snapshot.IsZero() && !d.SnapshotMax.IsZero() && snapshot.Before(d.SnapshotMax) {
		return verdict{false, fmt.Sprintf("stale: registry snapshot %s older than %s", hm(snapshot), hm(d.SnapshotMax))}
	}
	// a deletion-cycle answer taken before the current state was reached
	// (released or re-registered since) or before the expected release
	if !snapshot.IsZero() && (o.Status == store.StatusPendingDelete || o.Status == store.StatusRedemption) {
		if (d.Status == store.StatusAvailable || d.Status == store.StatusRegistered) && !d.StatusSince.IsZero() && snapshot.Before(d.StatusSince) && d.StatusSince.After(d.CreatedAt.Add(2*time.Minute)) {
			return verdict{false, fmt.Sprintf("stale: pending-delete snapshot %s predates the %s state (since %s)", hm(snapshot), d.Status, hm(d.StatusSince))}
		}
		if !d.FireAt.IsZero() && now.After(d.FireAt) && snapshot.Before(d.FireAt) && d.Status != store.StatusPendingDelete {
			return verdict{false, fmt.Sprintf("stale: snapshot %s predates the release %s", hm(snapshot), hm(d.FireAt))}
		}
	}
	registered := d.Status == store.StatusRegistered && !d.Created.IsZero()
	switch {
	case registered && created.IsZero() && (o.Status == store.StatusAvailable || o.Status == store.StatusPendingDelete || o.Status == store.StatusRedemption):
		// a registration with a known creation date never goes back to free or
		// to the deletion cycle unless the registry shows a new lifecycle,
		// which a weak/undated answer cannot prove
		if o.Status == store.StatusAvailable && !o.Weak && strongSource(o) && now.Sub(d.Created) > 24*time.Hour && !d.Expires.IsZero() && now.After(d.Expires) {
			break // a long-expired registration can really be deleted
		}
		return verdict{false, fmt.Sprintf("stale: registered since %s, answer %s has no newer registration data", hm(d.Created), o.Status)}
	case !created.IsZero() && !d.Created.IsZero() && created.Before(d.Created):
		return verdict{false, fmt.Sprintf("stale: creation %s older than known %s", hm(created), hm(d.Created))}
	case !created.IsZero() && !d.Created.IsZero() && created.Equal(d.Created) && !expires.IsZero() && !d.Expires.IsZero() && expires.Before(d.Expires):
		return verdict{false, fmt.Sprintf("stale: expiry %s older than known %s", expires.Format("2006-01-02"), d.Expires.Format("2006-01-02"))}
	case o.Status == store.StatusAvailable && o.Weak && d.Status == store.StatusRegistered:
		return verdict{false, "weak: 'not found' without snapshot time while registered"}
	}
	return verdict{true, ""}
}

// strongSource: answers read straight from the registry.
func strongSource(o monitor.Observation) bool {
	return o.Source == monitor.SrcTWNIC && o.Via == "port43" || o.Via == "sidecar-whois"
}

// confirmationsNeeded is how many consecutive agreeing answers commit a
// status change. One answer suffices when it is self-evidently new: a fresh
// registration (creation date after the last known one / after the expected
// release) or a direct port-43 answer.
func confirmationsNeeded(d *store.Domain, o monitor.Observation) int {
	if d.Status == "" || d.Status == store.StatusUnknown {
		return 1
	}
	if o.Status == store.StatusRegistered && o.Info != nil && !o.Info.Created.IsZero() &&
		(d.Created.IsZero() || o.Info.Created.After(d.Created)) &&
		(d.FireAt.IsZero() || !o.Info.Created.Before(d.FireAt.Add(-time.Minute))) {
		return 1
	}
	if o.Source == monitor.SrcTWNIC && o.Via == "port43" {
		return 1
	}
	if o.Source == monitor.SrcTWNIC && o.Via == "dns" && o.Status == store.StatusRegistered {
		return 1 // a delegation appearing in the live zone
	}
	return 2
}

// observed is the outcome of one answer.
type observed struct {
	Status   string // status in force after the answer
	Changed  bool   // a transition was committed
	Accepted bool   // the answer itself is plausible (not stale); orders may start on it
	Raw      string // the answer's own status
}

// observe applies one successful answer to the domain.
func (e *Engine) observe(d *store.Domain, o monitor.Observation, purpose string) observed {
	r := e.observe1(d, o, purpose)
	r.Raw = keepSpecific(d.Status, o)
	return r
}

func (e *Engine) observe1(d *store.Domain, o monitor.Observation, purpose string) observed {
	now := time.Now()
	o.Status = keepSpecific(d.Status, o)
	v := judge(d, o, now)
	pollVerdict := ""
	defer func() {
		e.logPoll(d.ID, purpose, o, pollVerdict)
	}()
	if !v.accept {
		pollVerdict = v.why
		e.st.Touch(d.ID)
		if d.CandStatus != "" {
			e.st.SetCandidate(d.ID, "", 0, time.Time{})
		}
		return observed{Status: d.Status}
	}
	if o.Info != nil && !o.Info.Snapshot.IsZero() {
		e.st.SetSnapshotMax(d.ID, o.Info.Snapshot)
	}
	if o.Status == monitor.StatusNotInZone {
		pollVerdict = "no verdict"
		e.st.Touch(d.ID)
		return observed{Status: d.Status}
	}
	if o.Status == d.Status {
		pollVerdict = "agrees"
		if d.CandStatus != "" {
			e.st.SetCandidate(d.ID, "", 0, time.Time{})
		}
		// same status: refresh registration data (dates only move forward,
		// enforced by judge)
		e.st.SaveObservation(d.ID, o.Status, o.Source, "", o.Info)
		e.afterData(d, o)
		return observed{Status: d.Status, Accepted: true}
	}
	need := confirmationsNeeded(d, o)
	count, since := 1, o.Start
	if d.CandStatus == o.Status {
		count, since = d.CandCount+1, d.CandSince
	}
	if since.IsZero() {
		since = now
	}
	if count < need {
		e.st.SetCandidate(d.ID, o.Status, count, since)
		e.st.Touch(d.ID)
		pollVerdict = fmt.Sprintf("pending %s %d/%d", o.Status, count, need)
		return observed{Status: d.Status, Accepted: true}
	}
	e.st.SetCandidate(d.ID, "", 0, time.Time{})
	pollVerdict = "committed " + o.Status
	prev := d.Status
	e.st.SaveObservation(d.ID, o.Status, o.Source, "", o.Info)
	e.statusEvent(d, prev, o, since)
	e.afterData(d, o)
	return observed{Status: o.Status, Changed: true, Accepted: true}
}

// statusEvent logs one committed transition with timing facts.
func (e *Engine) statusEvent(d *store.Domain, prev string, o monitor.Observation, firstSeen time.Time) {
	lvl := "info"
	if o.Status == store.StatusAvailable || o.Status == store.StatusPendingDelete {
		lvl = "alert"
	}
	via := o.Source
	if o.Via != "" && o.Via != "api" {
		via += "/" + o.Via
	}
	detail := fmt.Sprintf("%s → %s (via %s; first seen %s UTC)", prev, o.Status, via, firstSeen.UTC().Format("15:04:05.000"))
	if prev == store.StatusUnknown || prev == "" {
		// first check after adding: no detection timing to report
	} else if o.Status == store.StatusRegistered && o.Info != nil && !o.Info.Created.IsZero() &&
		(o.Info.Created.After(now().Add(-48*time.Hour)) || prev == store.StatusPendingDelete || prev == store.StatusRedemption || prev == store.StatusAvailable) &&
		(d.Created.IsZero() || o.Info.Created.After(d.Created)) {
		// a fresh registration: how long after the registry event we saw it
		detail += fmt.Sprintf("; registry creation %s UTC, detected %s after", o.Info.Created.UTC().Format("2006-01-02 15:04:05"),
			firstSeen.Sub(o.Info.Created).Round(100*time.Millisecond))
		if o.Info.Registrar != "" {
			detail += ", registrar " + o.Info.Registrar
		}
	} else if !d.FireAt.IsZero() && (prev == store.StatusPendingDelete || prev == store.StatusRedemption) && o.Status == store.StatusAvailable {
		// the drop itself: bounded by the last answer still showing the old
		// state and the first fresh "available"
		off := firstSeen.Sub(d.FireAt).Round(time.Second)
		last := e.st.LastPollWith(d.ID, prev, firstSeen)
		lastS := "?"
		if !last.IsZero() {
			lastS = last.Format("2006-01-02 15:04:05")
		}
		detail += fmt.Sprintf("; DROP between %s (last %s answer) and %s UTC (%+v vs expected release %s UTC)",
			lastS, prev, firstSeen.UTC().Format("15:04:05"), off, d.FireAt.UTC().Format("2006-01-02 15:04"))
	}
	e.st.AddEvent(d.ID, "status_change", lvl, detail)
	if o.Status == store.StatusPendingDelete && d.AutoCatchPD {
		e.st.AddEvent(d.ID, "auto_catch_armed", "alert", "pending delete seen: drop-catch armed automatically")
	}
}

var now = time.Now

// afterData handles registration data changes (expiry, fire time).
func (e *Engine) afterData(d *store.Domain, o monitor.Observation) {
	if o.Info != nil && !d.Expires.IsZero() && !o.Info.Expires.IsZero() && !o.Info.Expires.Equal(d.Expires) {
		e.st.AddEvent(d.ID, "expiry_change", "info", fmt.Sprintf("%s → %s", d.Expires.Format("2006-01-02"), o.Info.Expires.Format("2006-01-02")))
	}
	if d2, err := e.st.GetDomain(d.ID); err == nil {
		e.RefreshFireAt(d2)
	}
}

// logPoll stores the raw answer with its timing and verdict.
func (e *Engine) logPoll(id int64, purpose string, o monitor.Observation, verdict string) {
	p := store.Poll{DomainID: id, Start: o.Start, End: o.Start.Add(o.Elapsed), Purpose: purpose, Source: o.Source, Via: o.Via,
		Status: o.Status, Verdict: verdict, Detail: o.Detail, Raw: o.Raw}
	if p.Start.IsZero() {
		p.End = time.Now()
		p.Start = p.End.Add(-o.Elapsed)
	}
	if o.Err != nil {
		p.Status, p.Verdict, p.Detail = "error", "error", monitor.KindOf(o.Err).String()+": "+o.Err.Error()
	}
	if o.Info != nil && !o.Info.Snapshot.IsZero() {
		p.Detail = strings.TrimSpace(p.Detail + " snapshot " + o.Info.Snapshot.UTC().Format("15:04:05"))
	}
	e.st.AddPoll(p)
}

func hm(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") }

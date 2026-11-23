package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"dropcatch/internal/store"
)

// CIRATBRURL is CIRA's published To-Be-Released list, loaded by
// https://www.cira.ca/en/ca-domains/tbr/. It is behind Cloudflare, which
// rejects non-browser user agents.
const CIRATBRURL = "https://www.cira.ca/en/wp-json/cira/v1/domains/tbr"

const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// TBRList caches CIRA's TBR list: domain (ASCII, lower case) -> session
// date. CIRA updates it daily; it lists the upcoming session only.
type TBRList struct {
	url  string
	http *http.Client

	refreshing sync.Mutex // one download at a time

	mu        sync.RWMutex
	dates     map[string]time.Time
	fetchedAt time.Time
	err       error
}

// TBRStatus is shown in the UI.
type TBRStatus struct {
	Count     int
	Sessions  []string // distinct session dates, YYYY-MM-DD
	FetchedAt time.Time
	Err       string
}

func NewTBRList(url string) *TBRList {
	return &TBRList{url: url, http: &http.Client{Timeout: 60 * time.Second}}
}

// Lookup returns the session (19:00:00 UTC on the listed date) of a domain.
func (l *TBRList) Lookup(name string) (time.Time, bool) {
	if l == nil {
		return time.Time{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	t, ok := l.dates[strings.ToLower(name)]
	return t, ok
}

func (l *TBRList) Status() TBRStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()
	s := TBRStatus{Count: len(l.dates), FetchedAt: l.fetchedAt}
	if l.err != nil {
		s.Err = l.err.Error()
	}
	seen := map[string]bool{}
	for _, t := range l.dates {
		if d := t.Format("2006-01-02"); !seen[d] {
			seen[d] = true
			s.Sessions = append(s.Sessions, d)
		}
	}
	return s
}

// Refresh downloads the list. On failure the previous list is kept.
func (l *TBRList) Refresh(ctx context.Context) error {
	dates, err := l.fetch(ctx)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = err
	if err == nil {
		l.dates, l.fetchedAt = dates, time.Now()
	}
	return err
}

func (l *TBRList) fetch(ctx context.Context) (map[string]time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", l.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://www.cira.ca/en/ca-domains/tbr/")
	resp, err := l.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CIRA TBR list: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("CIRA TBR list: %v", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CIRA TBR list: HTTP %d", resp.StatusCode)
	}
	var rows []struct {
		Name string `json:"name"`
		Date string `json:"date"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("CIRA TBR list: not JSON (blocked?): %v", err)
	}
	dates := make(map[string]time.Time, len(rows))
	for _, r := range rows {
		day, err := time.Parse("2006-01-02", r.Date)
		if err != nil || r.Name == "" {
			continue
		}
		dates[strings.ToLower(strings.TrimSpace(r.Name))] = day.Add(19 * time.Hour)
	}
	if len(rows) > 0 && len(dates) == 0 {
		return nil, fmt.Errorf("CIRA TBR list: no usable rows")
	}
	return dates, nil
}

// TBR exposes the CIRA list (status for the UI).
func (e *Engine) TBR() *TBRList { return e.tbr }

// SetTBRList replaces the list source (tests).
func (e *Engine) SetTBRList(l *TBRList) { e.tbr = l }

// tbrLoop refreshes CIRA's TBR list hourly while any .ca domain exists and
// recomputes the .ca fire times from it.
func (e *Engine) tbrLoop(ctx context.Context) {
	for {
		e.RefreshTBR(ctx, time.Hour)
		if !sleepCtx(ctx, 10*time.Minute) {
			return
		}
	}
}

// RefreshTBR downloads the list when it is older than maxAge and some .ca
// domain is tracked, then updates the automatic fire times of .ca domains.
func (e *Engine) RefreshTBR(ctx context.Context, maxAge time.Duration) {
	var ca []int64
	for _, d := range e.st.ListDomains() {
		if d.Suffix == "ca" {
			ca = append(ca, d.ID)
		}
	}
	if len(ca) == 0 {
		return
	}
	e.tbr.refreshing.Lock()
	defer e.tbr.refreshing.Unlock()
	if st := e.tbr.Status(); time.Since(st.FetchedAt) < maxAge && st.Err == "" {
		return
	}
	if err := e.tbr.Refresh(ctx); err != nil {
		e.log.Warn("CIRA TBR list", "err", err)
		return
	}
	e.log.Info("CIRA TBR list refreshed", "domains", e.tbr.Status().Count)
	for _, id := range ca {
		if d, err := e.st.GetDomain(id); err == nil {
			e.RefreshFireAt(d)
			e.Start(id) // wake the worker: the fire time may have changed
		}
	}
}

// ReleaseInput is ReleaseInputFor plus the registry's published list.
func (e *Engine) ReleaseInput(d *store.Domain) ReleaseInput {
	in := ReleaseInputFor(d)
	if d.Suffix == "ca" {
		in.Listed, _ = e.tbr.Lookup(d.Name)
	}
	return in
}

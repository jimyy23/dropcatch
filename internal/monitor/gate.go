package monitor

import (
	"context"
	"sync"
	"time"
)

// Gate spaces requests to one upstream (a WHOIS server, a website) by a
// minimum gap. Priority callers (domains in drop-catch mode) are served before
// routine checks, so a busy suffix never delays a drop.
type Gate struct {
	mu   sync.Mutex
	gap  time.Duration
	next time.Time
	hi   int // priority callers waiting
}

func NewGate(gap time.Duration) *Gate { return &Gate{gap: gap} }

func (g *Gate) SetGap(d time.Duration) {
	g.mu.Lock()
	g.gap = d
	g.mu.Unlock()
}

// Wait blocks until the caller may send a request.
func (g *Gate) Wait(ctx context.Context, prio bool) error {
	if prio {
		g.mu.Lock()
		g.hi++
		g.mu.Unlock()
		defer func() {
			g.mu.Lock()
			g.hi--
			g.mu.Unlock()
		}()
	}
	for {
		g.mu.Lock()
		now := time.Now()
		var d time.Duration
		switch {
		case !prio && g.hi > 0:
			d = 100 * time.Millisecond
		case !now.Before(g.next):
			g.next = now.Add(g.gap)
			g.mu.Unlock()
			return nil
		default:
			d = g.next.Sub(now)
		}
		g.mu.Unlock()
		if d > 250*time.Millisecond {
			d = 250 * time.Millisecond
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// TryNow reserves a slot only if one is free immediately.
func (g *Gate) TryNow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Before(g.next) {
		return false
	}
	g.next = now.Add(g.gap)
	return true
}

// Gates is a lazily populated set of gates keyed by name.
type Gates struct {
	mu  sync.Mutex
	gap time.Duration
	m   map[string]*Gate
}

func NewGates(gap time.Duration) *Gates { return &Gates{gap: gap, m: map[string]*Gate{}} }

func (g *Gates) Get(key string) *Gate {
	g.mu.Lock()
	defer g.mu.Unlock()
	x, ok := g.m[key]
	if !ok {
		x = NewGate(g.gap)
		g.m[key] = x
	}
	return x
}

func (g *Gates) SetGap(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gap = d
	for _, x := range g.m {
		x.SetGap(d)
	}
}

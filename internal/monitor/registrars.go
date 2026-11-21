package monitor

import (
	"context"
	"errors"
	"sync"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/registrar"
	"dropcatch/internal/store"
)

// RegistrarSource adapts a registrar's availability API as a monitor source.
// It never places orders. A per-registrar gate and an hourly cap keep usage
// far below the registrars' limits (e.g. Porkbun flags accounts that check
// many names without registering).
type RegistrarSource struct {
	R       registrar.Registrar
	gate    *Gate
	mu      sync.Mutex
	window  time.Time
	used    int
	perHour int
}

func NewRegistrarSource(r registrar.Registrar, gap time.Duration, perHour int) *RegistrarSource {
	return &RegistrarSource{R: r, gate: NewGate(gap), perHour: perHour, window: time.Now()}
}

func (s *RegistrarSource) SetPerHour(n int) {
	s.mu.Lock()
	if n > 0 {
		s.perHour = n
	}
	s.mu.Unlock()
}

func (s *RegistrarSource) Name() string  { return "reg:" + s.R.Key() }
func (s *RegistrarSource) Label() string { return s.R.Label() + " API" }

func (s *RegistrarSource) budget() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.window) > time.Hour {
		s.window, s.used = time.Now(), 0
	}
	if s.used >= s.perHour {
		return false
	}
	s.used++
	return true
}

func (s *RegistrarSource) Check(ctx context.Context, d domainutil.Name, prio bool) (o Observation) {
	start := time.Now()
	o = Observation{Source: s.Name()}
	defer func() { o.Elapsed = time.Since(start) }()
	if !s.budget() {
		o.Err = lerr(ErrBusy, "%s: hourly check budget used", s.R.Label())
		return o
	}
	if err := s.gate.Wait(ctx, prio); err != nil {
		o.Err = lerr(ErrBusy, "%v", err)
		return o
	}
	a, err := s.R.Check(ctx, d.ASCII)
	if err != nil {
		var re *registrar.RateError
		switch {
		case errors.Is(err, registrar.ErrUnsupported):
			o.Err = lerr(ErrUnsupported, "%s: suffix not supported", s.R.Label())
		case errors.As(err, &re):
			o.Err = &LookupError{Kind: ErrRateLimited, Msg: re.Msg, RetryAfter: re.RetryAfter}
		default:
			o.Err = lerr(ErrTransient, "%s: %v", s.R.Label(), err)
		}
		return o
	}
	o.Status = store.StatusRegistered
	if a.Available {
		o.Status = store.StatusAvailable
	}
	o.Detail = a.Price
	if a.Premium {
		o.Detail = "premium " + a.Price
	}
	return o
}

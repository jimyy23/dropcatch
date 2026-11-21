// Package registrar implements availability checks and order placement for
// the supported registrar APIs. Every implementation follows the registrar's
// official documentation (see docs/registrars.md).
package registrar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Outcome of an order attempt.
type Outcome string

const (
	// Success: the registrar reports the domain registered to our account.
	Success Outcome = "success"
	// Pending: the order was accepted but completes asynchronously.
	Pending Outcome = "pending"
	// Unavailable: the registrar says the domain cannot be registered (yet).
	// During a drop this is the normal answer until the registry releases it.
	Unavailable Outcome = "unavailable"
	// RateLimited: slow down; RetryAfter is honoured.
	RateLimited Outcome = "rate_limited"
	// Retryable: transient error (timeout, 5xx, registry busy).
	Retryable Outcome = "error"
	// Fatal: retrying cannot help (bad credentials, funds, unsupported TLD,
	// premium, contact data). The registrar is dropped for this session.
	Fatal Outcome = "fatal"
	// DryRun: ORDERS_DRY_RUN is set; nothing was purchased.
	DryRun Outcome = "dry_run"
)

// Result of one order attempt.
type Result struct {
	Outcome    Outcome
	Ref        string // order / transaction / operation id
	Message    string
	RetryAfter time.Duration
	Price      string
}

// Availability is a registrar-side availability answer.
type Availability struct {
	Available bool
	Premium   bool
	Price     string
	Detail    string
}

// ErrUnsupported is returned by Check when the registrar does not sell the suffix.
var ErrUnsupported = errors.New("suffix not supported by registrar")

// Registrar is one registrar API.
type Registrar interface {
	Key() string   // stable key used in settings: dynadot, porkbun, ...
	Label() string // display name
	// PriceKey is the registrar's key in the nazhumi / miqingju price databases.
	PriceKey() string
	// Configured reports whether credentials are present.
	Configured() bool
	// Problem describes missing non-secret configuration (empty when ready).
	Problem() string
	// Check asks the registrar whether the domain can be registered. It is
	// used only as a cheap confirmation signal, never inside the order loop.
	Check(ctx context.Context, domain string) (Availability, error)
	// Register places an order paid from the account balance.
	Register(ctx context.Context, domain string) Result
	// MinGap is the minimum spacing between order attempts (registrar limits).
	MinGap() time.Duration
}

// RateError signals a registrar-side throttle on Check.
type RateError struct {
	Msg        string
	RetryAfter time.Duration
}

func (e *RateError) Error() string { return e.Msg }

func httpClient(timeout time.Duration) *http.Client { return &http.Client{Timeout: timeout} }

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func retryAfter(h http.Header, def time.Duration) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

// classifyHTTP maps a bare HTTP failure to an outcome.
func classifyHTTP(code int) Outcome {
	switch {
	case code == 429:
		return RateLimited
	case code >= 500 || code == 408:
		return Retryable
	case code == 401 || code == 403:
		return Fatal
	}
	return Retryable
}

// Info describes a registrar for the UI.
type Info struct {
	Key, Label, PriceKey string
	Configured           bool
	Problem              string
}

// Set is the configured registrars keyed by Key.
type Set struct {
	all []Registrar
	m   map[string]Registrar
}

func NewSet(rs ...Registrar) *Set {
	s := &Set{m: map[string]Registrar{}}
	for _, r := range rs {
		s.all = append(s.all, r)
		s.m[r.Key()] = r
	}
	return s
}

func (s *Set) Get(key string) Registrar { return s.m[key] }
func (s *Set) All() []Registrar         { return s.all }

// Ready returns registrars with credentials and complete configuration.
func (s *Set) Ready() []Registrar {
	var out []Registrar
	for _, r := range s.all {
		if r.Configured() && r.Problem() == "" {
			out = append(out, r)
		}
	}
	return out
}

func (s *Set) Infos() []Info {
	var out []Info
	for _, r := range s.all {
		out = append(out, Info{Key: r.Key(), Label: r.Label(), PriceKey: r.PriceKey(), Configured: r.Configured(), Problem: r.Problem()})
	}
	return out
}

// Keys lists all registrar keys.
func (s *Set) Keys() []string {
	var out []string
	for _, r := range s.all {
		out = append(out, r.Key())
	}
	return out
}

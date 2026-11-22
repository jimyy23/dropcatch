// Package monitor answers "is this domain available?" using the WHOIS/RDAP
// service first and keyless web checkers / registrar APIs as fallbacks, and
// learns per suffix which source is currently reliable.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/store"
)

// ErrKind classifies a failed lookup; it decides how the source is penalised.
type ErrKind int

const (
	ErrNone        ErrKind = iota
	ErrTransient           // timeout, 5xx, garbled answer: counts towards cooldown
	ErrRateLimited         // upstream throttled us: cooldown immediately
	ErrUnsupported         // source does not cover this suffix
	ErrInvalid             // the name itself was rejected: no penalty
	ErrBusy                // local budget exhausted (e.g. Regery per-IP limit): no penalty
	ErrUnparsed            // answer received but not understood: counts as an error, never "available"
)

func (k ErrKind) String() string {
	return [...]string{"", "error", "rate-limited", "unsupported", "invalid", "busy", "unparsed"}[k]
}

// LookupError carries the kind and an optional retry hint.
type LookupError struct {
	Kind       ErrKind
	Msg        string
	RetryAfter time.Duration
}

func (e *LookupError) Error() string { return e.Msg }

func lerr(k ErrKind, format string, a ...any) *LookupError {
	return &LookupError{Kind: k, Msg: fmt.Sprintf(format, a...)}
}

// KindOf extracts the error kind (transient for foreign errors).
func KindOf(err error) ErrKind {
	if err == nil {
		return ErrNone
	}
	var le *LookupError
	if errors.As(err, &le) {
		return le.Kind
	}
	return ErrTransient
}

// Observation is one answer from one source.
type Observation struct {
	Source  string
	Status  string      // store.Status*; empty when Err != nil
	Info    *store.Info // registration data (WHOIS/RDAP only)
	Err     error
	Elapsed time.Duration
	Detail  string
}

func (o Observation) Available() bool { return o.Err == nil && o.Status == store.StatusAvailable }

// Source is one availability checker.
type Source interface {
	Name() string
	Label() string
	// Check looks a domain up. prio marks drop-catch checks.
	Check(ctx context.Context, d domainutil.Name, prio bool) Observation
}

const (
	SrcWhois = "whois"
	// SrcWhoisExtPrefix prefixes external WHOIS sidecars: "whois:<host>".
	SrcWhoisExtPrefix = "whois:"
	SrcCloudean       = "cloudean"
	SrcRegery         = "regery"
)

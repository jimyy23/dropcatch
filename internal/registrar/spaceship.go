package registrar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"dropcatch/internal/config"
)

// Spaceship implements the Spaceship API (https://docs.spaceship.dev/).
//
//	base:     https://spaceship.dev/api, headers X-API-Key + X-API-Secret
//	check:    GET  /v1/domains/{d}/available -> result: available | taken |
//	          invalidDomainName | tldNotSupported | unexpectedError (+ premiumPricing)
//	          limits: 5 / domain / 300 s, 30 / user / 30 s
//	register: POST /v1/domains/{d} {autoRenew, years, privacyProtection{level,userConsent},
//	          contacts{registrant,admin,tech,billing}} -> 202 + spaceship-async-operationid
//	          limit: 30 / user / 30 s; scope domains:billing
//	status:   GET  /v1/async-operations/{id} -> pending | failed | success (60 / 300 s)
//	contact:  PUT  /v1/contacts -> {contactId} (idempotent for identical data)
//	prices:   GET  /v1/domains/{d}/pricing
//
// Errors are application/problem+json {detail} with a spaceship-error-code
// header. The API has no account-balance endpoint; registrations are charged
// to the account's payment method/funds.
type Spaceship struct {
	c    config.Spaceship
	ct   config.Contact
	base string
	http *http.Client
	dry  bool

	mu        sync.Mutex
	contactID string
	pollEvery time.Duration
}

func NewSpaceship(c config.Spaceship, ct config.Contact, dry bool) *Spaceship {
	return &Spaceship{c: c, ct: ct, base: "https://spaceship.dev/api", http: httpClient(60 * time.Second), dry: dry, contactID: c.ContactID, pollEvery: 5 * time.Second}
}

func (s *Spaceship) Key() string           { return "spaceship" }
func (s *Spaceship) Label() string         { return "Spaceship" }
func (s *Spaceship) PriceKey() string      { return "spaceship" }
func (s *Spaceship) Configured() bool      { return s.c.APIKey != "" && s.c.APISecret != "" }
func (s *Spaceship) MinGap() time.Duration { return 1100 * time.Millisecond } // 30 registrations / 30 s

func (s *Spaceship) Problem() string {
	if s.c.ContactID == "" && !s.ct.Complete() {
		return "set SPACESHIP_CONTACT_ID or the REGISTRANT_* contact"
	}
	return ""
}

type ssError struct {
	Status     int
	Code       string // spaceship-error-code header
	Detail     string
	OpID       string
	RetryAfter time.Duration
}

func (e *ssError) Error() string {
	s := fmt.Sprintf("spaceship HTTP %d", e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func (s *Spaceship) do(ctx context.Context, method, path string, body any, out any) (http.Header, int, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-API-Key", s.c.APIKey)
	req.Header.Set("X-API-Secret", s.c.APISecret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode >= 300 {
		e := &ssError{Status: resp.StatusCode, Code: resp.Header.Get("spaceship-error-code"), OpID: resp.Header.Get("spaceship-operation-id")}
		var p struct {
			Detail string `json:"detail"`
			Data   []struct {
				Field   string `json:"field"`
				Details string `json:"details"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &p) == nil {
			e.Detail = p.Detail
			for _, d := range p.Data {
				e.Detail += "; " + d.Field + ": " + d.Details
			}
		} else {
			e.Detail = trunc(string(raw), 200)
		}
		if resp.StatusCode == 429 {
			e.RetryAfter = retryAfter(resp.Header, 30*time.Second)
		}
		return resp.Header, resp.StatusCode, e
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.Header, resp.StatusCode, fmt.Errorf("spaceship: unexpected response: %s", trunc(string(raw), 200))
		}
	}
	return resp.Header, resp.StatusCode, nil
}

func (s *Spaceship) Check(ctx context.Context, domain string) (Availability, error) {
	var r struct {
		Domain         string `json:"domain"`
		Result         string `json:"result"`
		PremiumPricing []struct {
			Operation string      `json:"operation"`
			Price     json.Number `json:"price"`
			Currency  string      `json:"currency"`
		} `json:"premiumPricing"`
	}
	if _, _, err := s.do(ctx, "GET", "/v1/domains/"+url.PathEscape(domain)+"/available", nil, &r); err != nil {
		if e, ok := err.(*ssError); ok && e.Status == 429 {
			return Availability{}, &RateError{Msg: e.Error(), RetryAfter: e.RetryAfter}
		}
		return Availability{}, err
	}
	a := Availability{}
	for _, p := range r.PremiumPricing {
		if p.Operation == "register" {
			a.Premium, a.Price = true, p.Price.String()+" "+p.Currency
		}
	}
	switch r.Result {
	case "available":
		a.Available = true
		return a, nil
	case "taken":
		return a, nil
	case "tldNotSupported", "invalidDomainName":
		return Availability{}, ErrUnsupported
	}
	return Availability{}, fmt.Errorf("spaceship check: result %q", r.Result)
}

// EnsureContact returns the registrant contact id: SPACESHIP_CONTACT_ID, or
// REGISTRANT_* saved through PUT /v1/contacts (returns the existing id when
// identical data was saved before).
func (s *Spaceship) EnsureContact(ctx context.Context) (string, error) {
	s.mu.Lock()
	id := s.contactID
	s.mu.Unlock()
	if id != "" {
		return id, nil
	}
	if !s.ct.Complete() {
		return "", fmt.Errorf("REGISTRANT_* contact incomplete")
	}
	body := map[string]any{"firstName": s.ct.FirstName, "lastName": s.ct.LastName, "email": s.ct.Email, "address1": s.ct.Street,
		"city": s.ct.City, "country": s.ct.Country, "phone": s.ct.Phone}
	for k, v := range map[string]string{"organization": s.ct.Organization, "address2": s.ct.Street2, "stateProvince": s.ct.State, "postalCode": s.ct.PostalCode} {
		if v != "" {
			body[k] = v
		}
	}
	var out struct {
		ContactID string `json:"contactId"`
	}
	if _, _, err := s.do(ctx, "PUT", "/v1/contacts", body, &out); err != nil {
		return "", err
	}
	if out.ContactID == "" {
		return "", fmt.Errorf("spaceship: contact saved without id")
	}
	s.mu.Lock()
	s.contactID = out.ContactID
	s.mu.Unlock()
	return out.ContactID, nil
}

// ContactExists reads GET /v1/contacts/{id} (read-only).
func (s *Spaceship) ContactExists(ctx context.Context, id string) (bool, error) {
	_, _, err := s.do(ctx, "GET", "/v1/contacts/"+url.PathEscape(id), nil, &map[string]any{})
	if e, ok := err.(*ssError); ok && (e.Status == 404 || e.Status == 422 || e.Status == 400) {
		return false, nil
	}
	return err == nil, err
}

func (s *Spaceship) Register(ctx context.Context, domain string) Result {
	if s.dry {
		return Result{Outcome: DryRun, Message: "dry run: would POST /v1/domains/" + domain}
	}
	contact, err := s.EnsureContact(ctx)
	if err != nil {
		return ssResult(err, "saving contact: ")
	}
	level := "high"
	if !s.c.Privacy {
		level = "public"
	}
	body := map[string]any{
		"autoRenew":         false,
		"years":             1,
		"privacyProtection": map[string]any{"level": level, "userConsent": true},
		"contacts":          map[string]any{"registrant": contact, "admin": contact, "tech": contact, "billing": contact},
	}
	h, status, err := s.do(ctx, "POST", "/v1/domains/"+url.PathEscape(domain), body, nil)
	if err != nil {
		return ssResult(err, "")
	}
	opID := h.Get("spaceship-async-operationid")
	if status != 202 || opID == "" {
		return Result{Outcome: Pending, Ref: opID, Message: fmt.Sprintf("accepted (HTTP %d)", status)}
	}
	return s.waitOperation(ctx, opID)
}

// waitOperation polls the async operation briefly (the drop-catch session
// keeps other registrars going meanwhile). Polling is limited to 60 / 300 s.
func (s *Spaceship) waitOperation(ctx context.Context, opID string) Result {
	deadline := time.Now().Add(45 * time.Second)
	for {
		var op struct {
			Status  string          `json:"status"`
			Type    string          `json:"type"`
			Details json.RawMessage `json:"details"`
		}
		_, _, err := s.do(ctx, "GET", "/v1/async-operations/"+url.PathEscape(opID), nil, &op)
		if err == nil {
			switch op.Status {
			case "success":
				return Result{Outcome: Success, Ref: opID, Message: "registered"}
			case "failed":
				d := trunc(string(op.Details), 300)
				low := strings.ToLower(d)
				if strings.Contains(low, "not available") || strings.Contains(low, "taken") || strings.Contains(low, "unavailable") {
					return Result{Outcome: Unavailable, Ref: opID, Message: "registration failed: " + d}
				}
				return Result{Outcome: Retryable, Ref: opID, Message: "registration failed: " + d}
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return Result{Outcome: Pending, Ref: opID, Message: "registration in progress (async operation " + opID + ")"}
		}
		select {
		case <-ctx.Done():
			return Result{Outcome: Pending, Ref: opID, Message: "registration in progress (async operation " + opID + ")"}
		case <-time.After(s.pollEvery):
		}
	}
}

// ssResult maps an API error to an order outcome.
func ssResult(err error, prefix string) Result {
	e, ok := err.(*ssError)
	if !ok {
		return Result{Outcome: Retryable, Message: prefix + err.Error()}
	}
	msg := prefix + e.Error()
	low := strings.ToLower(e.Code + " " + e.Detail)
	switch {
	case e.Status == 429:
		return Result{Outcome: RateLimited, Message: msg, RetryAfter: e.RetryAfter}
	case e.Status == 401 || e.Status == 403:
		return Result{Outcome: Fatal, Message: msg + " (check SPACESHIP_API_KEY/SECRET and the domains:billing, contacts:write, asyncoperations:read scopes)"}
	case strings.Contains(low, "insufficient") || strings.Contains(low, "balance") || strings.Contains(low, "funds") || strings.Contains(low, "payment"):
		return Result{Outcome: Fatal, Message: msg}
	case strings.Contains(low, "premium") || strings.Contains(low, "notsupported") || strings.Contains(low, "not supported"):
		return Result{Outcome: Fatal, Message: msg}
	case strings.Contains(low, "notavailable") || strings.Contains(low, "not available") || strings.Contains(low, "taken") || strings.Contains(low, "unavailable") || strings.Contains(low, "alreadyexists") || strings.Contains(low, "already"):
		return Result{Outcome: Unavailable, Message: msg}
	case e.Status == 422 || e.Status == 400:
		// validation errors (contact data, bad name) cannot be fixed by retrying
		return Result{Outcome: Fatal, Message: msg}
	case e.Status >= 500:
		return Result{Outcome: Retryable, Message: msg}
	}
	return Result{Outcome: Retryable, Message: msg}
}

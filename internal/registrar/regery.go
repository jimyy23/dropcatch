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

// Regery implements the Regery external API
// (https://regery.com/partnership/api/introduction).
//
//	base:     https://api.regery.com/ (test mode = a test API key, same URL)
//	auth:     Authorization: API_KEY:API_SECRET, Content-Type: application/json
//	check:    GET  /v1/domains/{domain}/availability
//	          result: available | notAvailable | internal | error | notSupported | restricted | rateLimit
//	premium:  GET  /v1/domains/{domain}/register-premium-price
//	contact:  POST /v1/contacts {details:{...}} -> {id} (idempotent)
//	register: POST /v1/domains/{domain} {period, contacts:{registrant}, nameservers, services, disclose}
//	          -> {pending: bool}; pending results arrive in the message queue
//	queue:    GET /v1/messages, DELETE /v1/messages/{id}
//	balance:  GET /v1/account/balance
//
// The docs do not describe error bodies or numeric rate limits; HTTP status
// codes are mapped conservatively (unknown failures are retryable).
type Regery struct {
	c    config.Regery
	ct   config.Contact
	base string
	http *http.Client
	dry  bool

	mu        sync.Mutex
	contactID string // registrant contact (configured or saved from REGISTRANT_*)
}

func NewRegery(c config.Regery, ct config.Contact, dry bool) *Regery {
	return &Regery{c: c, ct: ct, base: "https://api.regery.com", http: httpClient(60 * time.Second), dry: dry, contactID: c.ContactID}
}

func (r *Regery) Key() string           { return "regery" }
func (r *Regery) Label() string         { return "Regery" }
func (r *Regery) PriceKey() string      { return "regery" }
func (r *Regery) Configured() bool      { return r.c.APIKey != "" && r.c.APISecret != "" }
func (r *Regery) MinGap() time.Duration { return time.Second }

func (r *Regery) Problem() string {
	if r.c.ContactID == "" && !r.ct.Complete() {
		return "set REGERY_CONTACT_ID or the REGISTRANT_* contact"
	}
	return ""
}

// apiError carries the HTTP status and the (undocumented) body text.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("regery HTTP %d", e.Status)
	}
	return fmt.Sprintf("regery HTTP %d: %s", e.Status, e.Body)
}

func (r *Regery) do(ctx context.Context, method, path string, body any, out any) (http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", r.c.APIKey+":"+r.c.APISecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.Header, &apiError{Status: resp.StatusCode, Body: errText(raw)}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.Header, fmt.Errorf("regery: unexpected response: %s", trunc(string(raw), 200))
		}
	}
	return resp.Header, nil
}

// errText extracts a readable message from an undocumented error body.
func errText(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		var p []string
		for _, k := range []string{"Message", "message", "error", "Error", "title", "detail", "StatusCode", "ErrorType", "Code"} {
			if v, ok := m[k]; ok && v != nil && fmt.Sprint(v) != "" {
				p = append(p, fmt.Sprint(v))
			}
		}
		if len(p) > 0 {
			return trunc(strings.Join(p, " "), 300)
		}
	}
	return trunc(s, 300)
}

type regeryCheck struct {
	Domain  string `json:"domain"`
	Source  string `json:"source"`
	Result  string `json:"result"`
	Premium *bool  `json:"premium"`
}

func (r *Regery) Check(ctx context.Context, domain string) (Availability, error) {
	var c regeryCheck
	h, err := r.do(ctx, "GET", "/v1/domains/"+url.PathEscape(domain)+"/availability", nil, &c)
	if err != nil {
		if ae, ok := err.(*apiError); ok && ae.Status == 429 {
			return Availability{}, &RateError{Msg: ae.Error(), RetryAfter: retryAfter(h, 60*time.Second)}
		}
		return Availability{}, err
	}
	a := Availability{Premium: c.Premium != nil && *c.Premium, Detail: c.Source}
	switch c.Result {
	case "available":
		a.Available = true
		// "dns" answers are fast but can be false positives (held/hidden
		// domains); they still count, the monitor cross-checks them.
		return a, nil
	case "notAvailable", "internal", "restricted":
		a.Detail = strings.TrimSpace(c.Result + " " + c.Source)
		return a, nil
	case "notSupported":
		return Availability{}, ErrUnsupported
	case "rateLimit":
		return Availability{}, &RateError{Msg: "regery: rateLimit", RetryAfter: 60 * time.Second}
	}
	return Availability{}, fmt.Errorf("regery check: result %q", c.Result)
}

type regeryContactDetails struct {
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email"`
	CountryCode  string `json:"countryCode"`
	State        string `json:"state,omitempty"`
	City         string `json:"city"`
	Address1     string `json:"address1"`
	Address2     string `json:"address2,omitempty"`
	Zip          string `json:"zip"`
	PhoneNumber  string `json:"phoneNumber"`
}

// EnsureContact returns the registrant contact id, saving REGISTRANT_* via
// POST /v1/contacts when no REGERY_CONTACT_ID is configured. The call is
// idempotent on Regery's side (same fields -> same id).
func (r *Regery) EnsureContact(ctx context.Context) (string, error) {
	r.mu.Lock()
	id := r.contactID
	r.mu.Unlock()
	if id != "" {
		return id, nil
	}
	if !r.ct.Complete() {
		return "", fmt.Errorf("REGISTRANT_* contact incomplete")
	}
	d := regeryContactDetails{FirstName: r.ct.FirstName, LastName: r.ct.LastName, Organization: r.ct.Organization, Email: r.ct.Email,
		CountryCode: r.ct.Country, State: r.ct.State, City: r.ct.City, Address1: r.ct.Street, Address2: r.ct.Street2, Zip: r.ct.PostalCode, PhoneNumber: r.ct.Phone}
	var out struct {
		ID string `json:"id"`
	}
	if _, err := r.do(ctx, "POST", "/v1/contacts", map[string]any{"name": "dropcatch registrant", "details": d}, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("regery: contact saved without id")
	}
	r.mu.Lock()
	r.contactID = out.ID
	r.mu.Unlock()
	return out.ID, nil
}

// Balance returns the account balance (GET /v1/account/balance).
func (r *Regery) Balance(ctx context.Context) (float64, error) {
	var b float64
	_, err := r.do(ctx, "GET", "/v1/account/balance", nil, &b)
	return b, err
}

func (r *Regery) Register(ctx context.Context, domain string) Result {
	if r.dry {
		return Result{Outcome: DryRun, Message: "dry run: would POST /v1/domains/" + domain}
	}
	contact, err := r.EnsureContact(ctx)
	if err != nil {
		if ae, ok := err.(*apiError); ok && ae.Status >= 500 {
			return Result{Outcome: Retryable, Message: "saving contact: " + err.Error()}
		}
		return Result{Outcome: Fatal, Message: "saving contact: " + err.Error()}
	}
	body := map[string]any{"period": 1, "autoRenew": false, "contacts": map[string]any{"registrant": contact}}
	if len(r.c.Nameservers) > 0 {
		body["nameservers"] = map[string]any{"list": r.c.Nameservers}
	} else {
		body["nameservers"] = map[string]any{"provider": "basic"}
	}
	if len(r.c.Services) > 0 {
		body["contacts"].(map[string]any)["services"] = r.c.Services
	}
	var out struct {
		Pending bool `json:"pending"`
	}
	h, err := r.do(ctx, "POST", "/v1/domains/"+url.PathEscape(domain), body, &out)
	if err != nil {
		return regeryRegisterError(err, h)
	}
	if out.Pending {
		return Result{Outcome: Pending, Ref: domain, Message: "registration queued (result arrives in the Regery message queue)"}
	}
	return Result{Outcome: Success, Ref: domain, Message: "registered"}
}

// regeryRegisterError maps an undocumented error to an outcome.
func regeryRegisterError(err error, h http.Header) Result {
	ae, ok := err.(*apiError)
	if !ok {
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	low := strings.ToLower(ae.Body)
	switch {
	case ae.Status == 429 || strings.Contains(low, "too many requests") || strings.Contains(low, "ratelimit"):
		return Result{Outcome: RateLimited, Message: ae.Error(), RetryAfter: retryAfter(h, 60*time.Second)}
	case ae.Status == 401 || ae.Status == 403 || ae.Status == 402:
		return Result{Outcome: Fatal, Message: ae.Error()}
	case strings.Contains(low, "insufficient") || strings.Contains(low, "balance") || strings.Contains(low, "funds"):
		return Result{Outcome: Fatal, Message: ae.Error()}
	case strings.Contains(low, "premium") || strings.Contains(low, "not supported") || strings.Contains(low, "notsupported") || strings.Contains(low, "contact"):
		return Result{Outcome: Fatal, Message: ae.Error()}
	case strings.Contains(low, "not available") || strings.Contains(low, "notavailable") || strings.Contains(low, "unavailable") || strings.Contains(low, "taken") || ae.Status == 409:
		return Result{Outcome: Unavailable, Message: ae.Error()}
	case ae.Status == 404:
		// the API answers 404 for unknown routes and unauthenticated calls
		return Result{Outcome: Fatal, Message: ae.Error() + " (check REGERY_API_KEY / REGERY_API_SECRET and API access)"}
	}
	return Result{Outcome: Retryable, Message: ae.Error()}
}

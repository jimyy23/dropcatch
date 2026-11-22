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
//	base:     https://api.regery.com
//	auth:     Authorization: API_KEY:API_SECRET, Content-Type: application/json
//	          test keys start with "TST_" and only accept domain names that
//	          contain the account's test domain token (403 wrongApiKeyMode otherwise)
//	check:    GET  /v1/domains/{domain}/availability
//	          result: available | notAvailable | internal | error | notSupported | restricted | rateLimit
//	contact:  POST /v1/contacts {name, details:{...}} -> {id}
//	register: POST /v1/domains/{domain} {period, autoRenew, nameservers, contacts:{registrant}}
//	          -> {pending: bool}; pending results arrive in GET /v1/messages
//	balance:  GET  /v1/account/balance -> bare number
//
// Behaviour verified against the API with a test key (2026-11-22):
//   - errors are JSON {code, message, type[, parameter, value, rules]}; e.g.
//     400 validation valueRequired / valueInvalid, 401 (empty body) bad key,
//     403 apiGateway wrongApiKeyMode, 429 apiGateway rateLimit
//     ("Rate exceeded. [60/00:01:00] ... with cooldown: 00:20:00"),
//     500 domains objectExists ("domain 'x' already exists")
//   - registration requires the registrant state as a region code such as
//     US_NY / CA_ON ("ON" is accepted when saving the contact but rejected
//     when registering)
//   - saving a contact whose fields match an existing one returns the
//     existing id even when only the state differs, so the contact is saved
//     with a name derived from its data
//
// Rate limits (per key): domains.check 60/min and 1800/h, domains.register
// 10/min, contacts.save 60/min, account.balance 4/h and 12/day,
// messages.pick 60/min (and 1 per 20 min when the queue is empty).
type Regery struct {
	c    config.Regery
	ct   config.Contact
	base string
	http *http.Client
	dry  bool

	mu        sync.Mutex
	contactID string // registrant contact (configured or saved from REGISTRANT_*)
	balance   []Balance
	balanceAt time.Time
}

func NewRegery(c config.Regery, ct config.Contact, dry bool) *Regery {
	return &Regery{c: c, ct: ct, base: "https://api.regery.com", http: httpClient(60 * time.Second), dry: dry, contactID: c.ContactID}
}

func (r *Regery) Key() string      { return "regery" }
func (r *Regery) Label() string    { return "Regery" }
func (r *Regery) PriceKey() string { return "regery" }
func (r *Regery) Configured() bool { return r.c.APIKey != "" && r.c.APISecret != "" }

// MinGap keeps orders under domains.register 10/min.
func (r *Regery) MinGap() time.Duration { return 6500 * time.Millisecond }

// TestMode reports whether a Regery test key is configured.
func (r *Regery) TestMode() bool { return strings.HasPrefix(r.c.APIKey, "TST_") }

func (r *Regery) Problem() string {
	if r.c.ContactID == "" && !r.ct.Complete() {
		return "set REGERY_CONTACT_ID or the REGISTRANT_* contact"
	}
	if r.c.ContactID == "" && r.ct.State == "" {
		return "REGISTRANT_STATE is required by Regery (e.g. ON or NY)"
	}
	return ""
}

// apiError is a Regery error response.
type apiError struct {
	Status    int
	Code      string // e.g. valueRequired, wrongApiKeyMode, rateLimit, objectExists
	Type      string // e.g. validation, apiGateway, domains, notFound
	Message   string
	Parameter string
}

func (e *apiError) Error() string {
	s := fmt.Sprintf("regery HTTP %d", e.Status)
	if e.Type != "" || e.Code != "" {
		s += " " + strings.Trim(e.Type+"/"+e.Code, "/")
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
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
		e := &apiError{Status: resp.StatusCode}
		var p struct {
			Code      string `json:"code"`
			Type      string `json:"type"`
			Message   string `json:"message"`
			Parameter string `json:"parameter"`
		}
		if json.Unmarshal(raw, &p) == nil {
			e.Code, e.Type, e.Message, e.Parameter = p.Code, p.Type, p.Message, p.Parameter
		} else {
			e.Message = trunc(string(raw), 200)
		}
		if resp.StatusCode == 401 && e.Message == "" {
			e.Message = "invalid API key or secret"
		}
		return resp.Header, e
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 && string(bytes.TrimSpace(raw)) != "null" {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.Header, fmt.Errorf("regery: unexpected response: %s", trunc(string(raw), 200))
		}
	}
	return resp.Header, nil
}

// rateLimitWait reads the cooldown from messages such as
// "Rate exceeded. [60/00:01:00] OR [empty: 1/00:20:00] with cooldown: 00:20:00".
func rateLimitWait(e *apiError, h http.Header) time.Duration {
	if i := strings.Index(e.Message, "cooldown:"); i >= 0 {
		var hh, mm, ss int
		if _, err := fmt.Sscanf(strings.TrimSpace(e.Message[i+len("cooldown:"):]), "%d:%d:%d", &hh, &mm, &ss); err == nil {
			if d := time.Duration(hh)*time.Hour + time.Duration(mm)*time.Minute + time.Duration(ss)*time.Second; d > 0 {
				return d
			}
		}
	}
	return retryAfter(h, 60*time.Second)
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
		if ae, ok := err.(*apiError); ok {
			switch {
			case ae.Status == 429 || ae.Code == "rateLimit":
				return Availability{}, &RateError{Msg: ae.Error(), RetryAfter: rateLimitWait(ae, h)}
			case ae.Code == "wrongApiKeyMode":
				// a test key cannot check real names: this source does not cover them
				return Availability{}, ErrUnsupported
			}
		}
		return Availability{}, err
	}
	a := Availability{Premium: c.Premium != nil && *c.Premium, Detail: c.Source}
	switch c.Result {
	case "available":
		// "dns" answers are fast but can be false positives (held/hidden
		// domains); they still count, the monitor cross-checks them.
		a.Available = true
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

// regionCode converts a state to Regery's region format: "ON" + "CA" ->
// "CA_ON"; values already in COUNTRY_REGION form are kept.
func regionCode(country, state string) string {
	state = strings.ToUpper(strings.TrimSpace(state))
	country = strings.ToUpper(strings.TrimSpace(country))
	if state == "" || strings.HasPrefix(state, country+"_") {
		return state
	}
	return country + "_" + state
}

// contactDetails builds the registrant from REGISTRANT_*. In test mode the
// documented "test phone number" (REGERY_TEST_PHONE) replaces the phone.
func (r *Regery) contactDetails() regeryContactDetails {
	phone := r.ct.Phone
	if r.TestMode() && r.c.TestPhone != "" {
		phone = r.c.TestPhone
	}
	return regeryContactDetails{FirstName: r.ct.FirstName, LastName: r.ct.LastName, Organization: r.ct.Organization, Email: r.ct.Email,
		CountryCode: strings.ToUpper(r.ct.Country), State: regionCode(r.ct.Country, r.ct.State), City: r.ct.City,
		Address1: r.ct.Street, Address2: r.ct.Street2, Zip: r.ct.PostalCode, PhoneNumber: phone}
}

// EnsureContact returns the registrant contact id: REGERY_CONTACT_ID, or
// REGISTRANT_* saved via POST /v1/contacts. The name encodes the region and
// phone so a changed state never reuses an older contact without it.
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
	d := r.contactDetails()
	name := "dropcatch " + d.CountryCode + " " + d.State + " " + d.PhoneNumber
	var out struct {
		ID string `json:"id"`
	}
	if _, err := r.do(ctx, "POST", "/v1/contacts", map[string]any{"name": name, "details": d}, &out); err != nil {
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

// Contact reads a contact (GET /v1/contacts/{id}).
func (r *Regery) Contact(ctx context.Context, id string) (map[string]any, error) {
	var out struct {
		Details map[string]any `json:"details"`
	}
	_, err := r.do(ctx, "GET", "/v1/contacts/"+url.PathEscape(id), nil, &out)
	return out.Details, err
}

// Balances reads GET /v1/account/balance. The endpoint allows only 4 calls
// per hour (12 per day), so the value is cached for 20 minutes.
func (r *Regery) Balances(ctx context.Context) ([]Balance, error) {
	r.mu.Lock()
	if r.balance != nil && time.Since(r.balanceAt) < 20*time.Minute {
		b := r.balance
		r.mu.Unlock()
		return b, nil
	}
	r.mu.Unlock()
	var b json.Number
	if _, err := r.do(ctx, "GET", "/v1/account/balance", nil, &b); err != nil {
		return nil, err
	}
	f, err := b.Float64()
	if err != nil {
		return nil, fmt.Errorf("regery: bad balance %q", b)
	}
	note := "cached 20 min (API limit 4/hour)"
	if r.TestMode() {
		note = "TEST key; " + note
	}
	out := []Balance{{Amount: fmt.Sprintf("%.2f", f), Currency: "USD", Note: note}}
	r.mu.Lock()
	r.balance, r.balanceAt = out, time.Now()
	r.mu.Unlock()
	return out, nil
}

// Message is one entry of the Regery message queue.
type RegeryMessage struct {
	ID      int64  `json:"id"`
	Created string `json:"created"`
	Data    struct {
		Type      string          `json:"type"`
		Operation string          `json:"operation"`
		Domain    string          `json:"domain"`
		Success   bool            `json:"success"`
		Error     json.RawMessage `json:"error"`
	} `json:"data"`
}

// NextMessage reads the first queued message (nil when the queue is empty).
// Note the limit: one call per 20 minutes when the queue is empty.
func (r *Regery) NextMessage(ctx context.Context) (*RegeryMessage, error) {
	var m *RegeryMessage
	if _, err := r.do(ctx, "GET", "/v1/messages", nil, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// AckMessage removes a message from the queue.
func (r *Regery) AckMessage(ctx context.Context, id int64) error {
	_, err := r.do(ctx, "DELETE", fmt.Sprintf("/v1/messages/%d", id), nil, nil)
	return err
}

func (r *Regery) Register(ctx context.Context, domain string) Result {
	if r.dry {
		return Result{Outcome: DryRun, Message: "dry run: would POST /v1/domains/" + domain}
	}
	contact, err := r.EnsureContact(ctx)
	if err != nil {
		res := regeryRegisterError(err, nil)
		res.Message = "saving contact: " + res.Message
		if res.Outcome == Unavailable {
			res.Outcome = Fatal
		}
		return res
	}
	contacts := map[string]any{"registrant": contact}
	if len(r.c.Services) > 0 {
		contacts["services"] = r.c.Services
	}
	body := map[string]any{"period": 1, "autoRenew": false, "contacts": contacts}
	if len(r.c.Nameservers) > 0 {
		body["nameservers"] = map[string]any{"list": r.c.Nameservers}
	} else {
		body["nameservers"] = map[string]any{"provider": "basic"}
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

// regeryRegisterError maps an error to an outcome using the observed codes.
func regeryRegisterError(err error, h http.Header) Result {
	ae, ok := err.(*apiError)
	if !ok {
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	msg := ae.Error()
	low := strings.ToLower(ae.Code + " " + ae.Message)
	switch {
	case ae.Status == 429 || ae.Code == "rateLimit":
		return Result{Outcome: RateLimited, Message: msg, RetryAfter: rateLimitWait(ae, h)}
	case ae.Code == "objectExists" || strings.Contains(low, "already exists"):
		// the domain exists in the registry (possibly already ours): never retried as an error
		return Result{Outcome: Unavailable, Message: msg}
	case ae.Code == "wrongApiKeyMode":
		return Result{Outcome: Fatal, Message: msg + " (a TST_ key only accepts names containing the test domain token)"}
	case ae.Status == 401 || ae.Status == 403 || ae.Status == 402:
		return Result{Outcome: Fatal, Message: msg}
	case ae.Type == "validation":
		// contact data or parameters: retrying cannot help
		return Result{Outcome: Fatal, Message: msg}
	case strings.Contains(low, "insufficient") || strings.Contains(low, "balance") || strings.Contains(low, "funds"):
		return Result{Outcome: Fatal, Message: msg}
	case strings.Contains(low, "premium") || strings.Contains(low, "notsupported") || strings.Contains(low, "not supported"):
		return Result{Outcome: Fatal, Message: msg}
	case strings.Contains(low, "notavailable") || strings.Contains(low, "not available") || strings.Contains(low, "unavailable") || strings.Contains(low, "taken") || ae.Status == 409:
		return Result{Outcome: Unavailable, Message: msg}
	case ae.Status == 404:
		return Result{Outcome: Fatal, Message: msg + " (check REGERY_API_KEY / REGERY_API_SECRET and API access)"}
	}
	return Result{Outcome: Retryable, Message: msg}
}

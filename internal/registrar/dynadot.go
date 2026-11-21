package registrar

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dropcatch/internal/config"
)

// Dynadot implements the Dynadot RESTful API v2
// (https://www.dynadot.com/domain/api-document).
//
//	search:   GET  /restful/v2/domains/{domain}/search   (Bearer key)
//	register: POST /restful/v2/domains/{domain}/register (Bearer key + X-Signature)
//
// X-Signature = base64(HMAC-SHA256(secret, apiKey\nfullPathAndQuery\nxRequestId\nbody)).
// Orders are paid from the account balance (402 "Insufficient funds.").
// Rate limits depend on the account price level (Regular: 1 thread, 1 req/s).
type Dynadot struct {
	c    config.Dynadot
	ct   config.Contact
	base string
	http *http.Client
	dry  bool
}

func NewDynadot(c config.Dynadot, ct config.Contact, dry bool) *Dynadot {
	base := "https://api.dynadot.com"
	if c.Sandbox {
		base = "https://api-sandbox.dynadot.com"
	}
	return &Dynadot{c: c, ct: ct, base: base, http: httpClient(30 * time.Second), dry: dry}
}

func (d *Dynadot) Key() string           { return "dynadot" }
func (d *Dynadot) Label() string         { return "Dynadot" }
func (d *Dynadot) PriceKey() string      { return "dynadot" }
func (d *Dynadot) Configured() bool      { return d.c.APIKey != "" && d.c.APISecret != "" }
func (d *Dynadot) MinGap() time.Duration { return time.Second }

func (d *Dynadot) Problem() string {
	if d.c.ContactID == "" && !d.ct.Complete() {
		return "set DYNADOT_CONTACT_ID or the REGISTRANT_* contact"
	}
	return ""
}

type dynEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
	Error   struct {
		Description string `json:"description"`
	} `json:"error"`
}

func uuid4() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (d *Dynadot) do(ctx context.Context, method, pathQuery string, body []byte, sign bool) (int, http.Header, *dynEnvelope, error) {
	req, err := http.NewRequestWithContext(ctx, method, d.base+pathQuery, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	reqID := uuid4()
	req.Header.Set("Authorization", "Bearer "+d.c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Request-ID", reqID)
	if sign {
		msg := d.c.APIKey + "\n" + pathQuery + "\n" + reqID + "\n" + string(body)
		m := hmac.New(sha256.New, []byte(d.c.APISecret))
		m.Write([]byte(msg))
		req.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(m.Sum(nil)))
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var env dynEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return resp.StatusCode, resp.Header, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(raw), 200))
	}
	if env.Code == 0 {
		env.Code = resp.StatusCode
	}
	return resp.StatusCode, resp.Header, &env, nil
}

// lenientBool accepts true/false and "yes"/"no" strings (the docs show both).
type lenientBool bool

func (b *lenientBool) UnmarshalJSON(p []byte) error {
	s := strings.ToLower(strings.Trim(string(p), `"`))
	*b = lenientBool(s == "true" || s == "yes" || s == "1")
	return nil
}

func (d *Dynadot) Check(ctx context.Context, domain string) (Availability, error) {
	pq := "/restful/v2/domains/" + url.PathEscape(domain) + "/search?show_price=true&currency=" + url.QueryEscape(d.c.Currency)
	code, h, env, err := d.do(ctx, "GET", pq, nil, false)
	if err != nil {
		return Availability{}, err
	}
	if env.Code == 429 || code == 429 {
		return Availability{}, &RateError{Msg: "dynadot: " + env.Error.Description, RetryAfter: retryAfter(h, 60*time.Second)}
	}
	if env.Code != 200 {
		if strings.Contains(env.Error.Description, "Unsupported domain type") {
			return Availability{}, ErrUnsupported
		}
		return Availability{}, fmt.Errorf("dynadot %d: %s", env.Code, env.Error.Description)
	}
	var r struct {
		Available lenientBool `json:"available"`
		Premium   string      `json:"premium"`
		PriceList []struct {
			Unit              string `json:"unit"`
			Currency          string `json:"currency"`
			RegistrationPrice string `json:"registration_price"`
		} `json:"price_list"`
	}
	if err := json.Unmarshal(env.Data, &r); err != nil {
		return Availability{}, fmt.Errorf("dynadot: bad search data")
	}
	a := Availability{Available: bool(r.Available), Premium: strings.EqualFold(r.Premium, "yes")}
	if len(r.PriceList) > 0 {
		a.Price = r.PriceList[0].RegistrationPrice + " " + r.PriceList[0].Currency
	}
	return a, nil
}

type dynContact struct {
	Organization string `json:"organization,omitempty"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	PhoneNumber  string `json:"phone_number"`
	PhoneCC      string `json:"phone_cc"`
	Address1     string `json:"address1"`
	Address2     string `json:"address2,omitempty"`
	City         string `json:"city"`
	State        string `json:"state,omitempty"`
	Zip          string `json:"zip"`
	Country      string `json:"country"`
}

// splitPhone turns "+1.5555555555" into ("1", "5555555555").
func splitPhone(p string) (string, string) {
	p = strings.TrimPrefix(strings.TrimSpace(p), "+")
	if cc, num, ok := strings.Cut(p, "."); ok {
		return cc, num
	}
	return "", p
}

func (d *Dynadot) Register(ctx context.Context, domain string) Result {
	dom := map[string]any{"duration": 1}
	if d.c.Privacy != "" {
		dom["privacy"] = d.c.Privacy
	}
	if d.c.ContactID != "" {
		id, _ := strconv.ParseInt(d.c.ContactID, 10, 64)
		for _, k := range []string{"registrant_contact_id", "admin_contact_id", "tech_contact_id", "billing_contact_id"} {
			dom[k] = id
		}
	} else {
		cc, num := splitPhone(d.ct.Phone)
		c := dynContact{Organization: d.ct.Organization, Name: d.ct.FirstName + " " + d.ct.LastName, Email: d.ct.Email, PhoneNumber: num, PhoneCC: cc,
			Address1: d.ct.Street, Address2: d.ct.Street2, City: d.ct.City, State: d.ct.State, Zip: d.ct.PostalCode, Country: d.ct.Country}
		for _, k := range []string{"registrant_contact", "admin_contact", "tech_contact", "billing_contact"} {
			dom[k] = c
		}
	}
	body, _ := json.Marshal(map[string]any{"domain": dom, "currency": d.c.Currency, "register_premium": false})
	if d.dry {
		return Result{Outcome: DryRun, Message: "dry run: would POST /restful/v2/domains/" + domain + "/register"}
	}
	code, h, env, err := d.do(ctx, "POST", "/restful/v2/domains/"+url.PathEscape(domain)+"/register", body, true)
	if err != nil {
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	msg := env.Error.Description
	switch env.Code {
	case 200, 201:
		var r struct {
			DomainName string `json:"domain_name"`
		}
		json.Unmarshal(env.Data, &r)
		return Result{Outcome: Success, Ref: r.DomainName, Message: "registered"}
	case 202:
		return Result{Outcome: Pending, Message: "accepted"}
	case 429:
		return Result{Outcome: RateLimited, Message: msg, RetryAfter: retryAfter(h, 60*time.Second)}
	case 409:
		low := strings.ToLower(msg)
		switch {
		case strings.Contains(low, "premium"), strings.Contains(low, "trademark"), strings.Contains(low, "already owned by your account"), strings.Contains(low, "coupon"):
			if strings.Contains(low, "already owned by your account") {
				return Result{Outcome: Success, Message: msg}
			}
			return Result{Outcome: Fatal, Message: msg}
		case strings.Contains(low, "cannot process"):
			return Result{Outcome: Retryable, Message: msg}
		}
		return Result{Outcome: Unavailable, Message: msg}
	case 402, 401, 403, 404:
		return Result{Outcome: Fatal, Message: msg}
	case 400:
		if strings.Contains(msg, "not supported") || strings.Contains(msg, "Could not parse") || strings.Contains(msg, "invalid") || strings.Contains(msg, "minimum registration period") {
			return Result{Outcome: Fatal, Message: msg}
		}
		return Result{Outcome: Retryable, Message: msg}
	case 500:
		if strings.Contains(msg, "order created") {
			return Result{Outcome: Pending, Message: msg}
		}
		return Result{Outcome: Retryable, Message: msg}
	}
	return Result{Outcome: classifyHTTP(code), Message: fmt.Sprintf("HTTP %d %s", env.Code, msg)}
}

package registrar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"dropcatch/internal/config"
)

// Porkbun implements Porkbun API v3 (https://porkbun.com/api/json/v3/documentation).
//
//	check:  POST /domain/checkDomain/{domain}   (default 10 checks / 10 s / account)
//	create: POST /domain/create/{domain}        {cost (cents), agreeToTerms:"yes"}
//
// Registration is paid from prepaid credit; cost must equal the current price
// of the minimum duration in pennies (COST_MISMATCH otherwise). Premium
// domains cannot be registered via the API. Default attempt limit: 1/s.
type Porkbun struct {
	c    config.Porkbun
	base string
	http *http.Client
	dry  bool
}

func NewPorkbun(c config.Porkbun, dry bool) *Porkbun {
	return &Porkbun{c: c, base: "https://api.porkbun.com/api/json/v3", http: httpClient(30 * time.Second), dry: dry}
}

func (p *Porkbun) Key() string           { return "porkbun" }
func (p *Porkbun) Label() string         { return "Porkbun" }
func (p *Porkbun) PriceKey() string      { return "porkbun" }
func (p *Porkbun) Configured() bool      { return p.c.APIKey != "" && p.c.SecretKey != "" }
func (p *Porkbun) Problem() string       { return "" }
func (p *Porkbun) MinGap() time.Duration { return 1100 * time.Millisecond }

type pbResp struct {
	Status     string          `json:"status"`
	Message    string          `json:"message"`
	Code       string          `json:"code"`
	Response   json.RawMessage `json:"response"`
	OrderID    json.Number     `json:"orderId"`
	Cost       json.Number     `json:"cost"`
	RetryAfter json.Number     `json:"retryAfter"`
	TTL        json.Number     `json:"ttlRemaining"`
	DryRun     bool            `json:"dryRun"`
	Would      bool            `json:"wouldSucceed"`
}

func (p *Porkbun) post(ctx context.Context, path string, body map[string]any, idem string) (int, http.Header, *pbResp, error) {
	if body == nil {
		body = map[string]any{}
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", p.base+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.c.APIKey)
	req.Header.Set("X-Secret-API-Key", p.c.SecretKey)
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r pbResp
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&r); err != nil {
		return resp.StatusCode, resp.Header, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(raw), 200))
	}
	return resp.StatusCode, resp.Header, &r, nil
}

func (r *pbResp) retry(h http.Header) time.Duration {
	for _, n := range []json.Number{r.RetryAfter, r.TTL} {
		if v, err := n.Int64(); err == nil && v > 0 {
			return time.Duration(v) * time.Second
		}
	}
	return retryAfter(h, 10*time.Second)
}

type pbCheck struct {
	Avail   string `json:"avail"`
	Price   string `json:"price"`
	Premium string `json:"premium"`
}

func (p *Porkbun) check(ctx context.Context, domain string) (*pbCheck, error) {
	code, h, r, err := p.post(ctx, "/domain/checkDomain/"+url.PathEscape(domain), nil, "")
	if err != nil {
		return nil, err
	}
	if r.Status != "SUCCESS" {
		if code == 429 || r.Code == "RATE_LIMIT_EXCEEDED" {
			return nil, &RateError{Msg: "porkbun: " + r.Message, RetryAfter: r.retry(h)}
		}
		if r.Code == "INVALID_TLD" || r.Code == "TLD_NOT_SUPPORTED" || strings.Contains(strings.ToLower(r.Message), "not supported") {
			return nil, ErrUnsupported
		}
		return nil, fmt.Errorf("porkbun %s: %s", r.Code, r.Message)
	}
	var c pbCheck
	if err := json.Unmarshal(r.Response, &c); err != nil {
		return nil, fmt.Errorf("porkbun: bad check response")
	}
	return &c, nil
}

func (p *Porkbun) Check(ctx context.Context, domain string) (Availability, error) {
	c, err := p.check(ctx, domain)
	if err != nil {
		return Availability{}, err
	}
	return Availability{Available: c.Avail == "yes", Premium: c.Premium == "yes", Price: c.Price + " USD"}, nil
}

func cents(price string) (int64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(price), 64)
	if err != nil || f <= 0 {
		return 0, false
	}
	return int64(math.Round(f * 100)), true
}

// quote asks for the exact price via dryRun with cost 0 (does not consume the
// create budget). Falls back to the check price.
func (p *Porkbun) quote(ctx context.Context, domain string) (int64, *Result) {
	_, h, r, err := p.post(ctx, "/domain/create/"+url.PathEscape(domain), map[string]any{"cost": 0, "agreeToTerms": "yes", "dryRun": true}, "")
	if err == nil && r.Status == "SUCCESS" {
		if c, err := r.Cost.Int64(); err == nil && c > 0 {
			return c, nil
		}
	}
	if err == nil && r.Status != "SUCCESS" {
		if res := p.classify(r, h); res.Outcome != Retryable {
			return 0, &res
		}
	}
	c, err := p.check(ctx, domain)
	if err != nil {
		if re, ok := err.(*RateError); ok {
			return 0, &Result{Outcome: RateLimited, Message: re.Msg, RetryAfter: re.RetryAfter}
		}
		return 0, &Result{Outcome: Retryable, Message: err.Error()}
	}
	if c.Avail != "yes" {
		return 0, &Result{Outcome: Unavailable, Message: "porkbun check: not available"}
	}
	if c.Premium == "yes" {
		return 0, &Result{Outcome: Fatal, Message: "premium domains cannot be registered via the Porkbun API"}
	}
	n, ok := cents(c.Price)
	if !ok {
		return 0, &Result{Outcome: Retryable, Message: "porkbun: no price"}
	}
	return n, nil
}

func (p *Porkbun) classify(r *pbResp, h http.Header) Result {
	msg := strings.TrimSpace(r.Code + " " + r.Message)
	switch r.Code {
	case "RATE_LIMIT_EXCEEDED":
		return Result{Outcome: RateLimited, Message: msg, RetryAfter: r.retry(h)}
	case "DOMAIN_NOT_AVAILABLE":
		return Result{Outcome: Unavailable, Message: msg}
	case "COST_MISMATCH":
		return Result{Outcome: Retryable, Message: msg}
	case "INSUFFICIENT_FUNDS", "VERIFICATION_REQUIRED", "ACCOUNT_VERIFICATION_REQUIRED", "TERMS_NOT_AGREED", "ORDER_TOO_LARGE",
		"MONTHLY_SPEND_LIMIT_EXCEEDED", "PAYMENT_REQUIRED", "INVALID_DOMAIN", "INVALID_TLD", "INVALID_API_KEYS", "UNAUTHORIZED", "FORBIDDEN":
		return Result{Outcome: Fatal, Message: msg}
	}
	low := strings.ToLower(r.Message)
	switch {
	case strings.Contains(low, "premium"):
		return Result{Outcome: Fatal, Message: msg}
	case strings.Contains(low, "not available"), strings.Contains(low, "unavailable"):
		return Result{Outcome: Unavailable, Message: msg}
	case strings.Contains(low, "api key"), strings.Contains(low, "scope"):
		return Result{Outcome: Fatal, Message: msg}
	}
	return Result{Outcome: Retryable, Message: msg}
}

func (p *Porkbun) Register(ctx context.Context, domain string) Result {
	cost, res := p.quote(ctx, domain)
	if res != nil {
		return *res
	}
	body := map[string]any{"cost": cost, "agreeToTerms": "yes", "whoisPrivacy": p.c.WhoisPrivacy}
	if p.dry {
		body["dryRun"] = true
	}
	// one idempotency key per (domain, price, minute): retries of the same
	// HTTP request replay instead of double-ordering
	idem := fmt.Sprintf("dropcatch-%s-%d-%d", domain, cost, time.Now().Unix()/60)
	code, h, r, err := p.post(ctx, "/domain/create/"+url.PathEscape(domain), body, idem)
	if err != nil {
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	price := fmt.Sprintf("%.2f USD", float64(cost)/100)
	if r.Status == "SUCCESS" {
		if r.DryRun {
			o := Result{Outcome: DryRun, Price: price, Message: "dry run: wouldSucceed=" + strconv.FormatBool(r.Would)}
			if !r.Would {
				o.Message += " " + r.Message
			}
			return o
		}
		return Result{Outcome: Success, Ref: r.OrderID.String(), Price: price, Message: "registered"}
	}
	if code == 429 {
		return Result{Outcome: RateLimited, Message: r.Message, RetryAfter: r.retry(h)}
	}
	out := p.classify(r, h)
	out.Price = price
	return out
}

// Balances reads GET /account/balance (balance in cents).
func (p *Porkbun) Balances(ctx context.Context) ([]Balance, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.base+"/account/balance", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", p.c.APIKey)
	req.Header.Set("X-Secret-API-Key", p.c.SecretKey)
	req.Header.Set("Accept", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		Status  string      `json:"status"`
		Message string      `json:"message"`
		Balance json.Number `json:"balance"`
		Display string      `json:"display"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("porkbun balance HTTP %d", resp.StatusCode)
	}
	if r.Status != "SUCCESS" {
		return nil, fmt.Errorf("porkbun: %s", r.Message)
	}
	c, _ := r.Balance.Int64()
	return []Balance{{Amount: fmt.Sprintf("%.2f", float64(c)/100), Currency: "USD", Note: r.Display}}, nil
}

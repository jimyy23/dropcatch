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
	"time"

	"dropcatch/internal/config"
)

// Cloudflare implements the Cloudflare Registrar API (beta)
// (https://developers.cloudflare.com/registrar/registrar-api/).
//
//	check:    POST /accounts/{id}/registrar/domain-check   {"domains":[...]}  (real-time)
//	register: POST /accounts/{id}/registrar/registrations  {"domain_name":...}
//	          201 = completed, 202 = in progress (poll links.self)
//
// Charged to the account's default payment method; the default registrant
// contact must exist in the dashboard. Premium domains cannot be registered
// via the API. Global limit 1200 requests / 5 min.
type Cloudflare struct {
	c    config.Cloudflare
	base string
	http *http.Client
	dry  bool
}

func NewCloudflare(c config.Cloudflare, dry bool) *Cloudflare {
	return &Cloudflare{c: c, base: "https://api.cloudflare.com/client/v4", http: httpClient(30 * time.Second), dry: dry}
}

func (f *Cloudflare) Key() string           { return "cloudflare" }
func (f *Cloudflare) Label() string         { return "Cloudflare" }
func (f *Cloudflare) PriceKey() string      { return "cloudflare" }
func (f *Cloudflare) Configured() bool      { return f.c.APIToken != "" && f.c.AccountID != "" }
func (f *Cloudflare) Problem() string       { return "" }
func (f *Cloudflare) MinGap() time.Duration { return time.Second }

type cfEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (e *cfEnvelope) errMsg() string {
	var p []string
	for _, x := range e.Errors {
		p = append(p, fmt.Sprintf("%d %s", x.Code, x.Message))
	}
	return strings.Join(p, "; ")
}

func (f *Cloudflare) do(ctx context.Context, method, path string, body any, async bool) (int, http.Header, *cfEnvelope, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.base+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+f.c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	if async {
		req.Header.Set("Prefer", "respond-async")
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return resp.StatusCode, resp.Header, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(raw), 200))
	}
	return resp.StatusCode, resp.Header, &env, nil
}

type cfDomain struct {
	Name        string `json:"name"`
	Registrable bool   `json:"registrable"`
	Tier        string `json:"tier"`
	Reason      string `json:"reason"`
	Pricing     *struct {
		Currency         string `json:"currency"`
		RegistrationCost string `json:"registration_cost"`
	} `json:"pricing"`
}

func (f *Cloudflare) Check(ctx context.Context, domain string) (Availability, error) {
	code, h, env, err := f.do(ctx, "POST", "/accounts/"+url.PathEscape(f.c.AccountID)+"/registrar/domain-check", map[string]any{"domains": []string{domain}}, false)
	if err != nil {
		return Availability{}, err
	}
	if code == 429 {
		return Availability{}, &RateError{Msg: "cloudflare: rate limited", RetryAfter: retryAfter(h, 60*time.Second)}
	}
	if !env.Success {
		for _, e := range env.Errors {
			if e.Code == 1008 {
				return Availability{}, ErrUnsupported
			}
		}
		return Availability{}, fmt.Errorf("cloudflare: %s", env.errMsg())
	}
	var r struct {
		Domains []cfDomain `json:"domains"`
	}
	if err := json.Unmarshal(env.Result, &r); err != nil || len(r.Domains) == 0 {
		return Availability{}, fmt.Errorf("cloudflare: empty check result")
	}
	d := r.Domains[0]
	switch d.Reason {
	case "extension_not_supported_via_api", "extension_not_supported", "extension_disallows_registration":
		return Availability{}, ErrUnsupported
	}
	a := Availability{Available: d.Registrable || d.Reason == "domain_premium", Premium: d.Tier == "premium" || d.Reason == "domain_premium", Detail: d.Reason}
	if d.Pricing != nil {
		a.Price = d.Pricing.RegistrationCost + " " + d.Pricing.Currency
	}
	return a, nil
}

type cfWorkflow struct {
	Completed bool   `json:"completed"`
	State     string `json:"state"`
	Context   struct {
		Action string `json:"action"`
	} `json:"context"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}

func (f *Cloudflare) Register(ctx context.Context, domain string) Result {
	if f.dry {
		return Result{Outcome: DryRun, Message: "dry run: would POST /registrar/registrations for " + domain}
	}
	code, h, env, err := f.do(ctx, "POST", "/accounts/"+url.PathEscape(f.c.AccountID)+"/registrar/registrations", map[string]any{"domain_name": domain}, false)
	if err != nil {
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	if code == 429 {
		return Result{Outcome: RateLimited, Message: "rate limited", RetryAfter: retryAfter(h, 60*time.Second)}
	}
	if !env.Success || (code != 200 && code != 201 && code != 202) {
		msg := env.errMsg()
		low := strings.ToLower(msg)
		switch {
		case strings.Contains(low, "domain limit"), strings.Contains(low, "registrant contact"), strings.Contains(low, "not supported"), code == 401, code == 403:
			return Result{Outcome: Fatal, Message: msg}
		case strings.Contains(low, "unavailable"), strings.Contains(low, "not available"), strings.Contains(low, "not registrable"):
			return Result{Outcome: Unavailable, Message: msg}
		}
		if code >= 500 {
			return Result{Outcome: Retryable, Message: msg}
		}
		return Result{Outcome: Unavailable, Message: fmt.Sprintf("HTTP %d %s", code, msg)}
	}
	var wf cfWorkflow
	json.Unmarshal(env.Result, &wf)
	return f.workflowResult(ctx, &wf)
}

func (f *Cloudflare) workflowResult(ctx context.Context, wf *cfWorkflow) Result {
	// poll briefly; the drop-catch loop keeps going with other registrars
	for i := 0; i < 6 && !wf.Completed && (wf.State == "pending" || wf.State == "in_progress") && wf.Links.Self != ""; i++ {
		select {
		case <-ctx.Done():
			return Result{Outcome: Pending, Ref: wf.Links.Self, Message: "registration " + wf.State}
		case <-time.After(time.Duration(2+i) * time.Second):
		}
		_, _, env, err := f.do(ctx, "GET", wf.Links.Self, nil, false)
		if err != nil || !env.Success {
			break
		}
		json.Unmarshal(env.Result, wf)
	}
	switch wf.State {
	case "succeeded":
		return Result{Outcome: Success, Ref: wf.Links.Self, Message: "registered"}
	case "failed":
		m := "failed"
		if wf.Error != nil {
			m = wf.Error.Code + ": " + wf.Error.Message
		}
		return Result{Outcome: Unavailable, Ref: wf.Links.Self, Message: m}
	case "action_required":
		return Result{Outcome: Pending, Ref: wf.Links.Self, Message: "action required: " + wf.Context.Action}
	}
	return Result{Outcome: Pending, Ref: wf.Links.Self, Message: "registration " + wf.State}
}

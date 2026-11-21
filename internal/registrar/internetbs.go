package registrar

import (
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

// InternetBS implements the Internet.bs API (https://internetbs.net/internet-bs-api.pdf).
//
//	check:  /Domain/Check  (free; STATUS=AVAILABLE|UNAVAILABLE|FAILURE)
//	create: /Domain/Create (STATUS=SUCCESS|PENDING|FAILURE; debited from prepaid balance)
//
// Auth is ApiKey+Password on every request; the API key is bound to the
// caller IP. Contacts come from CloneContactsFromDomain or the REGISTRANT_*
// contact (used for Registrant, Admin, Technical and Billing).
type InternetBS struct {
	c    config.InternetBS
	ct   config.Contact
	base string
	http *http.Client
	dry  bool
}

func NewInternetBS(c config.InternetBS, ct config.Contact, dry bool) *InternetBS {
	base := "https://api.internet.bs"
	if c.Test {
		base = "https://testapi.internet.bs"
	}
	return &InternetBS{c: c, ct: ct, base: base, http: httpClient(60 * time.Second), dry: dry}
}

func (b *InternetBS) Key() string           { return "internetbs" }
func (b *InternetBS) Label() string         { return "Internet.bs" }
func (b *InternetBS) PriceKey() string      { return "internetbs" }
func (b *InternetBS) Configured() bool      { return b.c.APIKey != "" && b.c.Password != "" }
func (b *InternetBS) MinGap() time.Duration { return time.Second }

func (b *InternetBS) Problem() string {
	if b.c.CloneContactsFrom == "" && !b.ct.Complete() {
		return "set INTERNETBS_CLONE_CONTACTS_FROM or the REGISTRANT_* contact"
	}
	return ""
}

func (b *InternetBS) call(ctx context.Context, cmd string, p url.Values) (int, map[string]string, error) {
	p.Set("ApiKey", b.c.APIKey)
	p.Set("Password", b.c.Password)
	p.Set("ResponseFormat", "JSON")
	req, err := http.NewRequestWithContext(ctx, "POST", b.base+cmd, strings.NewReader(p.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// JSON keys are case-insensitive in practice; normalise to lowercase strings
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(raw), 200))
	}
	out := map[string]string{}
	for k, v := range m {
		out[strings.ToLower(k)] = fmt.Sprint(v)
	}
	return resp.StatusCode, out, nil
}

func (b *InternetBS) Check(ctx context.Context, domain string) (Availability, error) {
	_, m, err := b.call(ctx, "/Domain/Check", url.Values{"Domain": {domain}})
	if err != nil {
		return Availability{}, err
	}
	switch strings.ToUpper(m["status"]) {
	case "AVAILABLE":
		return Availability{Available: true}, nil
	case "UNAVAILABLE":
		return Availability{Available: false}, nil
	}
	msg := m["message"]
	if strings.Contains(strings.ToLower(msg), "not supported") || strings.Contains(strings.ToLower(msg), "invalid extension") {
		return Availability{}, ErrUnsupported
	}
	return Availability{}, fmt.Errorf("internet.bs: %s %s", m["status"], msg)
}

func (b *InternetBS) Register(ctx context.Context, domain string) Result {
	p := url.Values{"Domain": {domain}, "Period": {"1Y"}}
	if b.c.PrivateWhois != "" {
		p.Set("privateWhois", b.c.PrivateWhois)
	}
	if b.c.CloneContactsFrom != "" {
		p.Set("CloneContactsFromDomain", b.c.CloneContactsFrom)
	} else {
		for _, t := range []string{"Registrant", "Admin", "Technical", "Billing"} {
			set := func(f, v string) {
				if v != "" {
					p.Set(t+"_"+f, v)
				}
			}
			set("FirstName", b.ct.FirstName)
			set("LastName", b.ct.LastName)
			set("Organization", b.ct.Organization)
			set("Email", b.ct.Email)
			set("PhoneNumber", b.ct.Phone)
			set("Street", b.ct.Street)
			set("Street2", b.ct.Street2)
			set("City", b.ct.City)
			set("PostalCode", b.ct.PostalCode)
			set("CountryCode", b.ct.Country)
		}
	}
	if b.dry {
		return Result{Outcome: DryRun, Message: "dry run: would call /Domain/Create for " + domain}
	}
	code, m, err := b.call(ctx, "/Domain/Create", p)
	if err != nil {
		if code != 0 {
			return Result{Outcome: classifyHTTP(code), Message: err.Error()}
		}
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	status := strings.ToUpper(m["status"])
	if status == "" {
		status = strings.ToUpper(m["product_0_status"])
	}
	ref := m["transactid"]
	price := strings.TrimSpace(m["price"] + " " + m["currency"])
	msg := m["message"]
	switch status {
	case "SUCCESS":
		return Result{Outcome: Success, Ref: ref, Price: price, Message: "registered, expires " + m["product_0_expiration"]}
	case "PENDING":
		return Result{Outcome: Pending, Ref: ref, Price: price, Message: "pending at registry"}
	}
	low := strings.ToLower(msg + " " + m["product_0_message"])
	switch {
	case strings.Contains(low, "not available"), strings.Contains(low, "unavailable"), strings.Contains(low, "already registered"), strings.Contains(low, "is taken"):
		return Result{Outcome: Unavailable, Ref: ref, Message: msg}
	case strings.Contains(low, "balance"), strings.Contains(low, "funds"), strings.Contains(low, "credit"),
		strings.Contains(low, "api key"), strings.Contains(low, "password"), strings.Contains(low, "not allowed"), strings.Contains(low, "ip"),
		strings.Contains(low, "not supported"), strings.Contains(low, "invalid") && strings.Contains(low, "contact"), strings.Contains(low, "missing"):
		return Result{Outcome: Fatal, Ref: ref, Message: msg}
	}
	if msg == "" {
		msg = "FAILURE"
	}
	return Result{Outcome: Retryable, Ref: ref, Message: msg}
}

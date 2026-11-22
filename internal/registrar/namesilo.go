package registrar

import (
	"bytes"
	"context"
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

// NameSilo implements the NameSilo API (https://www.namesilo.com/api-reference).
//
//	https://www.namesilo.com/api/OPERATION?version=1&type=json&key=KEY   (GET only)
//	check:    checkRegisterAvailability&domains=a.com,b.com (≤200)
//	register: registerDomain&domain=..&years=1[&contact_id=..|fn,ln,ad,cy,st,zp,ct,em,ph][&private=1]
//	          without payment_id the order is paid from account funds
//	balance:  getAccountBalance
//
// reply.code 300 = success; 301/302 = success with default nameservers /
// default contact profile. No rate limit is documented; code 400 means a
// previous request is still processing.
type NameSilo struct {
	c    config.NameSilo
	ct   config.Contact
	base string
	http *http.Client
	dry  bool
}

func NewNameSilo(c config.NameSilo, ct config.Contact, dry bool) *NameSilo {
	return &NameSilo{c: c, ct: ct, base: "https://www.namesilo.com/api", http: httpClient(60 * time.Second), dry: dry}
}

func (n *NameSilo) Key() string           { return "namesilo" }
func (n *NameSilo) Label() string         { return "NameSilo" }
func (n *NameSilo) PriceKey() string      { return "namesilo" }
func (n *NameSilo) Configured() bool      { return n.c.APIKey != "" }
func (n *NameSilo) Problem() string       { return "" } // falls back to the account's default contact profile
func (n *NameSilo) MinGap() time.Duration { return time.Second }

// nsReply is reply{} of the standard envelope; code arrives as a number in
// the JSON examples but is parsed leniently.
type nsReply struct {
	Code        json.RawMessage `json:"code"`
	Detail      string          `json:"detail"`
	Message     string          `json:"message"`
	Domain      string          `json:"domain"`
	OrderAmount json.Number     `json:"order_amount"`
	Balance     json.Number     `json:"balance"`
	Available   json.RawMessage `json:"available"`
	Unavailable json.RawMessage `json:"unavailable"`
	Invalid     json.RawMessage `json:"invalid"`
	Contact     json.RawMessage `json:"contact"`
}

func (r *nsReply) code() int {
	s := strings.Trim(string(r.Code), `" `)
	n, _ := strconv.Atoi(s)
	return n
}

func (n *NameSilo) call(ctx context.Context, op string, p url.Values) (*nsReply, error) {
	if p == nil {
		p = url.Values{}
	}
	p.Set("version", "1")
	p.Set("type", "json")
	p.Set("key", n.c.APIKey)
	req, err := http.NewRequestWithContext(ctx, "GET", n.base+"/"+op+"?"+p.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := n.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	var env struct {
		Reply nsReply `json:"reply"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("namesilo HTTP %d: %s", resp.StatusCode, trunc(string(raw), 200))
	}
	return &env.Reply, nil
}

// nsDomains decodes the availability lists. Observed live shapes
// (2026-11-22) besides the documented array of objects:
//
//	"available":   {"domain": {"domain":"x.org","price":10.79,...}}   (single entry, wrapped)
//	"unavailable": {"domain":"example.com"}                           (single entry)
//	"unavailable": ["example.com","example.net"]                      (several, bare strings)
//	"invalid":     ["foobar123.lu","foobar123.tw"]
func nsDomains(raw json.RawMessage) []nsAvail {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var arr []json.RawMessage
	if raw[0] != '[' {
		arr = []json.RawMessage{raw}
	} else if json.Unmarshal(raw, &arr) != nil {
		return nil
	}
	var out []nsAvail
	for _, x := range arr {
		if a, ok := nsEntry(x); ok {
			out = append(out, a)
		}
	}
	return out
}

// nsEntry decodes one entry: a bare string, {"domain":"x", price...} or
// {"domain":{...}} (the wrapper seen for single results).
func nsEntry(x json.RawMessage) (nsAvail, bool) {
	var s string
	if json.Unmarshal(x, &s) == nil {
		return nsAvail{Domain: s}, s != ""
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(x, &obj) != nil {
		return nsAvail{}, false
	}
	if inner, ok := obj["domain"]; ok {
		inner = bytes.TrimSpace(inner)
		if len(inner) > 0 && inner[0] == '{' {
			return nsEntry(inner)
		}
	}
	var a nsAvail
	d := json.NewDecoder(bytes.NewReader(x))
	d.UseNumber()
	if d.Decode(&a) != nil || a.Domain == "" {
		return nsAvail{}, false
	}
	return a, true
}

type nsAvail struct {
	Domain   string      `json:"domain"`
	Price    json.Number `json:"price"`
	Premium  json.Number `json:"premium"`
	Duration json.Number `json:"duration"`
}

// nsError maps a non-success reply code.
func nsError(r *nsReply) error {
	return fmt.Errorf("namesilo %d: %s", r.code(), strings.TrimSpace(r.Detail+" "+r.Message))
}

func (n *NameSilo) Check(ctx context.Context, domain string) (Availability, error) {
	r, err := n.call(ctx, "checkRegisterAvailability", url.Values{"domains": {domain}})
	if err != nil {
		return Availability{}, err
	}
	switch r.code() {
	case 300:
	case 267:
		return Availability{}, ErrUnsupported
	case 400:
		return Availability{}, &RateError{Msg: "namesilo 400: previous request still processing", RetryAfter: 5 * time.Second}
	default:
		return Availability{}, nsError(r)
	}
	for _, a := range nsDomains(r.Available) {
		if strings.EqualFold(a.Domain, domain) {
			p := a.Premium.String()
			price := ""
			if f, err := a.Price.Float64(); err == nil && f > 0 {
				price = fmt.Sprintf("%.2f USD", f)
			}
			return Availability{Available: true, Premium: p == "1", Price: price}, nil
		}
	}
	for _, a := range nsDomains(r.Unavailable) {
		if strings.EqualFold(a.Domain, domain) {
			return Availability{Available: false}, nil
		}
	}
	for _, a := range nsDomains(r.Invalid) {
		if strings.EqualFold(a.Domain, domain) {
			return Availability{}, ErrUnsupported
		}
	}
	return Availability{}, fmt.Errorf("namesilo: %s not in the availability reply", domain)
}

func (n *NameSilo) Register(ctx context.Context, domain string) Result {
	p := url.Values{"domain": {domain}, "years": {"1"}, "auto_renew": {"0"}}
	if n.c.Private {
		p.Set("private", "1")
	}
	switch {
	case n.c.ContactID != "":
		p.Set("contact_id", n.c.ContactID)
	case n.ct.Complete():
		// all required fields or none: a partial set is ignored by NameSilo
		state := n.ct.State
		if state == "" {
			state = n.ct.City
		}
		for k, v := range map[string]string{"fn": n.ct.FirstName, "ln": n.ct.LastName, "ad": n.ct.Street, "ad2": n.ct.Street2, "cy": n.ct.City,
			"st": state, "zp": n.ct.PostalCode, "ct": n.ct.Country, "em": n.ct.Email, "ph": n.ct.Phone, "cp": n.ct.Organization} {
			if v != "" {
				p.Set(k, v)
			}
		}
	}
	for i, ns := range n.c.Nameservers {
		if i < 13 {
			p.Set(fmt.Sprintf("ns%d", i+1), ns)
		}
	}
	if n.dry {
		return Result{Outcome: DryRun, Message: "dry run: would call registerDomain for " + domain}
	}
	r, err := n.call(ctx, "registerDomain", p)
	if err != nil {
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	return nsRegisterResult(r)
}

func nsRegisterResult(r *nsReply) Result {
	price := ""
	if f, err := r.OrderAmount.Float64(); err == nil && f > 0 {
		price = fmt.Sprintf("%.2f USD", f)
	}
	msg := strings.TrimSpace(r.Detail + " " + r.Message)
	switch c := r.code(); c {
	case 300:
		return Result{Outcome: Success, Ref: r.Domain, Price: price, Message: "registered"}
	case 301:
		return Result{Outcome: Success, Ref: r.Domain, Price: price, Message: "registered (NameSilo default nameservers used)"}
	case 302:
		return Result{Outcome: Success, Ref: r.Domain, Price: price, Message: "registered with the account's DEFAULT contact profile (contact data rejected)"}
	case 400:
		return Result{Outcome: RateLimited, Message: "previous request still processing", RetryAfter: 5 * time.Second}
	case 115, 201:
		return Result{Outcome: Retryable, Message: fmt.Sprintf("%d %s", c, msg)}
	case 262:
		// "already active within our system": taken (at NameSilo)
		return Result{Outcome: Unavailable, Message: fmt.Sprintf("%d %s", c, msg)}
	case 261, 210:
		low := strings.ToLower(msg)
		if strings.Contains(low, "not available") || strings.Contains(low, "unavailable") || strings.Contains(low, "registered") || strings.Contains(low, "taken") {
			return Result{Outcome: Unavailable, Message: fmt.Sprintf("%d %s", c, msg)}
		}
		if strings.Contains(low, "premium") {
			return Result{Outcome: Fatal, Message: fmt.Sprintf("%d %s", c, msg)}
		}
		return Result{Outcome: Retryable, Message: fmt.Sprintf("%d %s", c, msg)}
	case 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 116, 117, 118, 119, 120, 263, 267:
		return Result{Outcome: Fatal, Message: fmt.Sprintf("%d %s", c, msg)}
	default:
		return Result{Outcome: Retryable, Message: fmt.Sprintf("%d %s", c, msg)}
	}
}

// Balances reads getAccountBalance (currency not stated by the docs).
func (n *NameSilo) Balances(ctx context.Context) ([]Balance, error) {
	r, err := n.call(ctx, "getAccountBalance", nil)
	if err != nil {
		return nil, err
	}
	if r.code() != 300 {
		return nil, nsError(r)
	}
	f, _ := r.Balance.Float64()
	return []Balance{{Amount: fmt.Sprintf("%.2f", f), Currency: "USD"}}, nil
}

// ContactExists checks a contact profile id via contactList (read-only).
func (n *NameSilo) ContactExists(ctx context.Context, id string) (bool, error) {
	r, err := n.call(ctx, "contactList", url.Values{"contact_id": {id}})
	if err != nil {
		return false, err
	}
	if r.code() != 300 {
		return false, nsError(r)
	}
	raw := bytes.TrimSpace(r.Contact)
	if len(raw) == 0 || string(raw) == "null" {
		return false, nil
	}
	var list []map[string]any
	if raw[0] == '{' {
		var one map[string]any
		if json.Unmarshal(raw, &one) != nil {
			return false, nil
		}
		list = []map[string]any{one}
	} else if json.Unmarshal(raw, &list) != nil {
		return false, nil
	}
	for _, c := range list {
		if fmt.Sprint(c["contact_id"]) == id {
			return true, nil
		}
	}
	return false, nil
}

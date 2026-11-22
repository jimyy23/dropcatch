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

// Netim implements the Netim REST API 1.0
// (https://support.netim.com/en/docs/api-rest-1-0/).
//
//	session: POST   /session/  (Basic resellerId:password) -> access_token
//	check:   GET    /domain/{domain}/check/ -> [{domain,result,reason}]
//	create:  POST   /domain/{domain}/  {idOwner,idAdmin,idTech,idBilling,ns1..,duration}
//	status:  GET    /operation/{id}
//
// Only 10 concurrent sessions are allowed per account, so one session is
// shared and renewed on 401. Contact handles must exist in the account.
type Netim struct {
	c    config.Netim
	base string
	http *http.Client
	dry  bool

	mu    sync.Mutex
	token string
	tokAt time.Time
}

func NewNetim(c config.Netim, dry bool) *Netim {
	base := "https://rest.netim.com/1.0"
	if c.OTE {
		base = "http://oterest.netim.com/1.0" // documented OT&E URL (http)
	}
	return &Netim{c: c, base: base, http: httpClient(60 * time.Second), dry: dry}
}

func (n *Netim) Key() string           { return "netim" }
func (n *Netim) Label() string         { return "Netim" }
func (n *Netim) PriceKey() string      { return "netim" }
func (n *Netim) Configured() bool      { return n.c.ID != "" && n.c.Password != "" }
func (n *Netim) MinGap() time.Duration { return time.Second }

func (n *Netim) Problem() string {
	if n.c.OwnerID == "" {
		return "set NETIM_OWNER_ID (an owner contact handle)"
	}
	return ""
}

func (n *Netim) session(ctx context.Context, renew bool) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !renew && n.token != "" && time.Since(n.tokAt) < 30*time.Minute {
		return n.token, nil
	}
	if n.token != "" {
		n.closeLocked()
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", n.base+"/session/", nil)
	req.SetBasicAuth(n.c.ID, n.c.Password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "EN")
	resp, err := n.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("netim session HTTP %d: %s", resp.StatusCode, trunc(string(raw), 200))
	}
	var r struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || r.AccessToken == "" {
		return "", fmt.Errorf("netim session: no access_token")
	}
	n.token, n.tokAt = r.AccessToken, time.Now()
	return n.token, nil
}

func (n *Netim) closeLocked() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "DELETE", n.base+"/session/", nil)
	req.Header.Set("Authorization", "Bearer "+n.token)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := n.http.Do(req); err == nil {
		resp.Body.Close()
	}
	n.token = ""
}

// Close ends the shared session (called on shutdown).
func (n *Netim) Close() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.token != "" {
		n.closeLocked()
	}
}

func (n *Netim) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := n.session(ctx, attempt > 0)
		if err != nil {
			return 0, nil, err
		}
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequestWithContext(ctx, method, n.base+path, rd)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept-Language", "EN")
		resp, err := n.http.Do(req)
		if err != nil {
			return 0, nil, err
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == 401 && attempt == 0 {
			continue
		}
		return resp.StatusCode, raw, nil
	}
	return 401, nil, fmt.Errorf("netim: unauthorized")
}

type netimCheck struct {
	Domain string `json:"domain"`
	Result string `json:"result"`
	Reason string `json:"reason"`
}

func (n *Netim) Check(ctx context.Context, domain string) (Availability, error) {
	code, raw, err := n.do(ctx, "GET", "/domain/"+url.PathEscape(domain)+"/check/", nil)
	if err != nil {
		return Availability{}, err
	}
	if code != 200 {
		return Availability{}, fmt.Errorf("netim check HTTP %d: %s", code, trunc(string(raw), 200))
	}
	var arr []netimCheck
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		var one netimCheck
		if json.Unmarshal(raw, &one) != nil || one.Result == "" {
			return Availability{}, fmt.Errorf("netim: unexpected check response")
		}
		arr = []netimCheck{one}
	}
	r := arr[0]
	res, reason := strings.ToUpper(r.Result), strings.ToUpper(r.Reason)
	switch res {
	case "AVAILABLE":
		return Availability{Available: true, Premium: reason == "PREMIUM", Detail: reason}, nil
	case "NOT AVAILABLE":
		return Availability{Available: false, Premium: reason == "PREMIUM", Detail: reason}, nil
	case "CLOSED", "NOT SOLD":
		return Availability{}, ErrUnsupported
	}
	return Availability{}, fmt.Errorf("netim: %s %s", r.Result, r.Reason)
}

type netimOp struct {
	ID      json.Number `json:"ID_OPE"`
	Status  string      `json:"STATUS"`
	Message string      `json:"MESSAGE"`
}

func (n *Netim) Register(ctx context.Context, domain string) Result {
	body := map[string]any{"idOwner": n.c.OwnerID, "idAdmin": n.c.AdminID, "idTech": n.c.TechID, "idBilling": n.c.BillID, "duration": 1}
	for i, ns := range n.c.Nameservers {
		if i < 5 {
			body[fmt.Sprintf("ns%d", i+1)] = ns
		}
	}
	if n.dry {
		return Result{Outcome: DryRun, Message: "dry run: would POST /domain/" + domain + "/"}
	}
	code, raw, err := n.do(ctx, "POST", "/domain/"+url.PathEscape(domain)+"/", body)
	if err != nil {
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	msg := trunc(string(raw), 300)
	switch code {
	case 200:
	case 401, 405, 406:
		return Result{Outcome: Fatal, Message: fmt.Sprintf("HTTP %d %s", code, msg)}
	case 400:
		low := strings.ToLower(msg)
		switch {
		case strings.Contains(low, "not available"), strings.Contains(low, "already"), strings.Contains(low, "unavailable"):
			return Result{Outcome: Unavailable, Message: msg}
		case strings.Contains(low, "balance"), strings.Contains(low, "contact"), strings.Contains(low, "owner"), strings.Contains(low, "closed"), strings.Contains(low, "not sold"), strings.Contains(low, "duration"):
			return Result{Outcome: Fatal, Message: msg}
		}
		return Result{Outcome: Retryable, Message: msg}
	default:
		return Result{Outcome: classifyHTTP(code), Message: fmt.Sprintf("HTTP %d %s", code, msg)}
	}
	var op netimOp
	if err := json.Unmarshal(raw, &op); err != nil {
		return Result{Outcome: Pending, Message: "accepted (unparsed response): " + msg}
	}
	ref := op.ID.String()
	switch strings.ToLower(op.Status) {
	case "done":
		return Result{Outcome: Success, Ref: ref, Message: "registered"}
	case "pending":
		return Result{Outcome: Pending, Ref: ref, Message: "operation pending"}
	case "failed", "error", "cancelled":
		low := strings.ToLower(op.Message)
		if strings.Contains(low, "not available") || strings.Contains(low, "already") {
			return Result{Outcome: Unavailable, Ref: ref, Message: op.Message}
		}
		return Result{Outcome: Retryable, Ref: ref, Message: op.Message}
	}
	return Result{Outcome: Pending, Ref: ref, Message: op.Status + " " + op.Message}
}

// Balances reads GET /account/ (StructQueryResellerAccount).
func (n *Netim) Balances(ctx context.Context) ([]Balance, error) {
	code, raw, err := n.do(ctx, "GET", "/account/", nil)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("netim account HTTP %d: %s", code, trunc(string(raw), 200))
	}
	var r map[string]any
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("netim: bad account response")
	}
	get := func(k string) string {
		for kk, v := range r {
			if strings.EqualFold(kk, k) && v != nil {
				return fmt.Sprint(v)
			}
		}
		return ""
	}
	note := ""
	if l := get("BALANCE_LOW_LIMIT"); l != "" {
		note = "low limit " + l + ", hard limit " + get("BALANCE_HARD_LIMIT")
	}
	return []Balance{{Amount: get("BALANCE_AMOUNT"), Currency: "EUR", Note: note}}, nil
}

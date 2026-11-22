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

// ibsResp is the JSON response shape observed on the Internet.bs API
// (testapi.internet.bs): top-level status/message/code, optional nested
// "product" array for orders, "price" object and "details" field errors.
type ibsResp struct {
	TransactID string       `json:"transactid"`
	Status     string       `json:"status"`
	Message    string       `json:"message"`
	Code       any          `json:"code"`
	Currency   string       `json:"currency"`
	Price      any          `json:"price"`
	Product    []ibsProduct `json:"product"`
	Details    []ibsDetail  `json:"details"`
}

type ibsProduct struct {
	Status     string `json:"status"`
	Message    string `json:"message"`
	Code       any    `json:"code"`
	Domain     string `json:"domain"`
	Price      any    `json:"price"`
	Expiration string `json:"expiration"`
}

type ibsDetail struct {
	Field string `json:"field"`
	Error string `json:"error"`
}

func codeStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case float64:
		return fmt.Sprintf("%.0f", x)
	}
	return fmt.Sprint(v)
}

// message joins the top-level message, product messages and field errors.
func (r *ibsResp) message() string {
	var p []string
	if r.Message != "" {
		p = append(p, r.Message)
	}
	for _, x := range r.Product {
		if x.Message != "" {
			p = append(p, x.Message)
		}
	}
	for _, d := range r.Details {
		p = append(p, d.Field+": "+d.Error)
	}
	if c := r.code(); c != "" {
		p = append(p, "(code "+c+")")
	}
	return strings.Join(p, "; ")
}

// code returns the most specific error code (product first).
func (r *ibsResp) code() string {
	for _, x := range r.Product {
		if c := codeStr(x.Code); c != "" {
			return c
		}
	}
	return codeStr(r.Code)
}

func (b *InternetBS) call(ctx context.Context, cmd string, p url.Values) (int, *ibsResp, error) {
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
	var r ibsResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, trunc(string(raw), 200))
	}
	return resp.StatusCode, &r, nil
}

// Error codes returned by the API (observed on the test server).
const (
	ibsNotAvailable    = "100017" // Domain "x" is not available for registration
	ibsInvalidParam    = "100002" // Invalid value for parameter (contact data, eligibility)
	ibsMissingParam    = "100003" // Required parameter missing
	ibsPermission      = "100005" // Permission denied (e.g. CloneContactsFromDomain not ours)
	ibsBadCredentials  = "107002" // Invalid API key and/or Password
	ibsUnknownCommand  = "107013"
	ibsUnexpectedError = "107015" // Unexpected ERROR: Tech department has been notified
)

func (b *InternetBS) Check(ctx context.Context, domain string) (Availability, error) {
	_, r, err := b.call(ctx, "/Domain/Check", url.Values{"Domain": {domain}})
	if err != nil {
		return Availability{}, err
	}
	premium := false
	if m, ok := r.Price.(map[string]any); ok {
		premium = strings.EqualFold(fmt.Sprint(m["ispremium"]), "YES")
	}
	switch strings.ToUpper(r.Status) {
	case "AVAILABLE":
		return Availability{Available: true, Premium: premium}, nil
	case "UNAVAILABLE":
		return Availability{Available: false, Premium: premium}, nil
	}
	if r.code() == ibsBadCredentials {
		return Availability{}, fmt.Errorf("internet.bs: invalid API key and/or password (or IP not allowed)")
	}
	low := strings.ToLower(r.Message)
	if strings.Contains(low, "not supported") || strings.Contains(low, "invalid extension") {
		return Availability{}, ErrUnsupported
	}
	msg := r.message()
	if msg == "" {
		msg = "no answer"
	}
	return Availability{}, fmt.Errorf("internet.bs check %s: %s", r.Status, msg)
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
	code, r, err := b.call(ctx, "/Domain/Create", p)
	if err != nil {
		if code != 0 {
			return Result{Outcome: classifyHTTP(code), Message: err.Error()}
		}
		return Result{Outcome: Retryable, Message: err.Error()}
	}
	return ibsCreateResult(r)
}

// ibsCreateResult maps a /Domain/Create response to an outcome.
func ibsCreateResult(r *ibsResp) Result {
	status := strings.ToUpper(r.Status)
	var prod *ibsProduct
	if len(r.Product) > 0 {
		prod = &r.Product[0]
		if ps := strings.ToUpper(prod.Status); ps != "" && (status == "" || status == "SUCCESS") {
			status = ps
		}
	}
	price := strings.TrimSpace(codeStr(r.Price) + " " + r.Currency)
	if prod != nil && prod.Price != nil {
		price = strings.TrimSpace(codeStr(prod.Price) + " " + r.Currency)
	}
	res := Result{Ref: r.TransactID, Price: price, Message: r.message()}
	switch status {
	case "SUCCESS":
		res.Outcome, res.Message = Success, "registered"
		if prod != nil && prod.Expiration != "" {
			res.Message += ", expires " + prod.Expiration
		}
		return res
	case "PENDING":
		res.Outcome, res.Message = Pending, "pending at registry"
		return res
	}
	switch r.code() {
	case ibsNotAvailable:
		res.Outcome = Unavailable
	case ibsInvalidParam, ibsMissingParam, ibsPermission, ibsBadCredentials, ibsUnknownCommand:
		// contact data / eligibility / credentials: retrying cannot help
		res.Outcome = Fatal
	case ibsUnexpectedError:
		res.Outcome = Retryable
	default:
		low := strings.ToLower(res.Message)
		switch {
		case strings.Contains(low, "not available"), strings.Contains(low, "already registered"):
			res.Outcome = Unavailable
		case strings.Contains(low, "insufficient"), strings.Contains(low, "balance"), strings.Contains(low, "funds"), strings.Contains(low, "not supported"):
			res.Outcome = Fatal
		default:
			res.Outcome = Retryable
		}
	}
	if res.Message == "" {
		res.Message = "FAILURE"
	}
	return res
}

// Balances reads /Account/Balance/Get.
func (b *InternetBS) Balances(ctx context.Context) ([]Balance, error) {
	p := url.Values{"ApiKey": {b.c.APIKey}, "Password": {b.c.Password}, "ResponseFormat": {"JSON"}}
	req, err := http.NewRequestWithContext(ctx, "POST", b.base+"/Account/Balance/Get", strings.NewReader(p.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Balance []struct {
			Currency string      `json:"currency"`
			Amount   json.Number `json:"amount"`
		} `json:"balance"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("internet.bs balance HTTP %d", resp.StatusCode)
	}
	if !strings.EqualFold(r.Status, "SUCCESS") {
		return nil, fmt.Errorf("internet.bs: %s", r.Message)
	}
	var out []Balance
	for _, x := range r.Balance {
		f, _ := x.Amount.Float64()
		out = append(out, Balance{Amount: fmt.Sprintf("%.2f", f), Currency: x.Currency})
	}
	return out, nil
}

package registrar

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"dropcatch/internal/config"
)

func TestDynadotSignatureAndOutcomes(t *testing.T) {
	var gotSig, gotReq, gotBody, gotPath string
	status := 409
	body := `{"code":409,"message":"Conflict","error":{"description":"The domain is not available"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig, gotReq, gotPath = r.Header.Get("X-Signature"), r.Header.Get("X-Request-ID"), r.URL.RequestURI()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	d := NewDynadot(config.Dynadot{APIKey: "KEY", APISecret: "SECRET", ContactID: "123", Privacy: "full", Currency: "usd"}, config.Contact{}, false)
	d.base = srv.URL

	res := d.Register(context.Background(), "example.com")
	if res.Outcome != Unavailable {
		t.Fatalf("409 not available => %s", res.Outcome)
	}
	m := hmac.New(sha256.New, []byte("SECRET"))
	_ = gotReq
	m.Write([]byte("KEY\n" + gotPath + "\n\n" + gotBody)) // empty request-id line, as the live API requires
	if gotSig != base64.StdEncoding.EncodeToString(m.Sum(nil)) {
		t.Fatal("X-Signature does not match the documented scheme")
	}
	var parsed map[string]map[string]any
	json.Unmarshal([]byte(gotBody), &parsed)
	if parsed["domain"]["registrant_contact_id"] != float64(123) || parsed["domain"]["duration"] != float64(1) {
		t.Fatalf("body: %s", gotBody)
	}

	status, body = 402, `{"code":402,"message":"Payment Required","error":{"description":"Insufficient funds."}}`
	if res := d.Register(context.Background(), "example.com"); res.Outcome != Fatal {
		t.Fatalf("402 => %s", res.Outcome)
	}
	status, body = 200, `{"code":200,"message":"Success","data":{"domain_name":"example.com","expiration_date":"1458379145266"}}`
	if res := d.Register(context.Background(), "example.com"); res.Outcome != Success {
		t.Fatalf("200 => %s", res.Outcome)
	}
	status, body = 429, `{"code":429,"message":"Too Many Requests","error":{"description":"Too many requests."}}`
	if res := d.Register(context.Background(), "example.com"); res.Outcome != RateLimited {
		t.Fatalf("429 => %s", res.Outcome)
	}
	// search: available is documented as Boolean but the example shows "No"
	status, body = 200, `{"code":200,"message":"Success","data":{"domain_name":"example.com","available":"No","premium":"yes"}}`
	a, err := d.Check(context.Background(), "example.com")
	if err != nil || a.Available || !a.Premium {
		t.Fatalf("search parse: %+v %v", a, err)
	}
	if gotSig != "" {
		t.Fatal("search must not be signed")
	}
}

func TestPorkbunCostInCents(t *testing.T) {
	var createBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "pk" || r.Header.Get("X-Secret-API-Key") != "sk" {
			t.Errorf("missing auth headers")
		}
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		switch {
		case strings.HasPrefix(r.URL.Path, "/domain/create/") && b["dryRun"] == true && b["cost"] == float64(0):
			io.WriteString(w, `{"status":"SUCCESS","dryRun":true,"wouldSucceed":true,"cost":973}`)
		case strings.HasPrefix(r.URL.Path, "/domain/create/"):
			createBody = b
			io.WriteString(w, `{"status":"SUCCESS","domain":"example.com","cost":973,"orderId":12345678}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	p := NewPorkbun(config.Porkbun{APIKey: "pk", SecretKey: "sk"}, false)
	p.base = srv.URL
	res := p.Register(context.Background(), "example.com")
	if res.Outcome != Success || res.Ref != "12345678" {
		t.Fatalf("result: %+v", res)
	}
	if createBody["cost"] != float64(973) || createBody["agreeToTerms"] != "yes" {
		t.Fatalf("create body: %v", createBody)
	}
}

func TestPorkbunErrors(t *testing.T) {
	code, body := 200, ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		if b["dryRun"] == true {
			io.WriteString(w, `{"status":"SUCCESS","dryRun":true,"cost":973}`)
			return
		}
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	p := NewPorkbun(config.Porkbun{APIKey: "pk", SecretKey: "sk"}, false)
	p.base = srv.URL
	for _, c := range []struct {
		code int
		body string
		want Outcome
	}{
		{400, `{"status":"ERROR","code":"DOMAIN_NOT_AVAILABLE","message":"Domain is not available."}`, Unavailable},
		{400, `{"status":"ERROR","code":"INSUFFICIENT_FUNDS","message":"no money"}`, Fatal},
		{429, `{"status":"ERROR","code":"RATE_LIMIT_EXCEEDED","message":"slow down"}`, RateLimited},
		{200, `{"status":"ERROR","code":"RATE_LIMIT_EXCEEDED","message":"slow down","ttlRemaining":3}`, RateLimited},
	} {
		code, body = c.code, c.body
		if res := p.Register(context.Background(), "example.com"); res.Outcome != c.want {
			t.Errorf("%s => %s, want %s", c.body, res.Outcome, c.want)
		}
	}
}

func TestCloudflareCheck(t *testing.T) {
	resp := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || !strings.HasSuffix(r.URL.Path, "/accounts/acc/registrar/domain-check") {
			t.Errorf("bad request %s", r.URL.Path)
		}
		io.WriteString(w, resp)
	}))
	defer srv.Close()
	f := NewCloudflare(config.Cloudflare{APIToken: "tok", AccountID: "acc"}, false)
	f.base = srv.URL
	resp = `{"success":true,"errors":[],"result":{"domains":[{"name":"a.com","registrable":true,"tier":"standard","pricing":{"currency":"USD","registration_cost":"8.57"}}]}}`
	if a, err := f.Check(context.Background(), "a.com"); err != nil || !a.Available || a.Premium {
		t.Fatalf("%+v %v", a, err)
	}
	resp = `{"success":true,"errors":[],"result":{"domains":[{"name":"mybrand.uk","reason":"extension_not_supported_via_api","registrable":false}]}}`
	if _, err := f.Check(context.Background(), "mybrand.uk"); err != ErrUnsupported {
		t.Fatalf("want unsupported, got %v", err)
	}
}

func TestCloudflareRegisterAsync(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(202)
			io.WriteString(w, `{"success":true,"errors":[],"result":{"completed":false,"state":"in_progress","links":{"self":"/accounts/acc/registrar/registrations/a.com/registration-status"}}}`)
			return
		}
		polls++
		io.WriteString(w, `{"success":true,"errors":[],"result":{"completed":true,"state":"succeeded","links":{"self":"/accounts/acc/registrar/registrations/a.com/registration-status"}}}`)
	}))
	defer srv.Close()
	f := NewCloudflare(config.Cloudflare{APIToken: "tok", AccountID: "acc"}, false)
	f.base = srv.URL
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if res := f.Register(ctx, "a.com"); res.Outcome != Success || polls == 0 {
		t.Fatalf("%+v polls=%d", res, polls)
	}
}

// Responses below were captured from https://testapi.internet.bs on 2026-11-22.
func TestInternetBSRealResponses(t *testing.T) {
	resp := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("ApiKey") != "k" || r.Form.Get("ResponseFormat") != "JSON" {
			t.Errorf("bad params")
		}
		io.WriteString(w, resp)
	}))
	defer srv.Close()
	b := NewInternetBS(config.InternetBS{APIKey: "k", Password: "p", CloneContactsFrom: "mine.com"}, config.Contact{}, false)
	b.base = srv.URL

	resp = `{"transactid":"10104348a468f76e94ac88d79d1d71dc","status":"UNAVAILABLE","domain":"example.com","minregperiod":"1Y","maxregperiod":"10Y","registrarlockallowed":"YES","privatewhoisallowed":"YES","realtimeregistration":"YES","price":{"ispremium":"NO"}}`
	if a, err := b.Check(context.Background(), "example.com"); err != nil || a.Available || a.Premium {
		t.Fatalf("UNAVAILABLE: %+v %v", a, err)
	}
	resp = `{"transactid":"f4936a25ccb3c081105ffeec1745bd55","status":"FAILURE","domain":"foobar123zqx.com","minregperiod":"1Y","price":{"ispremium":"NO"}}`
	if _, err := b.Check(context.Background(), "foobar123zqx.com"); err == nil {
		t.Fatal("FAILURE must not read as available or unavailable")
	}
	resp = `{"transactid":"3060f7522d55f190e82931da96ac70de","status":"FAILURE","message":"Unexpected ERROR: Tech department has been notified!","code":107015}`
	if _, err := b.Check(context.Background(), "example.co"); err == nil || err == ErrUnsupported {
		t.Fatalf("107015 is a transient error, got %v", err)
	}

	cases := []struct {
		body string
		want Outcome
	}{
		{`{"transactid":"1a2a","status":"FAILURE","product":[{"status":"FAILURE","message":"Domain \"x.com\" is not available for registration","code":100017}]}`, Unavailable},
		{`{"transactid":"a44c","status":"FAILURE","message":"Invalid value \"test@example.com\" for parameter \"registrant_email\"!","code":100002,"details":[{"field":"registrant_email","val":"test@example.com","error":"This email has been previously been used ... not been verified."}]}`, Fatal},
		{`{"transactid":"fb02","status":"FAILURE","message":"Required parameter \"registrant_email\" missing!","code":100003,"details":[{"field":"registrant_email","val":null,"error":"Please populate this field"}]}`, Fatal},
		{`{"transactid":"33e4","status":"FAILURE","message":"Permission denied! \"x.com\" permission is not granted.","code":100005}`, Fatal},
		{`{"transactid":"49e3","status":"FAILURE","message":"Invalid API key and\/or Password","code":107002}`, Fatal},
		{`{"transactid":"eda5","status":"FAILURE","message":"Unexpected ERROR: Tech department has been notified!","code":107015}`, Retryable},
		{`{"transactid":"4448","status":"FAILURE","message":"Invalid value \"US\" for parameter \"registrant_countrycode\"!","code":100002,"details":[{"field":"registrant_countrycode","val":"US","error":"European citizenship is required"}]}`, Fatal},
		// documented success shapes (PDF): flat product_0_* (TEXT) and status SUCCESS
		{`{"transactid":"820b","status":"SUCCESS","currency":"USD","price":13.9,"product":[{"status":"SUCCESS","domain":"example.com","price":13.9,"expiration":"2010/04/02"}]}`, Success},
		{`{"transactid":"x","status":"PENDING"}`, Pending},
	}
	for _, c := range cases {
		resp = c.body
		res := b.Register(context.Background(), "x.com")
		if res.Outcome != c.want {
			t.Errorf("%s\n=> %s (%s), want %s", c.body, res.Outcome, res.Message, c.want)
		}
	}
	resp = cases[1].body
	if res := b.Register(context.Background(), "x.com"); !strings.Contains(res.Message, "registrant_email") || !strings.Contains(res.Message, "100002") {
		t.Errorf("field errors and code should be in the message: %q", res.Message)
	}
}

func TestNetimSessionAndCheck(t *testing.T) {
	sessions := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/session/" && r.Method == "POST":
			if u, p, ok := r.BasicAuth(); !ok || u != "ID" || p != "PW" {
				w.WriteHeader(401)
				return
			}
			sessions++
			io.WriteString(w, `{"access_token":"tok"}`)
		case strings.HasSuffix(r.URL.Path, "/check/"):
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(401)
				return
			}
			io.WriteString(w, `[{"domain":"example.lu","result":"AVAILABLE","reason":""}]`)
		case r.Method == "POST":
			io.WriteString(w, `{"ID_OPE":5416,"STATUS":"Pending","MESSAGE":"","TYPE":"domainCreate"}`)
		}
	}))
	defer srv.Close()
	n := NewNetim(config.Netim{ID: "ID", Password: "PW", OwnerID: "OW1", AdminID: "ID", TechID: "ID", BillID: "ID"}, false)
	n.base = srv.URL
	a, err := n.Check(context.Background(), "example.lu")
	if err != nil || !a.Available {
		t.Fatalf("%+v %v", a, err)
	}
	if res := n.Register(context.Background(), "example.lu"); res.Outcome != Pending || res.Ref != "5416" {
		t.Fatalf("%+v", res)
	}
	if sessions != 1 {
		t.Fatalf("session should be reused, opened %d", sessions)
	}
}

// Request/response shapes from https://regery.com/partnership/api/ (2026-11-22).
func TestRegeryAPI(t *testing.T) {
	var contactBody, regBody map[string]any
	contactCalls := 0
	check := `{"domain":"example.com","source":"dns","result":"available","premium":false}`
	regStatus, regResp := 200, `{"pending":false}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "KEY:SECRET" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("auth/content-type headers: %q %q", r.Header.Get("Authorization"), r.Header.Get("Content-Type"))
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/domains/example.com/availability":
			io.WriteString(w, check)
		case r.Method == "POST" && r.URL.Path == "/v1/contacts":
			contactCalls++
			json.NewDecoder(r.Body).Decode(&contactBody)
			io.WriteString(w, `{"id":"ABCDEFGHIJ"}`)
		case r.Method == "POST" && r.URL.Path == "/v1/domains/example.com":
			json.NewDecoder(r.Body).Decode(&regBody)
			w.WriteHeader(regStatus)
			io.WriteString(w, regResp)
		case r.Method == "GET" && r.URL.Path == "/v1/account/balance":
			io.WriteString(w, `100.00`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ct := config.Contact{FirstName: "John", LastName: "Doe", Email: "j@example.com", Phone: "+1.23456789", Street: "Wall Street 1", City: "New York", PostalCode: "10005", Country: "US"}
	r := NewRegery(config.Regery{APIKey: "KEY", APISecret: "SECRET"}, ct, false)
	r.base = srv.URL
	ctx := context.Background()

	for body, want := range map[string]bool{
		`{"domain":"example.com","source":"dns","result":"available","premium":false}`:    true,
		`{"domain":"example.com","source":"dns","result":"notAvailable","premium":false}`: false,
		`{"domain":"example.com","result":"internal","premium":null}`:                     false,
		`{"domain":"example.com","result":"restricted","premium":false}`:                  false,
	} {
		check = body
		a, err := r.Check(ctx, "example.com")
		if err != nil || a.Available != want {
			t.Errorf("%s => %+v %v", body, a, err)
		}
	}
	check = `{"domain":"example.com","result":"notSupported"}`
	if _, err := r.Check(ctx, "example.com"); err != ErrUnsupported {
		t.Errorf("notSupported => %v", err)
	}
	check = `{"domain":"example.com","result":"rateLimit"}`
	if _, err := r.Check(ctx, "example.com"); err == nil {
		t.Error("rateLimit must be an error")
	} else if _, ok := err.(*RateError); !ok {
		t.Errorf("rateLimit => %T", err)
	}
	check = `{"domain":"example.com","result":"error"}`
	if _, err := r.Check(ctx, "example.com"); err == nil {
		t.Error("error result must be an error")
	}

	if b, err := r.Balances(ctx); err != nil || len(b) != 1 || b[0].Amount != "100.00" {
		t.Errorf("balance %v %v", b, err)
	}

	res := r.Register(ctx, "example.com")
	if res.Outcome != Success {
		t.Fatalf("register: %+v", res)
	}
	d := contactBody["details"].(map[string]any)
	if d["firstName"] != "John" || d["address1"] != "Wall Street 1" || d["zip"] != "10005" || d["phoneNumber"] != "+1.23456789" || d["countryCode"] != "US" {
		t.Errorf("contact details: %v", d)
	}
	if regBody["period"] != float64(1) || regBody["contacts"].(map[string]any)["registrant"] != "ABCDEFGHIJ" || regBody["nameservers"].(map[string]any)["provider"] != "basic" {
		t.Errorf("register body: %v", regBody)
	}
	regResp = `{"pending":true}`
	if res := r.Register(ctx, "example.com"); res.Outcome != Pending {
		t.Errorf("pending => %s", res.Outcome)
	}
	if contactCalls != 1 {
		t.Errorf("contact should be saved once and reused, saved %d times", contactCalls)
	}
	for _, c := range []struct {
		status int
		body   string
		want   Outcome
	}{
		{429, ``, RateLimited},
		{401, ``, Fatal},
		{400, `{"Message":"Insufficient funds"}`, Fatal},
		{400, `{"Message":"Domain is not available"}`, Unavailable},
		{500, `oops`, Retryable},
		{404, ``, Fatal},
	} {
		regStatus, regResp = c.status, c.body
		if res := r.Register(ctx, "example.com"); res.Outcome != c.want {
			t.Errorf("HTTP %d %s => %s, want %s", c.status, c.body, res.Outcome, c.want)
		}
	}

	dry := NewRegery(config.Regery{APIKey: "KEY", APISecret: "SECRET"}, ct, true)
	dry.base = srv.URL
	if res := dry.Register(ctx, "example.com"); res.Outcome != DryRun {
		t.Errorf("dry run => %s", res.Outcome)
	}
	if NewRegery(config.Regery{APIKey: "k", APISecret: "s"}, config.Contact{}, false).Problem() == "" {
		t.Error("missing contact must be reported")
	}
}

// Responses copied from https://www.namesilo.com/api-reference (2026-11-22).
func TestNameSilo(t *testing.T) {
	reply := ""
	var lastQ url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("NameSilo requires GET, got %s", r.Method)
		}
		lastQ = r.URL.Query()
		if lastQ.Get("version") != "1" || lastQ.Get("type") != "json" || lastQ.Get("key") != "K" {
			t.Errorf("standard params: %v", lastQ)
		}
		io.WriteString(w, reply)
	}))
	defer srv.Close()
	ct := config.Contact{FirstName: "John", LastName: "Smith", Email: "t@test.com", Phone: "+1.4805555555", Street: "123 N. 1st Street", City: "Anywhere", State: "AZ", PostalCode: "55555", Country: "US"}
	n := NewNameSilo(config.NameSilo{APIKey: "K", Private: true}, ct, false)
	n.base = srv.URL
	ctx := context.Background()

	reply = `{"request":{"operation":"checkRegisterAvailability","ip":"55.555.55.55"},"reply":{"code":300,"detail":"success","available":[{"domain":"namesilo.com","price":9.99,"premium":0,"duration":1},{"domain":"namesilo.org","price":19.99,"premium":0,"duration":10}],"unavailable":{"domain":"namesilo.net"},"invalid":{"domain":"n#mesilo.com"}}}`
	if a, err := n.Check(ctx, "namesilo.com"); err != nil || !a.Available || a.Premium || a.Price != "9.99 USD" {
		t.Errorf("available: %+v %v", a, err)
	}
	if a, err := n.Check(ctx, "namesilo.net"); err != nil || a.Available {
		t.Errorf("unavailable: %+v %v", a, err)
	}
	if _, err := n.Check(ctx, "n#mesilo.com"); err != ErrUnsupported {
		t.Errorf("invalid => %v", err)
	}
	reply = `{"reply":{"code":"300","detail":"success","unavailable":[{"domain":"a.com"},{"domain":"b.com"}]}}`
	if a, err := n.Check(ctx, "b.com"); err != nil || a.Available {
		t.Errorf("unavailable array: %+v %v", a, err)
	}
	// live production responses (2026-11-22)
	for _, c := range []struct {
		reply, domain string
		avail         bool
		err           error
	}{
		{`{"request":{"operation":"checkRegisterAvailability"},"reply":{"code":300,"detail":"success","available":{"domain":{"domain":"dropcatch-ns-c-81723.org","price":10.79,"renew":14.99,"premium":0,"duration":10}}}}`, "dropcatch-ns-c-81723.org", true, nil},
		{`{"reply":{"code":300,"detail":"success","unavailable":{"domain":"example.com"}}}`, "example.com", false, nil},
		{`{"reply":{"code":300,"detail":"success","available":[{"domain":"a-81723.com","price":19.99,"renew":19.99,"premium":0,"duration":10}],"unavailable":["example.com","example.net","google.com"]}}`, "example.net", false, nil},
		{`{"reply":{"code":300,"detail":"success","available":[{"domain":"a-81723.com","price":19.99,"renew":19.99,"premium":0,"duration":10}],"unavailable":["example.com","example.net","google.com"]}}`, "a-81723.com", true, nil},
		{`{"reply":{"code":300,"detail":"success","invalid":{"domain":"foobar123.lu"}}}`, "foobar123.lu", false, ErrUnsupported},
		{`{"reply":{"code":300,"detail":"success","invalid":["foobar123.lu","foobar123.tw","bankbazaar.tw"]}}`, "foobar123.tw", false, ErrUnsupported},
	} {
		reply = c.reply
		a, err := n.Check(ctx, c.domain)
		if err != c.err || (err == nil && a.Available != c.avail) {
			t.Errorf("live shape %s: %+v %v", c.domain, a, err)
		}
	}
	reply = `{"reply":{"code":300,"detail":"success","available":{"domain":{"domain":"x.org","price":10.79,"premium":0}}}}`
	if a, _ := n.Check(ctx, "x.org"); a.Price != "10.79 USD" {
		t.Errorf("wrapped price: %q", a.Price)
	}

	reply = `{"request":{"operation":"registerDomain","ip":"55.555.55.55"},"reply":{"code":300,"detail":"success","message":"Your domain registration was successfully processed.","domain":"namesilo.com","order_amount":7.77}}`
	res := n.Register(ctx, "namesilo.com")
	if res.Outcome != Success || res.Price != "7.77 USD" {
		t.Fatalf("register: %+v", res)
	}
	if lastQ.Get("domain") != "namesilo.com" || lastQ.Get("years") != "1" || lastQ.Get("private") != "1" || lastQ.Get("fn") != "John" || lastQ.Get("ph") != "+1.4805555555" || lastQ.Get("st") != "AZ" || lastQ.Has("payment_id") {
		t.Errorf("register params: %v", lastQ)
	}
	for _, c := range []struct {
		reply string
		want  Outcome
	}{
		{`{"reply":{"code":301,"detail":"success","domain":"x.com"}}`, Success},
		{`{"reply":{"code":302,"detail":"success","domain":"x.com"}}`, Success},
		{`{"reply":{"code":262,"detail":"This domain is already active within our system and therefore cannot be processed."}}`, Unavailable},
		{`{"reply":{"code":119,"detail":"Insufficient account funds for requested transaction"}}`, Fatal},
		{`{"reply":{"code":110,"detail":"Invalid API key"}}`, Fatal},
		{`{"reply":{"code":113,"detail":"This API account cannot be accessed from your IP"}}`, Fatal},
		{`{"reply":{"code":267,"detail":"Invalid domain name, or we do not support the provided extension/TLD."}}`, Fatal},
		{`{"reply":{"code":115,"detail":"Central Registry Not Responding - try again later"}}`, Retryable},
		{`{"reply":{"code":400,"detail":"Existing API request is still processing"}}`, RateLimited},
		{`{"reply":{"code":261,"detail":"Domain processing error","message":"domain is not available"}}`, Unavailable},
	} {
		reply = c.reply
		if res := n.Register(ctx, "x.com"); res.Outcome != c.want {
			t.Errorf("%s => %s, want %s", c.reply, res.Outcome, c.want)
		}
	}

	reply = `{"request":{"operation":"getAccountBalance","ip":"55.555.55.55"},"reply":{"code":300,"detail":"success","balance":355.75}}`
	if b, err := n.Balances(ctx); err != nil || len(b) != 1 || b[0].Amount != "355.75" {
		t.Errorf("balance: %v %v", b, err)
	}

	withID := NewNameSilo(config.NameSilo{APIKey: "K", ContactID: "4444444"}, ct, false)
	withID.base = srv.URL
	reply = `{"reply":{"code":300,"detail":"success","domain":"x.com"}}`
	withID.Register(ctx, "x.com")
	if lastQ.Get("contact_id") != "4444444" || lastQ.Has("fn") {
		t.Errorf("contact_id mode: %v", lastQ)
	}
}

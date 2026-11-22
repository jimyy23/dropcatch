package registrar

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"dropcatch/internal/config"
)

// Full operation test against the Regery API in TEST mode:
//
//	LIVE_REGERY=1 go test ./internal/registrar -run LiveRegery -v
//
// Requires a TST_ key in .env (REGERY_API_KEY, REGERY_API_SECRET,
// REGERY_TEST_DOMAIN_TOKEN, REGERY_TEST_PHONE). Refuses to run with a live
// key. Registers one test-token domain (simulated, free in test mode).
// Mind the limits: account.balance 4/hour, domains.register 10/min.
func TestLiveRegery(t *testing.T) {
	if os.Getenv("LIVE_REGERY") != "1" {
		t.Skip("set LIVE_REGERY=1 to run against the Regery API with a TST_ key")
	}
	loadDotEnv(t, "../../.env")
	env := config.Load()
	r := NewRegery(env.Regery, env.Contact, false)
	if !r.Configured() {
		t.Skip("REGERY_API_KEY / REGERY_API_SECRET not set")
	}
	if !r.TestMode() || env.Regery.TestToken == "" {
		t.Fatal("refusing to place orders: REGERY_API_KEY is not a TST_ test key or REGERY_TEST_DOMAIN_TOKEN is missing")
	}
	tok := env.Regery.TestToken
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	b, err := r.Balances(ctx)
	t.Logf("balance: %v err=%v", b, err)

	free := fmt.Sprintf("dc%d-%s.com", time.Now().Unix()%100000, tok)
	cases := []struct {
		domain string
		avail  bool
		err    error
	}{
		{free, true, nil},
		{"dc-xna-" + tok + ".com", false, nil},
		{"dc-" + tok + ".zzzz", false, ErrUnsupported},
		{"example.com", false, ErrUnsupported}, // real name with a test key: wrongApiKeyMode
	}
	for _, c := range cases {
		a, err := r.Check(ctx, c.domain)
		t.Logf("check %-48s %+v err=%v", c.domain, a, err)
		if err != c.err || (err == nil && a.Available != c.avail) {
			t.Errorf("%s: want available=%v err=%v", c.domain, c.avail, c.err)
		}
	}

	id, err := r.EnsureContact(ctx)
	if err != nil {
		t.Fatalf("save contact: %v", err)
	}
	det, err := r.Contact(ctx, id)
	t.Logf("contact %s: state=%v country=%v phone=%v err=%v", id, det["state"], det["countryCode"], det["phoneNumber"], err)
	if err != nil || det["state"] == nil || !strings.Contains(fmt.Sprint(det["state"]), "_") {
		t.Errorf("contact must carry a COUNTRY_STATE region code, got %v", det["state"])
	}

	res := r.Register(ctx, free)
	t.Logf("register %s -> %s %s", free, res.Outcome, res.Message)
	if res.Outcome != Success && res.Outcome != Pending {
		t.Fatalf("test registration failed: %+v", res)
	}
	res = r.Register(ctx, free)
	t.Logf("register again -> %s %s", res.Outcome, res.Message)
	if res.Outcome != Unavailable {
		t.Errorf("second order for the same domain must be unavailable (objectExists), got %s", res.Outcome)
	}

	bad := NewRegery(config.Regery{APIKey: env.Regery.APIKey, APISecret: "wrong"}, env.Contact, false)
	if _, err := bad.Check(ctx, free); err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("wrong secret must give 401, got %v", err)
	}
	res = bad.Register(ctx, "dc-bad-"+tok+".com")
	t.Logf("register with wrong secret -> %s %s", res.Outcome, res.Message)
	if res.Outcome != Fatal {
		t.Errorf("wrong secret must be fatal, got %s", res.Outcome)
	}
}

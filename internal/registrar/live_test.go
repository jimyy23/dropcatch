package registrar

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"dropcatch/internal/config"
)

// Live tests against registrar sandboxes. They never run by default:
//
//	LIVE_INTERNETBS=1 go test ./internal/registrar -run Live -v
//
// Internet.bs uses its public test server (https://testapi.internet.bs,
// testapi/testpass) regardless of .env credentials, so nothing is bought.
// The registrant contact comes from REGISTRANT_* in the environment.
func TestLiveInternetBSTestServer(t *testing.T) {
	if os.Getenv("LIVE_INTERNETBS") != "1" {
		t.Skip("set LIVE_INTERNETBS=1 to run against testapi.internet.bs")
	}
	env := config.Load()
	b := NewInternetBS(config.InternetBS{APIKey: "testapi", Password: "testpass", Test: true}, env.Contact, false)
	if b.base != "https://testapi.internet.bs" {
		t.Fatalf("refusing to run: base is %s", b.base)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	a, err := b.Check(ctx, "example.com")
	t.Logf("Check example.com -> %+v err=%v", a, err)
	if err != nil || a.Available {
		t.Errorf("example.com should be UNAVAILABLE, got %+v %v", a, err)
	}

	free := fmt.Sprintf("dropcatch-live-%d.com", rand.Int63())
	a, err = b.Check(ctx, free)
	t.Logf("Check %s -> %+v err=%v", free, a, err)

	res := b.Register(ctx, "example.com")
	t.Logf("Create example.com -> %s ref=%s msg=%s", res.Outcome, res.Ref, res.Message)
	if res.Outcome != Unavailable && res.Outcome != Fatal {
		t.Errorf("registering a taken domain must be unavailable (or fatal on contact data), got %s", res.Outcome)
	}

	res = b.Register(ctx, free)
	t.Logf("Create %s -> %s ref=%s price=%s msg=%s", free, res.Outcome, res.Ref, res.Price, res.Message)
	if res.Outcome == Retryable && res.Ref == "" {
		t.Errorf("unexpected transport-level failure: %s", res.Message)
	}

	bad := NewInternetBS(config.InternetBS{APIKey: "testapi", Password: "wrong", Test: true}, env.Contact, false)
	res = bad.Register(ctx, free)
	t.Logf("Create with wrong password -> %s msg=%s", res.Outcome, res.Message)
	if res.Outcome != Fatal {
		t.Errorf("wrong credentials must be fatal, got %s", res.Outcome)
	}
}

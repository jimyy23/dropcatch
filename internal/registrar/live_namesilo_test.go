package registrar

import (
	"context"
	"os"
	"testing"
	"time"

	"dropcatch/internal/config"
)

// Read-only test against the NameSilo production API with the .env key:
//
//	LIVE_NAMESILO=1 go test ./internal/registrar -run LiveNameSilo -v
//
// Only checkRegisterAvailability, getAccountBalance and contactList are
// called. Register runs with dry=true, so registerDomain is never sent.
func TestLiveNameSilo(t *testing.T) {
	if os.Getenv("LIVE_NAMESILO") != "1" {
		t.Skip("set LIVE_NAMESILO=1 to run read-only calls against NameSilo")
	}
	loadDotEnv(t, "../../.env")
	env := config.Load()
	if env.NameSilo.APIKey == "" {
		t.Skip("NAMESILO_API_KEY not set")
	}
	n := NewNameSilo(env.NameSilo, env.Contact, true) // dry: no orders
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if b, err := n.Balances(ctx); err != nil || len(b) == 0 {
		t.Errorf("balance: %v %v", b, err)
	} else {
		t.Logf("balance: %s %s", b[0].Amount, b[0].Currency)
	}
	if env.NameSilo.ContactID != "" {
		ok, err := n.ContactExists(ctx, env.NameSilo.ContactID)
		t.Logf("NAMESILO_CONTACT_ID exists: %v err=%v", ok, err)
		if err != nil || !ok {
			t.Errorf("configured contact id is not valid")
		}
	}
	for d, want := range map[string]bool{"example.com": false, "google.com": false, "dropcatch-live-probe-81723.org": true} {
		a, err := n.Check(ctx, d)
		t.Logf("check %-32s %+v err=%v", d, a, err)
		if err != nil || a.Available != want {
			t.Errorf("%s: want available=%v", d, want)
		}
	}
	if _, err := n.Check(ctx, "foobar123.lu"); err != ErrUnsupported {
		t.Errorf(".lu should be unsupported by NameSilo, got %v", err)
	}
	if res := n.Register(ctx, "dropcatch-live-probe-81723.org"); res.Outcome != DryRun {
		t.Fatalf("register must be a dry run here, got %s", res.Outcome)
	}
}

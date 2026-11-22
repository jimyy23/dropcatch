package registrar

import (
	"context"
	"os"
	"testing"
	"time"

	"dropcatch/internal/config"
)

// Read-only test against the Spaceship production API with the .env keys:
//
//	LIVE_SPACESHIP=1 go test ./internal/registrar -run LiveSpaceship -v
//
// Calls only GET /available and GET /contacts/{id}; Register runs with dry=true.
func TestLiveSpaceship(t *testing.T) {
	if os.Getenv("LIVE_SPACESHIP") != "1" {
		t.Skip("set LIVE_SPACESHIP=1 to run read-only calls against Spaceship")
	}
	loadDotEnv(t, "../../.env")
	env := config.Load()
	if env.Spaceship.APIKey == "" {
		t.Skip("SPACESHIP_API_KEY not set")
	}
	s := NewSpaceship(env.Spaceship, env.Contact, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for d, want := range map[string]bool{"example.com": false, "dropcatch-ss-probe-81723.com": true} {
		a, err := s.Check(ctx, d)
		t.Logf("check %-30s %+v err=%v", d, a, err)
		if err != nil || a.Available != want {
			t.Errorf("%s: want available=%v", d, want)
		}
	}
	if _, err := s.Check(ctx, "foobar123.lu"); err != ErrUnsupported {
		t.Errorf(".lu should be unsupported, got %v", err)
	}
	if id := env.Spaceship.ContactID; id != "" {
		ok, err := s.ContactExists(ctx, id)
		t.Logf("SPACESHIP_CONTACT_ID exists: %v err=%v", ok, err)
		if !ok {
			t.Errorf("configured contact id not found")
		}
	}
	if res := s.Register(ctx, "dropcatch-ss-probe-81723.com"); res.Outcome != DryRun {
		t.Fatalf("register must be a dry run here, got %s", res.Outcome)
	}
	b, err := AccountBalances(ctx, s)
	t.Logf("balance: %v err=%v", b, err)
}

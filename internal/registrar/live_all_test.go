package registrar

import (
	"context"
	"os"
	"testing"
	"time"

	"dropcatch/internal/config"
)

// Read-only health check of every configured registrar with the real .env:
// credentials, configuration problems, balance and one availability check.
// Orders are dry runs and never sent.
//
//	LIVE_ALL=1 go test ./internal/registrar -run LiveAll -v
func TestLiveAll(t *testing.T) {
	if os.Getenv("LIVE_ALL") != "1" {
		t.Skip("set LIVE_ALL=1")
	}
	loadDotEnv(t, "../../.env")
	env := config.Load()
	regs := []Registrar{
		NewDynadot(env.Dynadot, env.Contact, true),
		NewPorkbun(env.Porkbun, true),
		NewInternetBS(env.InternetBS, env.Contact, true),
		NewNetim(env.Netim, true),
		NewCloudflare(env.Cloudflare, true),
		NewRegery(env.Regery, env.Contact, true),
		NewNameSilo(env.NameSilo, env.Contact, true),
		NewSpaceship(env.Spaceship, env.Contact, true),
	}
	for _, r := range regs {
		if !r.Configured() {
			t.Logf("%-12s not configured", r.Label())
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		b, berr := AccountBalances(ctx, r)
		a, cerr := r.Check(ctx, "example.com")
		res := r.Register(ctx, "example.com")
		cancel()
		t.Logf("%-12s problem=%q balance=%v balErr=%v | example.com available=%v err=%v | register=%s", r.Label(), r.Problem(), b, berr, a.Available, cerr, res.Outcome)
		if r.Problem() != "" {
			t.Errorf("%s: %s", r.Label(), r.Problem())
		}
		if cerr != nil && cerr != ErrUnsupported {
			t.Errorf("%s check failed: %v", r.Label(), cerr)
		}
		// dry mode never orders; Porkbun's dry mode uses its official dryRun
		// quote and so can report unavailable instead of dry_run
		if res.Outcome == Success || res.Outcome == Pending {
			t.Fatalf("%s: register must not succeed in dry mode", r.Label())
		}
	}
}

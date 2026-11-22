package registrar

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"dropcatch/internal/config"
)

// loadDotEnv exports KEY=VALUE lines of the given file (no shell parsing).
func loadDotEnv(t *testing.T, path string) {
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("no %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			t.Setenv(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
}

// Read-only: queries account balances with the real .env keys.
//
//	LIVE_BALANCES=1 go test ./internal/registrar -run LiveBalances -v
func TestLiveBalances(t *testing.T) {
	if os.Getenv("LIVE_BALANCES") != "1" {
		t.Skip("set LIVE_BALANCES=1 to query real account balances (read-only)")
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
	}
	for _, r := range regs {
		if !r.Configured() {
			t.Logf("%-12s not configured", r.Label())
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		b, err := AccountBalances(ctx, r)
		cancel()
		t.Logf("%-12s %+v err=%v", r.Label(), b, err)
	}
}

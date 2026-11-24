package monitor

import (
	"context"
	"os"
	"testing"
	"time"

	"dropcatch/internal/domainutil"
)

// Compare the WHOIS-only lookup with the sidecar's default WHOIS+RDAP merge
// on a sample of suffixes. Read-only.
//
//	LIVE_WHOIS_URL=http://127.0.0.1:18090 go test ./internal/monitor -run LiveWhoisModes -v
func TestLiveWhoisModes(t *testing.T) {
	base := os.Getenv("LIVE_WHOIS_URL")
	if base == "" {
		t.Skip("set LIVE_WHOIS_URL")
	}
	w := NewWhois(base, "", 60*time.Second, 0)
	names := []string{"google.com", "example.org", "bankbazaar.tw", "fe-geant.com.tw", "sina.com.tw", "foobar123.tw",
		"post.lu", "foobar123.lu", "netcup.de", "foobar123xyzq.de", "bbc.co.uk", "nic.at", "nic.ch", "jprs.jp", "nic.io", "foobar123xyzq.io",
		"nic.fr", "google.com.br", "nic.es", "nic.it", "nic.ai", "nic.me", "nic.co", "nic.eu", "nic.be", "nic.nl", "nic.ca", "nic.us", "nic.cn"}
	for _, n := range names {
		d, err := domainutil.Parse(n)
		if err != nil {
			t.Logf("%-20s parse: %v", n, err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		ws, wi, _, _, we := w.lookup(ctx, d.ASCII)
		ms, mi, _, me := w.query(ctx, d.ASCII, "whois")
		_ = ms
		cancel()
		exp := func(i interface{ String() string }) string { return "" }
		_ = exp
		wexp, wcr := "", ""
		if wi != nil {
			wexp, wcr = wi.Expires.Format("2006-01-02"), wi.Created.Format("2006-01-02T15:04:05Z")
		}
		mexp := ""
		if mi != nil {
			mexp = mi.Expires.Format("2006-01-02")
		}
		t.Logf("%-20s lookup=%-14s exp=%s created=%s err=%v | whois-only=%s exp=%s err=%v", n, ws, wexp, wcr, we, ms, mexp, me)
	}
}

package monitor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"dropcatch/internal/domainutil"
)

// LIVE_EXTERNAL_WHOIS="https://a/,https://b/" go test ./internal/monitor -run LiveExternal -v
func TestLiveExternalWhois(t *testing.T) {
	eps := os.Getenv("LIVE_EXTERNAL_WHOIS")
	if eps == "" {
		t.Skip("set LIVE_EXTERNAL_WHOIS to a comma-separated endpoint list")
	}
	for _, e := range strings.Split(eps, ",") {
		w := NewExternalWhois(strings.TrimSpace(e), "", 40*time.Second, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		if err := w.Ping(ctx); err != nil {
			t.Errorf("%s ping: %v", w.Name(), err)
		}
		for _, dn := range []string{"bankbazaar.tw", "foobar123.tw", "google.com", "foobar123xyzq.com"} {
			d, _ := domainutil.Parse(dn)
			o := w.Check(ctx, d, false)
			reg := ""
			if o.Info != nil {
				reg = o.Info.Registrar + " exp " + o.Info.Expires.Format("2006-01-02")
			}
			t.Logf("%-55s %-18s -> status=%-11s err=%v %s (%s)", w.Name(), dn, o.Status, o.Err, reg, o.Elapsed.Round(time.Millisecond))
		}
		cancel()
	}
}

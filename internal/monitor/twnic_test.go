package monitor

import (
	"context"
	"os"
	"testing"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/store"
)

func TestParseTWNIC43(t *testing.T) {
	raw := "Domain Name: mbjq.tw\r\n   Domain Status: clientTransferProhibited\r\n   Registrant:\r\n      (Redacted for privacy)\r\n\r\n" +
		"   Record expires on 2027-11-23 14:00:42 (UTC+8)\r\n   Record created on 2026-11-23 14:00:42 (UTC+8)\r\n\r\n" +
		"   Domain servers in listed order:\r\n      ns1.dyna-ns.net     \r\n      ns2.dyna-ns.net     \r\n\r\n" +
		"Registration Service Provider: Dynadot LLC\r\n"
	st, info, err := parseTWNIC43(raw)
	if err != nil || st != store.StatusRegistered || !info.Created.Equal(time.Date(2026, 11, 23, 6, 0, 42, 0, time.UTC)) ||
		info.Registrar != "Dynadot LLC" || len(info.Nameservers) != 2 || !info.Expires.Equal(time.Date(2027, 11, 23, 6, 0, 42, 0, time.UTC)) {
		t.Fatalf("%s %+v %v", st, info, err)
	}
	st, info, _ = parseTWNIC43("Domain Name: sina.com.tw\n   Domain Status: pendingDelete,serverHold,serverTransferProhibited\n   Record expires on 2026-10-27 00:00:00 (UTC+8)\n")
	if st != store.StatusPendingDelete || !info.PendingDelete || len(info.Statuses) != 3 {
		t.Fatalf("pd: %s %+v", st, info)
	}
	if st, _, err := parseTWNIC43("No Found\r\n"); st != store.StatusAvailable || err != nil {
		t.Fatalf("free: %s %v", st, err)
	}
	if _, _, err := parseTWNIC43(""); err == nil {
		t.Fatal("empty must be an error")
	}
	if _, _, err := parseTWNIC43("Server busy"); KindOf(err) != ErrUnparsed {
		t.Fatal("garbage must be unparsed")
	}
}

func TestParseRDAPSnapshot(t *testing.T) {
	body := `{"ldhName":"mbjq.tw","status":["client transfer prohibited"],"events":[{"eventAction":"registration","eventDate":"2026-11-23T06:00:42Z"},
	{"eventAction":"expiration","eventDate":"2027-11-23T06:00:42Z"},{"eventAction":"last changed","eventDate":"2026-11-23T06:01:50Z"},
	{"eventAction":"last update of RDAP database","eventDate":"2026-11-24T01:09:11Z"}],"nameservers":[{"ldhName":"ns1.dyna-ns.net"}],
	"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Dynadot LLC"]]]}]}`
	st, info, err := parseRDAP([]byte(body))
	if err != nil || st != store.StatusRegistered || !info.Snapshot.Equal(time.Date(2026, 11, 24, 1, 9, 11, 0, time.UTC)) || info.Registrar != "Dynadot LLC" {
		t.Fatalf("%s %+v %v", st, info, err)
	}
	st, info, _ = parseRDAP([]byte(`{"ldhName":"sina.com.tw","status":["pendingdelete","server hold"],"events":[]}`))
	if st != store.StatusPendingDelete || !info.PendingDelete {
		t.Fatalf("pd %s", st)
	}
}

func TestSidecarRDAPCarriesSnapshot(t *testing.T) {
	body := `{"code":0,"msg":"ok","data":{"registered":true,"pendingDelete":true,"rdapData":"{\"ldhName\":\"sina.com.tw\",\"events\":[{\"eventAction\":\"last update of RDAP database\",\"eventDate\":\"2026-11-23T05:39:00Z\"}]}"}}`
	_, info, err := parseWhois([]byte(body))
	if err != nil || !info.Snapshot.Equal(time.Date(2026, 11, 23, 5, 39, 0, 0, time.UTC)) {
		t.Fatalf("%+v %v", info, err)
	}
}

// Live, read-only, one request per protocol:
//
//	LIVE_TWNIC=1 go test ./internal/monitor -run LiveTWNIC -v
func TestLiveTWNIC(t *testing.T) {
	if os.Getenv("LIVE_TWNIC") != "1" {
		t.Skip("set LIVE_TWNIC=1")
	}
	tw := NewTWNIC(6 * time.Second)
	ctx := context.Background()
	for _, n := range []string{"mbjq.tw", "sina.com.tw", "costa.com.tw"} {
		d, _ := domainutil.Parse(n)
		o43 := tw.Port43(ctx, d.ASCII)
		od := tw.DNS(ctx, d.ASCII)
		or := tw.RDAP(ctx, d.ASCII)
		snap := ""
		if or.Info != nil {
			snap = or.Info.Snapshot.Format(time.RFC3339)
		}
		t.Logf("%-14s port43=%s %v (%s) | dns=%s %v (%s) | rdap=%s weak=%v snap=%s %v (%s)", n, o43.Status, o43.Err, o43.Elapsed.Round(time.Millisecond),
			od.Status, od.Err, od.Elapsed.Round(time.Millisecond), or.Status, or.Weak, snap, or.Err, or.Elapsed.Round(time.Millisecond))
		time.Sleep(7 * time.Second)
	}
}

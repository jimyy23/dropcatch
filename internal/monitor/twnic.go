package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/store"
)

// SrcTWNIC is the direct .tw registry source (no sidecar, no cache layer).
const SrcTWNIC = "twnic"

// TWNIC queries the .tw registry directly. Measured Nov 2026:
//
//   - port-43 WHOIS (whois.twnic.net.tw) is live, but limited per client IP:
//     one query every 6 s is fine, 3-5 s gets the IP blocked (connections
//     time out) for about 6 minutes. Shared by every .tw domain.
//   - RDAP (ccrdap.twnic.tw) is served by replicas holding different database
//     snapshots ("last update of RDAP database" from minutes to 4+ hours old),
//     so consecutive answers alternate between old and new data. Each answer
//     carries its snapshot time, which the engine uses to discard old ones.
//   - the .tw DNS zone on the authoritative servers is republished every
//     30-90 s and is not rate-limited: a delegation (NS records) appearing
//     for the name is a fresh "registered" signal.
type TWNIC struct {
	whoisAddr  string
	rdapBase   string
	dnsServers []string // authoritative servers for tw and its 2nd-level zones
	http       *http.Client
	gate       *Gate // port 43: one slot per gap for the whole host
	rdapGate   *Gate

	mu           sync.Mutex
	blockedUntil time.Time
	dnsAddrs     []string
	dnsAt        time.Time
	rdapAt       map[string]time.Time // last RDAP request per name (watch mode)
}

// RDAPDue reports whether a watch loop should ask RDAP for name again
// (RDAP snapshots refresh about every 30 min; no need to ask often).
func (t *TWNIC) RDAPDue(name string, every time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rdapAt == nil {
		t.rdapAt = map[string]time.Time{}
	}
	if time.Since(t.rdapAt[name]) < every {
		return false
	}
	t.rdapAt[name] = time.Now()
	return true
}

func NewTWNIC(gap time.Duration) *TWNIC {
	return &TWNIC{
		whoisAddr:  "whois.twnic.net.tw:43",
		rdapBase:   "https://ccrdap.twnic.tw/tw/",
		dnsServers: []string{"a.dns.tw", "d.dns.tw", "e.dns.tw", "g.dns.tw"},
		http:       &http.Client{Timeout: 15 * time.Second},
		gate:       NewGate(gap),
		rdapGate:   NewGate(2 * time.Second),
	}
}

func (t *TWNIC) Name() string           { return SrcTWNIC }
func (t *TWNIC) Label() string          { return "TWNIC direct" }
func (t *TWNIC) SetGap(d time.Duration) { t.gate.SetGap(d) }

// IsTW reports whether a suffix belongs to the .tw registry.
func IsTW(suffix string) bool { return suffix == "tw" || strings.HasSuffix(suffix, ".tw") }

// Blocked reports until when port 43 is considered blocked for this host.
func (t *TWNIC) Blocked() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.blockedUntil
}

func (t *TWNIC) port43Usable() bool { return time.Now().After(t.Blocked()) }

// Check is a normal monitor lookup: port 43 when a slot is free soon (armed
// domains jump the queue), else RDAP. A port-43 failure falls back to RDAP
// in the same call so the source as a whole is not benched.
func (t *TWNIC) Check(ctx context.Context, d domainutil.Name, prio bool) Observation {
	if !IsTW(d.Suffix) {
		return Observation{Source: SrcTWNIC, Err: lerr(ErrUnsupported, "TWNIC: only .tw")}
	}
	var first Observation
	if t.port43Usable() && (prio || time.Until(t.gate.NextFree()) < 15*time.Second) {
		if err := t.gate.Wait(ctx, prio); err == nil {
			o := t.Port43(ctx, d.ASCII)
			if o.Err == nil || KindOf(o.Err) == ErrInvalid {
				return o
			}
			first = o
		}
	}
	o := t.RDAP(ctx, d.ASCII)
	if o.Err != nil && first.Err != nil {
		o.Err = lerr(KindOf(o.Err), "port 43: %v; RDAP: %v", first.Err, o.Err)
	}
	return o
}

// TryPort43 queries port 43 only if a slot is free right now.
func (t *TWNIC) TryPort43(ctx context.Context, name string) (Observation, bool) {
	if !t.port43Usable() || !t.gate.TryNow() {
		return Observation{}, false
	}
	return t.Port43(ctx, name), true
}

// Port43 asks whois.twnic.net.tw. A connection timeout means this host is
// being rate-limited: port 43 is then skipped for 6 minutes.
func (t *TWNIC) Port43(ctx context.Context, name string) (o Observation) {
	o = Observation{Source: SrcTWNIC, Via: "port43", Start: time.Now()}
	defer func() { o.Elapsed = time.Since(o.Start) }()
	dl := net.Dialer{Timeout: 4 * time.Second}
	conn, err := dl.DialContext(ctx, "tcp", t.whoisAddr)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.mu.Lock()
			t.blockedUntil = time.Now().Add(6 * time.Minute)
			t.mu.Unlock()
			o.Err = &LookupError{Kind: ErrRateLimited, Msg: "port 43 connect timed out (per-IP rate limit): skipped for 6 min", RetryAfter: 6 * time.Minute}
			return o
		}
		o.Err = lerr(ErrTransient, "port 43: %v", err)
		return o
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(conn, name+"\r\n"); err != nil {
		o.Err = lerr(ErrTransient, "port 43: %v", err)
		return o
	}
	body, err := io.ReadAll(io.LimitReader(conn, 256<<10))
	o.Raw = string(body)
	if err != nil && len(body) == 0 {
		o.Err = lerr(ErrTransient, "port 43: %v", err)
		return o
	}
	o.Status, o.Info, o.Err = parseTWNIC43(o.Raw)
	if o.Info != nil {
		o.Detail = strings.Join(o.Info.Statuses, ", ")
	}
	return o
}

var taipei = time.FixedZone("UTC+8", 8*3600)

// parseTWNIC43 reads TWNIC's port-43 format:
//
//	Domain Name: mbjq.tw
//	   Domain Status: clientTransferProhibited
//	   Record expires on 2027-11-23 14:00:42 (UTC+8)
//	   Record created on 2026-11-23 14:00:42 (UTC+8)
//	   Domain servers in listed order:
//	      ns1.dyna-ns.net
//	Registration Service Provider: Dynadot LLC
//
// or "No Found" for a free name.
func parseTWNIC43(raw string) (string, *store.Info, error) {
	text := strings.ReplaceAll(raw, "\r", "")
	if strings.TrimSpace(text) == "" {
		return "", nil, lerr(ErrTransient, "port 43: empty answer")
	}
	if strings.Contains(text, "No Found") {
		return store.StatusAvailable, nil, nil
	}
	if !strings.Contains(text, "Domain Name:") {
		return "", nil, lerr(ErrUnparsed, "port 43: unrecognised answer: %.80q", strings.TrimSpace(text))
	}
	info := &store.Info{Source: "port43", WhoisServer: "whois.twnic.net.tw", Raw: raw}
	inNS := false
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case l == "":
			inNS = false
		case strings.HasPrefix(l, "Domain Status:"):
			for _, s := range strings.Split(strings.TrimPrefix(l, "Domain Status:"), ",") {
				if s = strings.TrimSpace(s); s != "" {
					info.Statuses = append(info.Statuses, s)
				}
			}
		case strings.HasPrefix(l, "Record expires on"):
			info.Expires = parseTWTime(strings.TrimPrefix(l, "Record expires on"))
		case strings.HasPrefix(l, "Record created on"):
			info.Created = parseTWTime(strings.TrimPrefix(l, "Record created on"))
		case strings.HasPrefix(l, "Registration Service Provider:"):
			info.Registrar = strings.TrimSpace(strings.TrimPrefix(l, "Registration Service Provider:"))
			inNS = false
		case strings.HasPrefix(l, "Domain servers in listed order:"):
			inNS = true
		case inNS:
			if f := strings.Fields(l); len(f) > 0 {
				info.Nameservers = append(info.Nameservers, strings.TrimSuffix(strings.ToLower(f[0]), "."))
			}
		}
	}
	st := store.StatusRegistered
	for _, s := range info.Statuses {
		switch strings.ToLower(strings.ReplaceAll(s, " ", "")) {
		case "pendingdelete":
			st, info.PendingDelete = store.StatusPendingDelete, true
		case "redemptionperiod":
			if st != store.StatusPendingDelete {
				st, info.Redemption = store.StatusRedemption, true
			}
		}
	}
	return st, info, nil
}

func parseTWTime(s string) time.Time {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "(UTC+8)"))
	t, err := time.ParseInLocation("2006-01-02 15:04:05", s, taipei)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// RDAP asks ccrdap.twnic.tw directly. The name's letter case is randomised
// so each request is a distinct URL for the CDN; the answer's snapshot time
// ("last update of RDAP database") goes into Info.Snapshot. A 404 has no
// snapshot time, so it is marked Weak: it may come from an old snapshot.
func (t *TWNIC) RDAP(ctx context.Context, name string) (o Observation) {
	o = Observation{Source: SrcTWNIC, Via: "rdap"}
	if err := t.rdapGate.Wait(ctx, true); err != nil {
		o.Err = lerr(ErrBusy, "%v", err)
		return o
	}
	o.Start = time.Now()
	defer func() { o.Elapsed = time.Since(o.Start) }()
	// TWNIC answers 429 for some uncached URL forms; retry once with the
	// canonical (possibly CDN-cached) name. Old copies are filtered by their
	// snapshot time.
	var resp *http.Response
	var body []byte
	for _, n := range []string{randomCase(name), strings.ToLower(name)} {
		req, err := http.NewRequestWithContext(ctx, "GET", t.rdapBase+"domain/"+n, nil)
		if err != nil {
			o.Err = lerr(ErrInvalid, "%v", err)
			return o
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		req.Header.Set("Cache-Control", "no-cache")
		r, err := t.http.Do(req)
		if err != nil {
			o.Err = lerr(ErrTransient, "RDAP: %v", err)
			return o
		}
		body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		resp = r
		if r.StatusCode != 429 {
			break
		}
	}
	o.Raw = fmt.Sprintf("HTTP %d x-cache=%s\n%s", resp.StatusCode, resp.Header.Get("X-Cache"), body)
	switch resp.StatusCode {
	case 200:
	case 404:
		o.Status, o.Weak = store.StatusAvailable, true
		return o
	case 429:
		o.Err = &LookupError{Kind: ErrRateLimited, Msg: "RDAP HTTP 429", RetryAfter: time.Minute}
		return o
	default:
		o.Err = lerr(ErrTransient, "RDAP HTTP %d", resp.StatusCode)
		return o
	}
	o.Status, o.Info, o.Err = parseRDAP(body)
	if o.Info != nil {
		o.Info.Source = "rdap"
		o.Detail = strings.Join(o.Info.Statuses, ", ")
	}
	return o
}

func randomCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' && rand.IntN(2) == 0 {
			b[i] = c - 32
		}
	}
	return string(b)
}

type rdapDomain struct {
	LDHName string   `json:"ldhName"`
	Status  []string `json:"status"`
	Events  []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Entities []struct {
		Roles []string        `json:"roles"`
		VCard json.RawMessage `json:"vcardArray"`
	} `json:"entities"`
}

// parseRDAP maps a registry RDAP domain object (RFC 9083).
func parseRDAP(body []byte) (string, *store.Info, error) {
	var r rdapDomain
	if err := json.Unmarshal(body, &r); err != nil || r.LDHName == "" {
		return "", nil, lerr(ErrUnparsed, "RDAP: not a domain object")
	}
	info := &store.Info{Raw: string(body)}
	for _, e := range r.Events {
		at := parseTime(&e.Date)
		switch a := strings.ToLower(e.Action); {
		case a == "registration":
			info.Created = at
		case a == "expiration":
			info.Expires = at
		case a == "last changed":
			info.Updated = at
		case strings.HasPrefix(a, "last update of rdap database"):
			info.Snapshot = at
		}
	}
	for _, n := range r.Nameservers {
		if n.LDHName != "" {
			info.Nameservers = append(info.Nameservers, strings.TrimSuffix(strings.ToLower(n.LDHName), "."))
		}
	}
	for _, e := range r.Entities {
		for _, role := range e.Roles {
			if role == "registrar" {
				info.Registrar = vcardFN(e.VCard)
			}
		}
	}
	st := store.StatusRegistered
	for _, s := range r.Status {
		info.Statuses = append(info.Statuses, s)
		switch strings.ToLower(strings.ReplaceAll(s, " ", "")) {
		case "pendingdelete":
			st, info.PendingDelete = store.StatusPendingDelete, true
		case "redemptionperiod":
			if st != store.StatusPendingDelete {
				st, info.Redemption = store.StatusRedemption, true
			}
		}
	}
	return st, info, nil
}

func vcardFN(raw json.RawMessage) string {
	var v []any
	if json.Unmarshal(raw, &v) != nil || len(v) < 2 {
		return ""
	}
	props, _ := v[1].([]any)
	for _, p := range props {
		if f, ok := p.([]any); ok && len(f) >= 4 && f[0] == "fn" {
			s, _ := f[3].(string)
			return s
		}
	}
	return ""
}

// DNS asks two authoritative .tw servers (no recursion) for the name's
// delegation. NS records => registered and active (Status registered,
// Info.Nameservers). No delegation => Status "not_in_zone": free, pending
// delete (on hold) or registered without nameservers, so it carries no
// verdict. Each answer's zone SOA serial is recorded in Raw.
func (t *TWNIC) DNS(ctx context.Context, name string) (o Observation) {
	o = Observation{Source: SrcTWNIC, Via: "dns", Start: time.Now()}
	defer func() { o.Elapsed = time.Since(o.Start) }()
	addrs := t.servers(ctx)
	if len(addrs) == 0 {
		o.Err = lerr(ErrTransient, "DNS: cannot resolve the .tw servers")
		return o
	}
	// one server per call (rotating), another one on error
	var lines []string
	for _, i := range rand.Perm(len(addrs)) {
		nx, ns, serial, err := queryNS(ctx, addrs[i], name)
		if err != nil {
			lines = append(lines, fmt.Sprintf("%s error: %v", addrs[i], err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if len(ns) > 0 {
			lines = append(lines, fmt.Sprintf("%s NS %s", addrs[i], strings.Join(ns, " ")))
			o.Raw = strings.Join(lines, "\n")
			o.Status = store.StatusRegistered
			o.Info = &store.Info{Source: "dns", Nameservers: ns, Raw: o.Raw}
			o.Detail = "delegated: " + strings.Join(ns, ", ")
			return o
		}
		lines = append(lines, fmt.Sprintf("%s nxdomain=%v zone serial=%d", addrs[i], nx, serial))
		o.Raw = strings.Join(lines, "\n")
		o.Status, o.Detail = StatusNotInZone, "not delegated"
		return o
	}
	o.Raw = strings.Join(lines, "\n")
	o.Err = lerr(ErrTransient, "DNS: %s", o.Raw)
	return o
}

// StatusNotInZone is a DNS answer without delegation: no verdict.
const StatusNotInZone = "not_in_zone"

func (t *TWNIC) servers(ctx context.Context) []string {
	t.mu.Lock()
	if len(t.dnsAddrs) > 0 && time.Since(t.dnsAt) < time.Hour {
		a := t.dnsAddrs
		t.mu.Unlock()
		return a
	}
	t.mu.Unlock()
	var addrs []string
	for _, h := range t.dnsServers {
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, h)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				addrs = append(addrs, net.JoinHostPort(ip.IP.String(), "53"))
				break
			}
		}
	}
	if len(addrs) > 0 {
		t.mu.Lock()
		t.dnsAddrs, t.dnsAt = addrs, time.Now()
		t.mu.Unlock()
	}
	return addrs
}

func queryNS(ctx context.Context, server, name string) (nx bool, ns []string, serial uint32, err error) {
	qn, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return false, nil, 0, err
	}
	id := uint16(rand.IntN(65536))
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: qn, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET})
	msg, err := b.Finish()
	if err != nil {
		return false, nil, 0, err
	}
	dl := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dl.DialContext(ctx, "udp", server)
	if err != nil {
		return false, nil, 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return false, nil, 0, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return false, nil, 0, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil {
		return false, nil, 0, err
	}
	if h.ID != id {
		return false, nil, 0, fmt.Errorf("DNS id mismatch")
	}
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		return false, nil, 0, fmt.Errorf("DNS rcode %v", h.RCode)
	}
	p.SkipAllQuestions()
	ans, _ := p.AllAnswers()
	auth, _ := p.AllAuthorities()
	for _, r := range append(ans, auth...) {
		switch body := r.Body.(type) {
		case *dnsmessage.NSResource:
			if strings.EqualFold(r.Header.Name.String(), qn.String()) {
				ns = append(ns, strings.TrimSuffix(strings.ToLower(body.NS.String()), "."))
			}
		case *dnsmessage.SOAResource:
			serial = body.Serial
		}
	}
	return h.RCode == dnsmessage.RCodeNameError, ns, serial, nil
}

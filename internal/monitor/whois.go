package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/store"
)

// Whois calls the JSON API of reg233/whois-domain-lookup (sidecar service),
// which combines port-43 WHOIS, RDAP and web-based WHOIS with per-ccTLD parsers.
type Whois struct {
	name    string // source name: "whois" (internal sidecar) or "whois:<host>" (external)
	label   string
	base    string
	auth    string
	http    *http.Client
	gates   *Gates // per suffix: registry servers ban aggressive clients
	timeout atomic.Int64
}

func NewWhois(baseURL, password string, timeout, gap time.Duration) *Whois {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	w := &Whois{name: SrcWhois, label: "WHOIS/RDAP", base: strings.TrimRight(strings.TrimSpace(baseURL), "/"), http: &http.Client{}, gates: NewGates(gap)}
	w.timeout.Store(int64(timeout))
	if password != "" {
		h := sha256.Sum256([]byte(password))
		w.auth = "Bearer " + hex.EncodeToString(h[:])
	}
	return w
}

// NewExternalWhois is another deployment of the same PHP program on an
// external server (EXTERNAL_WHOIS_API_ENDPOINTS). It answers with the same
// JSON API and is tried after the internal sidecar, before web checkers and
// registrar APIs. Its own per-suffix spacing protects the remote host.
func NewExternalWhois(baseURL, password string, timeout, gap time.Duration) *Whois {
	w := NewWhois(baseURL, password, timeout, gap)
	if w == nil {
		return nil
	}
	host := w.base
	if u, err := url.Parse(w.base); err == nil && u.Host != "" {
		host = u.Host
	}
	w.name, w.label = SrcWhoisExtPrefix+host, "WHOIS/RDAP @ "+host
	return w
}

// IsWhois reports whether a source name is a WHOIS/RDAP lookup (internal or external).
func IsWhois(name string) bool {
	return name == SrcWhois || strings.HasPrefix(name, SrcWhoisExtPrefix)
}

func (w *Whois) Name() string  { return w.name }
func (w *Whois) Label() string { return w.label }
func (w *Whois) BaseURL() string {
	if w == nil {
		return ""
	}
	return w.base
}
func (w *Whois) SetGap(d time.Duration) { w.gates.SetGap(d) }

// SetTimeout changes the per-request timeout.
func (w *Whois) SetTimeout(d time.Duration) {
	if d > 0 {
		w.timeout.Store(int64(d))
	}
}

type whoisEnvelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

type whoisData struct {
	WhoisData           string  `json:"whoisData"`
	RDAPData            string  `json:"rdapData"`
	Unknown             bool    `json:"unknown"`
	RateLimited         bool    `json:"rateLimited"`
	Reserved            bool    `json:"reserved"`
	Registered          bool    `json:"registered"`
	RegistryWHOISServer string  `json:"registryWHOISServer"`
	RegistryRDAPServer  string  `json:"registryRDAPServer"`
	Registrar           string  `json:"registrar"`
	Created             *string `json:"creationDateISO8601"`
	Expires             *string `json:"expirationDateISO8601"`
	Updated             *string `json:"updatedDateISO8601"`
	Available           *string `json:"availableDateISO8601"`
	Status              []struct {
		Text string `json:"text"`
	} `json:"status"`
	NameServers      []string `json:"nameServers"`
	GracePeriod      bool     `json:"gracePeriod"`
	RedemptionPeriod bool     `json:"redemptionPeriod"`
	PendingDelete    bool     `json:"pendingDelete"`
	Hold             bool     `json:"hold"`
}

func (w *Whois) Check(ctx context.Context, d domainutil.Name, prio bool) Observation {
	start := time.Now()
	o := Observation{Source: w.name}
	if err := w.gates.Get(d.Suffix).Wait(ctx, prio); err != nil {
		o.Err = lerr(ErrBusy, "%v", err)
		return o
	}
	o.Status, o.Info, o.Err = w.lookup(ctx, d.ASCII)
	o.Elapsed = time.Since(start)
	if o.Info != nil {
		o.Detail = strings.Join(o.Info.Statuses, ", ")
	}
	return o
}

// lookup asks the service for one data source at a time, never the
// merged default: in merged mode RDAP flags override WHOIS, and an RDAP
// answer served from a registry CDN cache (TWNIC ccrdap.twnic.tw kept copies
// over 3 h old) made the monitor lag registrations by hours and flap between
// available and pending_delete.
//
// Order: the suffix's preferred source first (RDAP where the bundled
// sidecar busts the registry cache, else port-43/web WHOIS), then the other
// one when the first fails (e.g. port 43 unreachable from this host). An
// answer from either is used as is; failures are never "available".
func (w *Whois) lookup(ctx context.Context, domain string) (string, *store.Info, error) {
	order := []string{"whois", "rdap"}
	if rdapFirst(domainutil.SuffixOf(domain)) {
		order = []string{"rdap", "whois"}
	}
	var firstErr error
	for i, src := range order {
		st, info, err := w.query(ctx, domain, src)
		if err == nil {
			if info != nil {
				info.Source = src
			}
			return st, info, nil
		}
		if i == 0 {
			firstErr = err
		}
		// a rate limit or invalid name is authoritative enough; do not
		// double the load on the registry
		if k := KindOf(err); k == ErrInvalid || ctx.Err() != nil {
			return "", nil, err
		}
	}
	return "", nil, firstErr
}

// rdapFirstTLDs are registries whose RDAP is fresh through the sidecar's
// cache-busting (whois-sidecar/src/RDAP.php) and whose port-43 WHOIS is
// slow or firewalled for some hosts.
var rdapFirstTLDs = map[string]bool{"tw": true}

func rdapFirst(suffix string) bool {
	tld := suffix
	if i := strings.LastIndexByte(suffix, '.'); i >= 0 {
		tld = suffix[i+1:]
	}
	return rdapFirstTLDs[tld]
}

// query runs one lookup with a single data source ("whois" or "rdap").
func (w *Whois) query(ctx context.Context, domain, source string) (string, *store.Info, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(w.timeout.Load()))
	defer cancel()
	q := url.Values{"domain": {domain}, "json": {"1"}, source: {"1"}}
	req, err := http.NewRequestWithContext(ctx, "GET", w.base+"/src/index.php?"+q.Encode(), nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	if w.auth != "" {
		req.Header.Set("Authorization", w.auth)
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return "", nil, lerr(ErrTransient, "whois service: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", nil, lerr(ErrTransient, "whois service: %v", err)
	}
	if resp.StatusCode != 200 {
		k := ErrTransient
		if resp.StatusCode == 429 {
			k = ErrRateLimited
		}
		return "", nil, lerr(k, "whois service HTTP %d", resp.StatusCode)
	}
	st, info, err := parseWhois(body)
	if info != nil && source == "whois" {
		info.Source = "whois"
	}
	return st, info, err
}

// parseWhois maps an upstream answer to a status. Only an explicit
// registered=false with some raw registry data counts as "available"; an
// empty or unparseable answer ("unknown") is never treated as available.
func parseWhois(body []byte) (string, *store.Info, error) {
	var env whoisEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return "", nil, lerr(ErrTransient, "whois service: invalid JSON")
	}
	var a whoisData
	if len(env.Data) > 0 && string(env.Data) != "null" {
		if err := json.Unmarshal(env.Data, &a); err != nil {
			return "", nil, lerr(ErrTransient, "whois service: invalid data")
		}
	}
	if env.Code != 0 {
		m := env.Msg
		switch {
		case a.RateLimited || strings.Contains(m, "rate limit"):
			return "", nil, lerr(ErrRateLimited, "%s", m)
		case strings.HasPrefix(m, "No WHOIS server found"), strings.HasPrefix(m, "No RDAP server found"), strings.HasPrefix(m, "No WHOIS or RDAP server found"), strings.Contains(m, "No WHOIS or RDAP parser"):
			return "", nil, lerr(ErrUnsupported, "%s", m)
		case strings.Contains(m, "is not a valid domain"):
			return "", nil, lerr(ErrInvalid, "%s", m)
		case strings.Contains(m, "Incorrect password"):
			return "", nil, lerr(ErrTransient, "whois service rejected credentials (check WHOIS_PASSWORD)")
		}
		return "", nil, lerr(ErrTransient, "%s", m)
	}
	if a.RateLimited {
		return "", nil, lerr(ErrRateLimited, "registry rate limit")
	}
	if a.Reserved {
		return store.StatusReserved, nil, nil
	}
	if !a.Registered {
		// "unknown" means the parser could not read the answer (e.g. .ch WHOIS
		// returns a registered record the parser does not understand): never
		// treat that as available.
		if a.Unknown {
			return "", nil, lerr(ErrUnparsed, "registry answer could not be parsed")
		}
		return store.StatusAvailable, nil, nil
	}
	info := &store.Info{
		Source:        "whois",
		Registrar:     a.Registrar,
		Created:       parseTime(a.Created),
		Expires:       parseTime(a.Expires),
		Updated:       parseTime(a.Updated),
		AvailableDate: parseTime(a.Available),
		PendingDelete: a.PendingDelete,
		Redemption:    a.RedemptionPeriod,
		WhoisServer:   a.RegistryWHOISServer,
	}
	if a.RDAPData != "" {
		info.Source = "rdap"
		if a.WhoisData != "" {
			info.Source = "whois+rdap"
		}
	}
	if info.WhoisServer == "" {
		info.WhoisServer = a.RegistryRDAPServer
	}
	raw := a.WhoisData
	if raw == "" {
		raw = a.RDAPData
	}
	info.Raw = raw
	seen := map[string]bool{}
	for _, n := range a.NameServers {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n != "" && !seen[n] {
			seen[n] = true
			info.Nameservers = append(info.Nameservers, n)
		}
	}
	for _, s := range a.Status {
		if t := strings.TrimSpace(s.Text); t != "" {
			info.Statuses = append(info.Statuses, t)
		}
	}
	st := store.StatusRegistered
	switch {
	case a.PendingDelete:
		st = store.StatusPendingDelete
	case a.RedemptionPeriod:
		st = store.StatusRedemption
	}
	return st, info, nil
}

func parseTime(p *string) time.Time {
	if p == nil {
		return time.Time{}
	}
	s := strings.TrimSpace(*p)
	for _, f := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC().Truncate(time.Second)
		}
	}
	return time.Time{}
}

// Ping checks the service answers the JSON API. Without a domain, older
// upstream versions serve the HTML page, so this falls back to a lookup of a
// permanently registered name (iana.org) and only needs a JSON reply.
func (w *Whois) Ping(ctx context.Context) error {
	if w == nil {
		return fmt.Errorf("disabled")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	try := func(q string) (whoisEnvelope, error) {
		var env whoisEnvelope
		req, _ := http.NewRequestWithContext(ctx, "GET", w.base+"/src/index.php?"+q, nil)
		req.Header.Set("Accept", "application/json")
		if w.auth != "" {
			req.Header.Set("Authorization", w.auth)
		}
		resp, err := w.http.Do(req)
		if err != nil {
			return env, err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&env); err != nil {
			return env, fmt.Errorf("unexpected response (HTTP %d): not the whois-domain-lookup JSON API", resp.StatusCode)
		}
		return env, nil
	}
	env, err := try("json=1")
	if err != nil {
		env, err = try("json=1&domain=iana.org")
		if err != nil {
			return err
		}
	}
	if strings.Contains(env.Msg, "Incorrect password") {
		return fmt.Errorf("credentials rejected")
	}
	return nil
}

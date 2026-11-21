package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"dropcatch/internal/domainutil"
	"dropcatch/internal/store"
)

const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

// validLabel mirrors registry LDH rules. Cloudean silently strips invalid
// characters and checks a different name, so names are validated here first.
var validLabel = regexp.MustCompile(`^(xn--)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func checkLabel(d domainutil.Name) error {
	if !validLabel.MatchString(d.Label) {
		return lerr(ErrInvalid, "invalid label %q", d.Label)
	}
	return nil
}

// ---------------------------------------------------------------- Cloudean

// Cloudean uses the public HostBill cart endpoint of manage.cloudean.com.
// No session, token or captcha is needed. status "ok" = available,
// "" = not registrable (taken; also invalid names, hence our own validation),
// "notsuppoerted" (sic) = TLD not sold.
type Cloudean struct {
	http *http.Client
	gate *Gate
	sem  chan struct{}
}

func NewCloudean(timeout, gap time.Duration, conc int) *Cloudean {
	if conc < 1 {
		conc = 1
	}
	return &Cloudean{http: &http.Client{Timeout: timeout}, gate: NewGate(gap), sem: make(chan struct{}, conc)}
}

func (c *Cloudean) Name() string           { return SrcCloudean }
func (c *Cloudean) Label() string          { return "Cloudean (web)" }
func (c *Cloudean) SetGap(d time.Duration) { c.gate.SetGap(d) }

func (c *Cloudean) Check(ctx context.Context, d domainutil.Name, prio bool) (o Observation) {
	start := time.Now()
	o = Observation{Source: SrcCloudean}
	defer func() { o.Elapsed = time.Since(start) }()
	if err := checkLabel(d); err != nil {
		o.Err = err
		return o
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		o.Err = lerr(ErrBusy, "%v", ctx.Err())
		return o
	}
	if err := c.gate.Wait(ctx, prio); err != nil {
		o.Err = lerr(ErrBusy, "%v", err)
		return o
	}
	form := url.Values{"cat_id": {"11"}, "sld": {d.Label}, "tld": {"." + d.Suffix}, "product_id": {""}, "product_cycle": {""}}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://manage.cloudean.com/index.php?/cart/v1/checkdomain", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", browserUA)
	resp, err := c.http.Do(req)
	if err != nil {
		o.Err = lerr(ErrTransient, "cloudean: %v", err)
		return o
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == 429 || resp.StatusCode == 403 {
		o.Err = lerr(ErrRateLimited, "cloudean HTTP %d", resp.StatusCode)
		return o
	}
	if resp.StatusCode != 200 {
		o.Err = lerr(ErrTransient, "cloudean HTTP %d", resp.StatusCode)
		return o
	}
	o.Status, o.Detail, o.Err = parseCloudean(body, d)
	return o
}

func parseCloudean(body []byte, d domainutil.Name) (string, string, error) {
	var r struct {
		SLD     string `json:"sld"`
		TLD     string `json:"tld"`
		Status  string `json:"status"`
		Premium bool   `json:"premium"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		// an empty array means the category/TLD is unknown
		if strings.TrimSpace(string(body)) == "[]" {
			return "", "", lerr(ErrUnsupported, "cloudean: suffix not sold")
		}
		return "", "", lerr(ErrTransient, "cloudean: unexpected response")
	}
	switch strings.ToLower(r.Status) {
	case "notsuppoerted", "notsupported":
		return "", "", lerr(ErrUnsupported, "cloudean: suffix not sold")
	}
	// guard against Cloudean checking a mangled name
	if r.SLD != "" && !strings.EqualFold(r.SLD, d.Label) && !strings.EqualFold(r.SLD, strings.TrimSuffix(d.Unicode, "."+d.Suffix)) {
		return "", "", lerr(ErrInvalid, "cloudean checked %q instead of %q", r.SLD, d.Label)
	}
	detail := ""
	if r.Premium {
		detail = "premium"
	}
	switch r.Status {
	case "ok":
		return store.StatusAvailable, detail, nil
	case "":
		return store.StatusRegistered, detail, nil
	}
	return "", "", lerr(ErrTransient, "cloudean: unknown status %q", r.Status)
}

// ---------------------------------------------------------------- Regery

// Regery needs a 3-step handshake (cookies, x-rgcsrf header, signed session
// ticket). Without a valid ticket it returns fast, RANDOM answers, so the
// ticket is refreshed proactively and answers faster than ~250 ms are
// rejected as decoys. The per-IP limit is strict (≈100/hour sustained, 5 min
// cooldown on 429), so a local token bucket keeps us under it and leaves
// headroom for drop-catch (priority) checks.
type Regery struct {
	mu        sync.Mutex
	http      *http.Client
	csrf      string
	ticket    string
	ticketAt  time.Time
	blocked   time.Time
	bucket    float64
	bucketAt  time.Time
	perHour   float64
	burst     float64
	reserve   float64 // tokens kept for priority checks
	minAnswer time.Duration
}

func NewRegery(timeout time.Duration, perHour int) *Regery {
	jar, _ := cookiejar.New(nil)
	if perHour < 1 {
		perHour = 60
	}
	return &Regery{http: &http.Client{Timeout: timeout, Jar: jar}, perHour: float64(perHour), burst: 20, bucket: 10, bucketAt: time.Now(), reserve: 5, minAnswer: 250 * time.Millisecond}
}

func (r *Regery) Name() string  { return SrcRegery }
func (r *Regery) Label() string { return "Regery (web)" }

func (r *Regery) SetPerHour(n int) {
	r.mu.Lock()
	if n > 0 {
		r.perHour = float64(n)
	}
	r.mu.Unlock()
}

// take consumes one token; non-priority callers cannot dip into the reserve.
func (r *Regery) take(prio bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Before(r.blocked) {
		return &LookupError{Kind: ErrRateLimited, Msg: "regery: cooling down after 429", RetryAfter: time.Until(r.blocked)}
	}
	r.bucket += now.Sub(r.bucketAt).Hours() * r.perHour
	if r.bucket > r.burst {
		r.bucket = r.burst
	}
	r.bucketAt = now
	need := 1.0
	if !prio {
		need += r.reserve
	}
	if r.bucket < need {
		return lerr(ErrBusy, "regery: local budget exhausted (protecting per-IP limit)")
	}
	r.bucket--
	return nil
}

func (r *Regery) Check(ctx context.Context, d domainutil.Name, prio bool) (o Observation) {
	start := time.Now()
	o = Observation{Source: SrcRegery}
	defer func() { o.Elapsed = time.Since(start) }()
	if err := checkLabel(d); err != nil {
		o.Err = err
		return o
	}
	if err := r.take(prio); err != nil {
		o.Err = err
		return o
	}
	for attempt := 0; attempt < 2; attempt++ {
		csrf, ticket, err := r.session(ctx, attempt > 0)
		if err != nil {
			o.Err = lerr(ErrTransient, "regery handshake: %v", err)
			return o
		}
		st, detail, retry, err := r.check(ctx, d, csrf, ticket, attempt > 0)
		if retry && attempt == 0 {
			// the retry is another request against the per-IP limit
			if terr := r.take(true); terr != nil {
				o.Err = err
				return o
			}
			continue
		}
		o.Status, o.Detail, o.Err = st, detail, err
		return o
	}
	return o
}

func (r *Regery) session(ctx context.Context, force bool) (string, string, error) {
	r.mu.Lock()
	if !force && r.ticket != "" && time.Since(r.ticketAt) < 5*time.Minute {
		c, t := r.csrf, r.ticket
		r.mu.Unlock()
		return c, t, nil
	}
	r.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://regery.com/", nil)
	req.Header.Set("User-Agent", browserUA)
	resp, err := r.http.Do(req)
	if err != nil {
		return "", "", err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	csrf := ""
	u, _ := url.Parse("https://regery.com/")
	for _, c := range r.http.Jar.Cookies(u) {
		if c.Name == "x-rgcsrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		return "", "", fmt.Errorf("no x-rgcsrf cookie (HTTP %d)", resp.StatusCode)
	}
	req, _ = http.NewRequestWithContext(ctx, "POST", "https://regery.com/api/v1/rg/storeopen/issuesessionticket", nil)
	r.headers(req, csrf)
	resp, err = r.http.Do(req)
	if err != nil {
		return "", "", err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("ticket HTTP %d", resp.StatusCode)
	}
	ticket := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if strings.Count(ticket, ".") < 3 {
		return "", "", fmt.Errorf("unexpected ticket format")
	}
	r.mu.Lock()
	r.csrf, r.ticket, r.ticketAt = csrf, ticket, time.Now()
	r.mu.Unlock()
	return csrf, ticket, nil
}

func (r *Regery) headers(req *http.Request, csrf string) {
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("x-rgcsrf", csrf)
	req.Header.Set("x-forwarded-locale", "En")
	req.Header.Set("Origin", "https://regery.com")
	req.Header.Set("Referer", "https://regery.com/domains/search")
	req.Header.Set("Accept", "application/json, text/plain, */*")
}

// check returns retry=true when the session should be renewed and retried.
func (r *Regery) check(ctx context.Context, d domainutil.Name, csrf, ticket string, fresh bool) (string, string, bool, error) {
	body, _ := json.Marshal(map[string]any{"currency": 0, "domains": d.ASCII, "possibleActions": []int{1, 2, 3, 4}, "validationKey": ticket})
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://regery.com/api/v1/rg/storeopen/checkdomain", strings.NewReader(string(body)))
	r.headers(req, csrf)
	req.Header.Set("Content-Type", "application/json")
	t0 := time.Now()
	resp, err := r.http.Do(req)
	if err != nil {
		return "", "", false, lerr(ErrTransient, "regery: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	elapsed := time.Since(t0)
	switch resp.StatusCode {
	case 200:
	case 429:
		cool := 5 * time.Minute
		var rl struct {
			CoolDown string `json:"CoolDown"`
		}
		if json.Unmarshal(b, &rl) == nil && rl.CoolDown != "" {
			var h, m, s int
			if _, err := fmt.Sscanf(rl.CoolDown, "%d:%d:%d", &h, &m, &s); err == nil {
				cool = time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second
			}
		}
		r.mu.Lock()
		r.blocked = time.Now().Add(cool)
		r.bucket = 0
		r.mu.Unlock()
		return "", "", false, &LookupError{Kind: ErrRateLimited, Msg: "regery: 429 too many requests", RetryAfter: cool}
	case 403:
		return "", "", true, lerr(ErrTransient, "regery: 403 (csrf/session)")
	case 400:
		return "", "", false, lerr(ErrInvalid, "regery: name rejected")
	default:
		return "", "", false, lerr(ErrTransient, "regery HTTP %d", resp.StatusCode)
	}
	var arr []struct {
		DomainName   string `json:"DomainName"`
		IsAvailable  bool   `json:"IsAvailable"`
		IsSupported  bool   `json:"IsSupported"`
		IsPremium    bool   `json:"IsPremium"`
		SupportError any    `json:"SupportError"`
	}
	if err := json.Unmarshal(b, &arr); err != nil || len(arr) == 0 {
		return "", "", false, lerr(ErrTransient, "regery: unexpected response")
	}
	x := arr[0]
	if !x.IsSupported {
		return "", "", false, lerr(ErrUnsupported, "regery: suffix not sold")
	}
	if x.IsAvailable && elapsed < r.minAnswer && !fresh {
		// Possibly a decoy (ticket not accepted). Genuine cached answers can be
		// fast too, so retry once with a brand-new ticket instead of failing.
		return "", "", true, lerr(ErrTransient, "regery: suspiciously fast 'available' (%s)", elapsed.Round(time.Millisecond))
	}
	detail := ""
	if x.IsPremium {
		detail = "premium"
	}
	if x.IsAvailable {
		return store.StatusAvailable, detail, false, nil
	}
	return store.StatusRegistered, detail, false, nil
}

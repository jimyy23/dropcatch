// Package pricing caches which registrars sell a suffix and at what price.
//
// Primary source: nazhumi (https://www.nazhumi.com/llms.txt). GET
// /api/v1?domain=<suffix> returns every registrar that sells the suffix.
// Fallback: miqingju (GET https://api.miqingju.com/api/v1/query?tld=<suffix>),
// which only returns the cheapest registrar per operation, and the miqingju
// full snapshot (/api/v1/snapshot) for the same information in bulk.
// Results are cached in the database (the APIs ask for >= 5 min caching; we
// refresh daily).
package pricing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"dropcatch/internal/store"
)

// Price is one registrar's offer for a suffix.
type Price struct {
	Registrar string  `json:"registrar"` // price-DB key (nazhumi registrar code or lowercased name)
	Name      string  `json:"name"`
	Register  string  `json:"register"`
	Renew     string  `json:"renew"`
	Transfer  string  `json:"transfer"`
	Currency  string  `json:"currency"`
	RegCNY    float64 `json:"reg_cny"`
	Updated   string  `json:"updated"`
}

// Book is the cached data for one suffix.
type Book struct {
	Suffix    string
	Source    string
	FetchedAt time.Time
	Complete  bool // true when the source lists every registrar (nazhumi)
	Prices    []Price
	Error     string
}

// Sells reports whether the price DB lists the registrar key for the suffix.
func (b *Book) Sells(key string) bool {
	for _, p := range b.Prices {
		if p.Registrar == key {
			return true
		}
	}
	return false
}

func (b *Book) Price(key string) *Price {
	for i := range b.Prices {
		if b.Prices[i].Registrar == key {
			return &b.Prices[i]
		}
	}
	return nil
}

// Service fetches and caches books.
type Service struct {
	st   *store.Store
	http *http.Client
	ttl  time.Duration
	mu   sync.Mutex
	inf  map[string]*sync.Mutex
}

func New(st *store.Store, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Service{st: st, http: &http.Client{Timeout: 30 * time.Second}, ttl: ttl, inf: map[string]*sync.Mutex{}}
}

func (s *Service) SetTTL(d time.Duration) {
	if d > 0 {
		s.ttl = d
	}
}

func (s *Service) lock(suffix string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.inf[suffix]
	if !ok {
		m = &sync.Mutex{}
		s.inf[suffix] = m
	}
	return m
}

// Cached returns the stored book without fetching.
func (s *Service) Cached(suffix string) (*Book, bool) {
	si, ok := s.st.GetSuffixInfo(suffix)
	if !ok {
		return nil, false
	}
	b := &Book{Suffix: suffix, Source: si.Source, FetchedAt: si.FetchedAt, Error: si.Error, Complete: si.Source == "nazhumi"}
	json.Unmarshal([]byte(si.Prices), &b.Prices)
	return b, true
}

// Get returns a fresh-enough book, fetching when stale. On fetch failure the
// stale book (if any) is returned.
func (s *Service) Get(ctx context.Context, suffix string, force bool) (*Book, error) {
	l := s.lock(suffix)
	l.Lock()
	defer l.Unlock()
	if b, ok := s.Cached(suffix); ok && !force && b.Error == "" && time.Since(b.FetchedAt) < s.ttl {
		return b, nil
	}
	b, err := s.fetchNazhumi(ctx, suffix)
	if err != nil {
		b2, err2 := s.fetchMiqingju(ctx, suffix)
		if err2 != nil {
			if old, ok := s.Cached(suffix); ok && len(old.Prices) > 0 {
				return old, fmt.Errorf("refresh failed (nazhumi: %v; miqingju: %v), using cached data", err, err2)
			}
			s.save(&Book{Suffix: suffix, Source: "none", FetchedAt: time.Now(), Error: fmt.Sprintf("nazhumi: %v; miqingju: %v", err, err2)})
			return nil, fmt.Errorf("nazhumi: %v; miqingju: %v", err, err2)
		}
		b = b2
	}
	s.save(b)
	return b, nil
}

func (s *Service) save(b *Book) {
	raw, _ := json.Marshal(b.Prices)
	var keys []string
	for _, p := range b.Prices {
		keys = append(keys, p.Registrar)
	}
	s.st.PutSuffixInfo(store.SuffixInfo{Suffix: b.Suffix, Source: b.Source, FetchedAt: b.FetchedAt, Registrars: keys, Prices: string(raw), Error: b.Error})
}

func (s *Service) getJSON(ctx context.Context, u string, v any) error {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dropcatch/1.0 (+self-hosted)")
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// num renders a JSON number or "n/a".
func num(v any) string {
	switch x := v.(type) {
	case float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", x), "0"), ".")
	case string:
		return x
	}
	return ""
}

func (s *Service) fetchNazhumi(ctx context.Context, suffix string) (*Book, error) {
	var r struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Total int `json:"total"`
			Price []struct {
				Registrar     string `json:"registrar"`
				RegistrarName string `json:"registrarname"`
				Register      any    `json:"register"`
				Renew         any    `json:"renew"`
				Transfer      any    `json:"transfer"`
				RegEffCNY     any    `json:"register_eff_cny"`
				Currency      string `json:"currency"`
				Updated       string `json:"updatedtime"`
			} `json:"price"`
		} `json:"data"`
	}
	if err := s.getJSON(ctx, "https://www.nazhumi.com/api/v1?domain="+url.QueryEscape(suffix), &r); err != nil {
		return nil, err
	}
	if r.Code != 100 {
		return nil, fmt.Errorf("code %d %s", r.Code, r.Msg)
	}
	b := &Book{Suffix: suffix, Source: "nazhumi", FetchedAt: time.Now(), Complete: true}
	for _, p := range r.Data.Price {
		cny, _ := p.RegEffCNY.(float64)
		b.Prices = append(b.Prices, Price{Registrar: p.Registrar, Name: p.RegistrarName, Register: num(p.Register), Renew: num(p.Renew),
			Transfer: num(p.Transfer), Currency: strings.ToUpper(p.Currency), RegCNY: cny, Updated: p.Updated + " (UTC+8)"})
	}
	return b, nil
}

// miqingjuKey maps a miqingju registrar display name to a nazhumi-style key.
func miqingjuKey(name string) string {
	k := strings.ToLower(strings.TrimSpace(name))
	switch k {
	case "internet.bs":
		return "internetbs"
	case "ovhcloud":
		return "ovh"
	case "name.com":
		return "namecom"
	}
	return strings.NewReplacer(" ", "", ".", "").Replace(k)
}

func (s *Service) fetchMiqingju(ctx context.Context, suffix string) (*Book, error) {
	var r struct {
		Success bool `json:"success"`
		Data    []struct {
			Type      string  `json:"type"`
			Registrar string  `json:"registrar"`
			Price     float64 `json:"price"`
			Currency  string  `json:"currency"`
			PriceCNY  float64 `json:"price_cny"`
		} `json:"data"`
		Timestamp string `json:"timestamp"`
	}
	if err := s.getJSON(ctx, "https://api.miqingju.com/api/v1/query?tld="+url.QueryEscape(suffix), &r); err != nil {
		return nil, err
	}
	if !r.Success {
		return nil, fmt.Errorf("success=false")
	}
	b := &Book{Suffix: suffix, Source: "miqingju", FetchedAt: time.Now()}
	idx := map[string]int{}
	for _, x := range r.Data {
		k := miqingjuKey(x.Registrar)
		i, ok := idx[k]
		if !ok {
			b.Prices = append(b.Prices, Price{Registrar: k, Name: x.Registrar, Currency: x.Currency, Updated: r.Timestamp})
			i = len(b.Prices) - 1
			idx[k] = i
		}
		p := num(x.Price)
		switch x.Type {
		case "registration":
			b.Prices[i].Register, b.Prices[i].RegCNY = p, x.PriceCNY
		case "renewal":
			b.Prices[i].Renew = p
		case "transfer":
			b.Prices[i].Transfer = p
		}
	}
	return b, nil
}

// Sorted returns prices ordered by registration price (CNY reference).
func (b *Book) Sorted() []Price {
	out := append([]Price(nil), b.Prices...)
	sort.SliceStable(out, func(i, j int) bool {
		a, c := out[i].RegCNY, out[j].RegCNY
		if a == 0 {
			return false
		}
		if c == 0 {
			return true
		}
		return a < c
	})
	return out
}

// Package domainutil normalises user-entered domain names.
package domainutil

import (
	"errors"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Name is a normalised registrable domain.
type Name struct {
	ASCII   string // punycode, lowercase: xn--mller-kva.de
	Unicode string // müller.de
	Label   string // second-level label (ASCII): xn--mller-kva
	Suffix  string // public suffix (ASCII): de, co.uk
}

var profile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(true), idna.BidiRule())

// Parse accepts "example.com", "https://Example.com/path", "müller.de" and
// returns the registrable name. Subdomains are rejected rather than silently
// stripped: drop-catching the wrong name would be expensive.
func Parse(in string) (Name, error) {
	s := strings.TrimSpace(in)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" {
		return Name{}, errors.New("empty domain")
	}
	a, err := profile.ToASCII(s)
	if err != nil {
		return Name{}, errors.New("invalid domain name: " + in)
	}
	suffix, icann := publicsuffix.PublicSuffix(a)
	if !icann && !strings.Contains(suffix, ".") {
		// unknown TLD: PublicSuffix falls back to the last label
		return Name{}, errors.New("unknown top-level domain: " + suffix)
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(a)
	if err != nil {
		return Name{}, errors.New("not a registrable domain: " + in)
	}
	if reg != a {
		return Name{}, errors.New(in + " is a subdomain; enter the registrable name " + reg)
	}
	label := strings.TrimSuffix(a, "."+suffix)
	if len(label) < 1 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return Name{}, errors.New("invalid label: " + label)
	}
	u, err := idna.ToUnicode(a)
	if err != nil {
		u = a
	}
	return Name{ASCII: a, Unicode: u, Label: label, Suffix: suffix}, nil
}

// SuffixOf returns the public suffix of an already-normalised ASCII name.
func SuffixOf(ascii string) string {
	s, _ := publicsuffix.PublicSuffix(ascii)
	return s
}

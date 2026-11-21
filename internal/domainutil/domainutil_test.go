package domainutil

import "testing"

func TestParse(t *testing.T) {
	ok := map[string][3]string{ // input -> ascii, label, suffix
		"foobar123.lu":                 {"foobar123.lu", "foobar123", "lu"},
		" FooBar123.TW ":               {"foobar123.tw", "foobar123", "tw"},
		"https://Example.com/path?x=1": {"example.com", "example", "com"},
		"bbc.co.uk":                    {"bbc.co.uk", "bbc", "co.uk"},
		"müller.de":                    {"xn--mller-kva.de", "xn--mller-kva", "de"},
		"walfer-lsap.lu.":              {"walfer-lsap.lu", "walfer-lsap", "lu"},
	}
	for in, want := range ok {
		n, err := Parse(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if n.ASCII != want[0] || n.Label != want[1] || n.Suffix != want[2] {
			t.Errorf("%q: got %+v", in, n)
		}
	}
	if n, _ := Parse("müller.de"); n.Unicode != "müller.de" {
		t.Errorf("unicode form: %q", n.Unicode)
	}
	for _, in := range []string{"", "com", "www.example.com", "foo_bar!.com", "-abc.com", "example.notarealtld"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

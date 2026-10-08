package dlc

import (
	"slices"
	"strings"
	"testing"
)

func resolve(t *testing.T, lists map[string]string, name string) []string {
	t.Helper()
	ls, err := Parse(lists)
	if err != nil {
		t.Fatal(err)
	}
	es, err := ls.Resolve(name)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.key())
	}
	return out
}

func TestEntryTypesAndComments(t *testing.T) {
	got := resolve(t, map[string]string{"a": `
# whole-line comment
example.com            # default type is domain
domain:Sub.Example.org @cn @ads
full:www.example.net
keyword:track
regexp:^ad[0-9]+\.example\.com$
`}, "a")
	want := []string{
		"domain:example.com:",
		"domain:sub.example.org:ads,cn",
		"full:www.example.net:",
		"keyword:track:",
		`regexp:^ad[0-9]+\.example\.com$:`,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestIncludeIsRecursiveAndCaseInsensitive(t *testing.T) {
	got := resolve(t, map[string]string{
		"Top":  "include:Mid\ntop.com",
		"mid":  "include:leaf\nmid.com",
		"leaf": "leaf.com",
	}, "top")
	want := []string{"domain:leaf.com:", "domain:mid.com:", "domain:top.com:"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAttributeFilters(t *testing.T) {
	lists := map[string]string{
		"src":    "a.com @cn\nb.com @ads\nc.com @cn @ads\nd.com\ne.com @!cn",
		"must":   "include:src @cn",
		"ban":    "include:src @-ads",
		"both":   "include:src @cn @-ads",
		"nested": "include:must @ads", // only entries that survived the first filter and also carry ads
	}
	cases := map[string][]string{
		"must":   {"domain:a.com:cn", "domain:c.com:ads,cn"},
		"ban":    {"domain:a.com:cn", "domain:d.com:", "domain:e.com:!cn"},
		"both":   {"domain:a.com:cn"},
		"nested": {"domain:c.com:ads,cn"},
	}
	for name, want := range cases {
		if got := resolve(t, lists, name); !slices.Equal(got, want) {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

func TestAffiliationAddsEntryToOtherList(t *testing.T) {
	got := resolve(t, map[string]string{"a": "x.com &b", "b": "y.com"}, "b")
	want := []string{"domain:x.com:", "domain:y.com:"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCycleAndMissing(t *testing.T) {
	ls, err := Parse(map[string]string{"a": "include:b", "b": "include:c", "c": "include:a", "d": "include:nope"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ls.Resolve("a"); err == nil || !strings.Contains(err.Error(), "circular") {
		t.Fatalf("want circular include error, got %v", err)
	}
	if _, err := ls.Resolve("d"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want not found error, got %v", err)
	}
	if _, err := ls.Resolve("missing"); err == nil {
		t.Fatal("want error for unknown list")
	}
}

func TestSyntaxErrors(t *testing.T) {
	for _, text := range []string{"bogus:x.com", "include:", "x.com $weird", "include:a @cn extra"} {
		if _, err := Parse(map[string]string{"a": text}); err == nil {
			t.Errorf("%q: want error", text)
		}
	}
}

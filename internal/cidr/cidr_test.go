package cidr

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func strs(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func TestRangeToPrefixes(t *testing.T) {
	cases := []struct {
		start string
		count uint64
		want  []string
	}{
		{"1.0.1.0", 256, []string{"1.0.1.0/24"}},
		{"1.0.8.0", 2048, []string{"1.0.8.0/21"}},
		// 768 = 512 + 256, aligned start
		{"1.0.0.0", 768, []string{"1.0.0.0/23", "1.0.2.0/24"}},
		// unaligned start: 1.0.1.0 + 768 = .1.0/24 then .2.0/23
		{"1.0.1.0", 768, []string{"1.0.1.0/24", "1.0.2.0/23"}},
		{"10.0.0.1", 5, []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31"}},
		{"0.0.0.0", 1 << 32, []string{"0.0.0.0/0"}},
		{"255.255.255.255", 1, []string{"255.255.255.255/32"}},
	}
	for _, c := range cases {
		got, err := RangeToPrefixes(netip.MustParseAddr(c.start), c.count)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(strs(got), c.want) {
			t.Errorf("%s+%d: got %v want %v", c.start, c.count, strs(got), c.want)
		}
	}
	if _, err := RangeToPrefixes(netip.MustParseAddr("255.255.255.255"), 2); err == nil {
		t.Error("want error past the end of the IPv4 space")
	}
	if _, err := RangeToPrefixes(netip.MustParseAddr("1.0.0.0"), 0); err == nil {
		t.Error("want error for zero count")
	}
}

const apnicFixture = `2|apnic|20261009|8|19830613|20261008|+1000
apnic|*|asn|*|1|summary
apnic|*|ipv4|*|5|summary
apnic|*|ipv6|*|2|summary
apnic|CN|asn|4134|1|20020801|allocated
apnic|CN|ipv4|1.0.1.0|256|20110414|allocated
apnic|CN|ipv4|1.0.2.0|512|20110414|allocated
apnic|CN|ipv4|1.0.8.0|768|20110412|assigned
apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated
apnic|CN|ipv4|1.1.0.0|256|20110412|reserved
apnic|CN|ipv6|2001:250::|35|20000101|allocated
apnic|CN|ipv6|2001:250:2000::|35|20000101|allocated
`

func TestParseDelegatedAPNIC(t *testing.T) {
	all, info, err := ParseDelegated(strings.NewReader(apnicFixture), "apnic")
	if err != nil {
		t.Fatal(err)
	}
	got := all["CN"]
	// 1.0.1.0/24 + 1.0.2.0/23 stay (different alignment so no merge); 768 at 1.0.8.0 is /22 minus /24... = /23 + /24.
	want := []string{"1.0.1.0/24", "1.0.2.0/23", "1.0.8.0/23", "1.0.10.0/24", "2001:250::/34"}
	// 2001:250::/35 and 2001:250:2000::/35 are siblings and merge into a /34.
	if !slices.Equal(strs(got), want) {
		t.Fatalf("got %v want %v", strs(got), want)
	}
	if info.Serial != "20261009" || info.EndDate != "20261008" {
		t.Errorf("info = %+v", info)
	}
}

func TestParseDelegatedGroupsByCountry(t *testing.T) {
	in := strings.Replace(apnicFixture, "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n", "apnic|CN|ipv4|1.0.1.0|256|20110414|allocated\napnic|jp|ipv4|1.0.16.0|4096|20110414|assigned\n", 1)
	in = strings.Replace(in, "|20261009|8|", "|20261009|9|", 1)
	in = strings.Replace(in, "apnic|*|ipv4|*|5|summary", "apnic|*|ipv4|*|6|summary", 1)
	all, _, err := ParseDelegated(strings.NewReader(in), "apnic")
	if err != nil {
		t.Fatal(err)
	}
	if got := strs(all["JP"]); !slices.Equal(got, []string{"1.0.16.0/20"}) {
		t.Fatalf("JP = %v", got)
	}
	if len(all["CN"]) != 5 || len(all) != 2 {
		t.Fatalf("CN = %v, countries = %d", strs(all["CN"]), len(all))
	}
}

func TestParseDelegatedRejectsTruncatedOrInconsistentFile(t *testing.T) {
	// The IPv6 records are cut off, as after an interrupted download.
	lines := strings.Split(strings.TrimSpace(apnicFixture), "\n")
	truncated := strings.Join(lines[:len(lines)-2], "\n") + "\n"
	cases := map[string]string{
		"truncated":       truncated,
		"no header":       strings.Join(lines[1:], "\n") + "\n",
		"missing summary": strings.Replace(apnicFixture, "apnic|*|ipv6|*|2|summary\n", "", 1),
		"header total":    strings.Replace(apnicFixture, "|20261009|8|", "|20261009|9|", 1),
		"summary count":   strings.Replace(apnicFixture, "apnic|*|ipv4|*|5|summary", "apnic|*|ipv4|*|6|summary", 1),
	}
	for name, in := range cases {
		if _, _, err := ParseDelegated(strings.NewReader(in), "apnic"); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, _, err := ParseDelegated(strings.NewReader(apnicFixture), "apnic"); err != nil {
		t.Fatalf("the complete fixture must parse: %v", err)
	}
}

func TestParseDelegatedBadRecord(t *testing.T) {
	if _, _, err := ParseDelegated(strings.NewReader("apnic|CN|ipv4|nope|256|20110414|allocated\n"), "apnic"); err == nil {
		t.Error("want error")
	}
}

func TestAggregate(t *testing.T) {
	in := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.0.0/24"),   // sibling of the first: merge into /23
		netip.MustParsePrefix("10.0.0.128/25"), // covered
		netip.MustParsePrefix("10.0.2.0/24"),
		netip.MustParsePrefix("10.0.2.0/24"), // duplicate
		netip.MustParsePrefix("2001:db8::/33"),
		netip.MustParsePrefix("2001:db8:8000::/33"),
	}
	got := strs(Aggregate(in))
	want := []string{"10.0.0.0/23", "10.0.2.0/24", "2001:db8::/32"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSubtractGoogleMinusCloud(t *testing.T) {
	goog := []netip.Prefix{
		netip.MustParsePrefix("8.8.8.0/24"),     // untouched
		netip.MustParsePrefix("34.0.0.0/22"),    // loses 34.0.1.0/24
		netip.MustParsePrefix("35.0.0.0/24"),    // fully inside cloud: dropped
		netip.MustParsePrefix("2001:4860::/32"), // loses a /34
	}
	cloud := []netip.Prefix{
		netip.MustParsePrefix("34.0.1.0/24"),
		netip.MustParsePrefix("35.0.0.0/16"),
		netip.MustParsePrefix("2001:4860:4000::/34"),
	}
	got := strs(Subtract(goog, cloud))
	want := []string{
		"8.8.8.0/24", "34.0.0.0/24", "34.0.2.0/23",
		"2001:4860::/34", "2001:4860:8000::/33",
	}
	// 2001:4860::/32 minus 4000::/34 = 0000::/34 + 8000::/33 (the /34 at 4000 is cut, c000::/34 merges with 8000::/34).
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseGoogleJSON(t *testing.T) {
	js := `{"syncToken":"1","creationTime":"2026-10-08T07:05:05","prefixes":[{"ipv4Prefix":"8.8.4.0/24"},{"ipv6Prefix":"2001:4860::/32"}]}`
	got, g, err := ParseGoogleJSON(strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(strs(got), []string{"8.8.4.0/24", "2001:4860::/32"}) || g.CreationTime == "" {
		t.Fatalf("got %v %+v", strs(got), g)
	}
	if _, _, err := ParseGoogleJSON(strings.NewReader(`{"prefixes":[{}]}`)); err == nil {
		t.Error("want error for a prefix without address")
	}
	for _, empty := range []string{`{}`, `null`, `{"prefixes":[]}`, `{"prefixes":null}`} {
		if _, _, err := ParseGoogleJSON(strings.NewReader(empty)); err == nil {
			t.Errorf("%s: want an error for an empty prefix list", empty)
		}
	}
}

func TestParseLines(t *testing.T) {
	got, err := ParseLines(strings.NewReader("91.108.4.0/22\n# c\n\n91.108.8.0/22\n2a0a:f280::/32 # v6\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(strs(got), []string{"91.108.4.0/22", "91.108.8.0/22", "2a0a:f280::/32"}) {
		t.Fatalf("got %v", strs(got))
	}
	if _, err := ParseLines(strings.NewReader("not-an-ip\n")); err == nil {
		t.Error("want error")
	}
	for _, empty := range []string{"", "\n\n", "# only a comment\n"} {
		if _, err := ParseLines(strings.NewReader(empty)); err == nil {
			t.Errorf("%q: want an error for an empty list", empty)
		}
	}
}

func TestPrivateSpecialPurposeBlocks(t *testing.T) {
	priv := Private()
	contains := func(s string) bool {
		a := netip.MustParseAddr(s)
		for _, p := range priv {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	for _, in := range []string{"10.1.2.3", "172.31.255.255", "192.168.1.1", "169.254.1.1", "127.0.0.1", "224.0.0.251", "255.255.255.255", "fe80::1", "fd00::1", "ff02::fb", "::1", "::", "100.64.0.1", "100.127.255.254", "198.18.0.1", "192.0.2.1", "240.0.0.1"} {
		if !contains(in) {
			t.Errorf("%s should be private", in)
		}
	}
	for _, out := range []string{"8.8.8.8", "172.32.0.1", "100.128.0.1", "198.20.0.1", "2001:4860::1", "::2"} {
		if contains(out) {
			t.Errorf("%s must not be private", out)
		}
	}
}

// The extended files of the other registries: another registry name, a version like 2.3, an
// opaque-id column, and available / reserved records without a country.
const ripeFixture = `2.3|ripencc|1791496799|4|19700101|20261008|+0200
ripencc|*|ipv4|*|3|summary
ripencc|*|asn|*|0|summary
ripencc|*|ipv6|*|1|summary
ripencc|DE|ipv4|2.16.0.0|1048576|20100401|allocated|3a6f
ripencc||ipv4|5.0.0.0|256||available
ripencc|ZZ|ipv4|5.0.1.0|256||reserved|x
ripencc|GB|ipv6|2a00:1450::|32|20100401|assigned|9b1c
`

func TestParseDelegatedExtendedFile(t *testing.T) {
	all, info, err := ParseDelegated(strings.NewReader(ripeFixture), "ripencc")
	if err != nil {
		t.Fatal(err)
	}
	if info.Serial != "1791496799" || len(all) != 2 || !slices.Equal(strs(all["DE"]), []string{"2.16.0.0/12"}) || !slices.Equal(strs(all["GB"]), []string{"2a00:1450::/32"}) {
		t.Fatalf("all = %v info = %+v", all, info)
	}
	// The summary counts the available and reserved records too.
	if _, _, err := ParseDelegated(strings.NewReader(ripeFixture), "arin"); err == nil {
		t.Error("a file of another registry must be refused")
	}
	cut := ripeFixture[:strings.LastIndex(strings.TrimSpace(ripeFixture), "\n")] + "\n"
	if _, _, err := ParseDelegated(strings.NewReader(cut), "ripencc"); err == nil {
		t.Error("a truncated extended file must be refused")
	}
}

func TestMergeCountries(t *testing.T) {
	a := map[string][]netip.Prefix{"US": {netip.MustParsePrefix("1.0.0.0/24")}}
	b := map[string][]netip.Prefix{"US": {netip.MustParsePrefix("1.0.1.0/24")}, "DE": {netip.MustParsePrefix("2.0.0.0/24")}}
	got := MergeCountries(a, b)
	if !slices.Equal(strs(got["US"]), []string{"1.0.0.0/23"}) || len(got["DE"]) != 1 {
		t.Fatalf("got %v", got)
	}
}

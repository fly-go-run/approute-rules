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

const apnicFixture = `2|apnic|20261009|7|19830613|20261008|+1000
apnic|*|asn|*|1|summary
apnic|*|ipv4|*|4|summary
apnic|CN|asn|4134|1|20020801|allocated
apnic|CN|ipv4|1.0.1.0|256|20110414|allocated
apnic|CN|ipv4|1.0.2.0|512|20110414|allocated
apnic|CN|ipv4|1.0.8.0|768|20110412|assigned
apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated
apnic|CN|ipv4|1.1.0.0|256|20110412|reserved
apnic|CN|ipv6|2001:250::|35|20000101|allocated
apnic|CN|ipv6|2001:250:2000::|35|20000101|allocated
`

func TestParseAPNIC(t *testing.T) {
	got, info, err := ParseAPNIC(strings.NewReader(apnicFixture), "CN")
	if err != nil {
		t.Fatal(err)
	}
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

func TestParseAPNICBadRecord(t *testing.T) {
	if _, _, err := ParseAPNIC(strings.NewReader("apnic|CN|ipv4|nope|256|20110414|allocated\n"), "CN"); err == nil {
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
}

func TestPrivateExcludesCGNATAndFakeIP(t *testing.T) {
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
	for _, in := range []string{"10.1.2.3", "172.31.255.255", "192.168.1.1", "169.254.1.1", "127.0.0.1", "224.0.0.251", "255.255.255.255", "fe80::1", "fd00::1", "ff02::fb", "::1"} {
		if !contains(in) {
			t.Errorf("%s should be private", in)
		}
	}
	for _, out := range []string{"100.64.0.1", "100.127.255.254", "198.18.0.1", "8.8.8.8", "172.32.0.1", "2001:4860::1"} {
		if contains(out) {
			t.Errorf("%s must not be private", out)
		}
	}
}

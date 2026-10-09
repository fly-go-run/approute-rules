// Package cidr turns the IP sources (APNIC, Telegram, Google, a fixed private list)
// into sorted, minimal CIDR lists.
package cidr

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Private is the set of special-purpose address blocks (IANA IPv4 and IPv6
// special-purpose registries: "this network", RFC 1918, carrier-grade NAT, loopback,
// link-local, IETF protocol assignments, documentation, 6to4 relay, benchmarking,
// multicast and reserved, unspecified and loopback IPv6, ULA, link-local and
// multicast IPv6). It is the rule set behind the built-in `RULE-SET,geoip-private,
// DIRECT`, so it keeps 100.64.0.0/10 (carrier NAT, also used by tailnets) and
// 198.18.0.0/15 (benchmarking) direct as before. AppRoute's local-network exception
// is a separate, narrower check in the app and is not derived from this list.
func Private() []netip.Prefix {
	return mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
		"::/127", "fc00::/7", "fe80::/10", "ff00::/8",
	)
}

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, v := range s {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

// RangeToPrefixes converts a first address and an address count (APNIC IPv4 records,
// not always a power of two) into the fewest CIDR blocks.
func RangeToPrefixes(start netip.Addr, count uint64) ([]netip.Prefix, error) {
	if !start.Is4() {
		return nil, fmt.Errorf("not an IPv4 address: %s", start)
	}
	if count == 0 {
		return nil, fmt.Errorf("zero count at %s", start)
	}
	a := start.As4()
	cur := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
	if cur+count > 1<<32 {
		return nil, fmt.Errorf("range %s+%d leaves the IPv4 space", start, count)
	}
	var out []netip.Prefix
	for count > 0 {
		size := uint64(1) << 32
		if cur != 0 {
			size = uint64(1) << bits.TrailingZeros64(cur)
		}
		for size > count {
			size >>= 1
		}
		hostBits := bits.TrailingZeros64(size)
		addr := netip.AddrFrom4([4]byte{byte(cur >> 24), byte(cur >> 16), byte(cur >> 8), byte(cur)})
		out = append(out, netip.PrefixFrom(addr, 32-hostBits))
		cur += size
		count -= size
	}
	return out, nil
}

// DelegatedInfo is what the report prints about a delegation file.
type DelegatedInfo struct {
	Serial  string
	EndDate string
}

// ParseDelegated reads a regional registry's delegation file (the format APNIC, ARIN,
// RIPE NCC, LACNIC and AFRINIC share; registry is the name in the first field of a
// record, e.g. "apnic", "ripencc") and returns the allocated and assigned ipv4 / ipv6
// records per country code (upper case, as the file writes it), aggregated. Records of
// the extended files that carry no country (available, reserved) are ignored. The
// file's own header total and summary lines are checked against what was read, so a
// truncated download fails.
func ParseDelegated(r io.Reader, registry string) (map[string][]netip.Prefix, DelegatedInfo, error) {
	byCountry := map[string][]netip.Prefix{}
	var info DelegatedInfo
	haveHeader := false
	declaredTotal := 0
	summary := map[string]int{} // type -> count promised by the summary lines
	seen := map[string]int{}    // type -> records actually read (all countries)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "|")
		// The version line is the only one that does not start with the registry name.
		if len(f) >= 6 && f[0] != registry {
			if f[1] != registry {
				return nil, info, fmt.Errorf("%s: the header names registry %q", registry, f[1])
			}
			info = DelegatedInfo{Serial: f[2], EndDate: f[5]}
			total, err := strconv.Atoi(f[3])
			if err != nil {
				return nil, info, fmt.Errorf("%s line %d: bad record count in the header: %w", registry, n, err)
			}
			haveHeader, declaredTotal = true, total
			continue
		}
		if len(f) == 6 && f[5] == "summary" {
			c, err := strconv.Atoi(f[4])
			if err != nil {
				return nil, info, fmt.Errorf("%s line %d: bad summary count: %w", registry, n, err)
			}
			summary[f[2]] = c
			continue
		}
		if len(f) >= 7 && f[0] == registry {
			seen[f[2]]++
		}
		if len(f) < 7 || len(f[1]) != 2 || f[1] == "ZZ" || (f[6] != "allocated" && f[6] != "assigned") {
			continue
		}
		cc := strings.ToUpper(f[1])
		switch f[2] {
		case "ipv4":
			start, err := netip.ParseAddr(f[3])
			if err != nil {
				return nil, info, fmt.Errorf("%s line %d: %w", registry, n, err)
			}
			count, err := strconv.ParseUint(f[4], 10, 64)
			if err != nil {
				return nil, info, fmt.Errorf("%s line %d: %w", registry, n, err)
			}
			ps, err := RangeToPrefixes(start, count)
			if err != nil {
				return nil, info, fmt.Errorf("%s line %d: %w", registry, n, err)
			}
			byCountry[cc] = append(byCountry[cc], ps...)
		case "ipv6":
			p, err := netip.ParsePrefix(f[3] + "/" + f[4])
			if err != nil {
				return nil, info, fmt.Errorf("%s line %d: %w", registry, n, err)
			}
			byCountry[cc] = append(byCountry[cc], p.Masked())
		}
	}
	if err := sc.Err(); err != nil {
		return nil, info, err
	}
	// A download cut off mid-file still parses record by record, so compare what was read
	// with what the file itself declares: a short file must fail the build.
	if !haveHeader {
		return nil, info, fmt.Errorf("%s: version header line missing", registry)
	}
	total := 0
	for _, typ := range []string{"asn", "ipv4", "ipv6"} {
		want, ok := summary[typ]
		if !ok {
			return nil, info, fmt.Errorf("%s: summary line for %s missing", registry, typ)
		}
		if seen[typ] != want {
			return nil, info, fmt.Errorf("%s: %d %s records read, summary declares %d (truncated file?)", registry, seen[typ], typ, want)
		}
		total += seen[typ]
	}
	if total != declaredTotal {
		return nil, info, fmt.Errorf("%s: %d records read, header declares %d (truncated file?)", registry, total, declaredTotal)
	}
	for cc, ps := range byCountry {
		byCountry[cc] = Aggregate(ps)
	}
	return byCountry, info, nil
}

// MergeCountries joins per-country prefixes of several registries (a country can hold
// space from more than one) and aggregates each.
func MergeCountries(parts ...map[string][]netip.Prefix) map[string][]netip.Prefix {
	out := map[string][]netip.Prefix{}
	for _, m := range parts {
		for cc, ps := range m {
			out[cc] = append(out[cc], ps...)
		}
	}
	for cc, ps := range out {
		out[cc] = Aggregate(ps)
	}
	return out
}

// ParseLines reads one CIDR (or bare address) per line; # starts a comment.
func ParseLines(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := parsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no prefixes")
	}
	return Aggregate(out), nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

// GoogleJSON is the shape of goog.json / cloud.json.
type GoogleJSON struct {
	SyncToken    string `json:"syncToken"`
	CreationTime string `json:"creationTime"`
	Prefixes     []struct {
		IPv4 string `json:"ipv4Prefix"`
		IPv6 string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

func ParseGoogleJSON(r io.Reader) ([]netip.Prefix, GoogleJSON, error) {
	var g GoogleJSON
	if err := json.NewDecoder(r).Decode(&g); err != nil {
		return nil, g, err
	}
	// {} / null / an empty list would make "goog minus cloud" publish every Google range.
	if len(g.Prefixes) == 0 {
		return nil, g, errors.New("no prefixes")
	}
	var out []netip.Prefix
	for i, p := range g.Prefixes {
		s := p.IPv4 + p.IPv6
		if s == "" {
			return nil, g, fmt.Errorf("prefix %d has no address", i)
		}
		pp, err := parsePrefix(s)
		if err != nil {
			return nil, g, fmt.Errorf("prefix %d: %w", i, err)
		}
		out = append(out, pp)
	}
	return Aggregate(out), g, nil
}

// Aggregate sorts, drops prefixes covered by another and merges adjacent siblings, so
// the result is the smallest list covering the same addresses.
func Aggregate(in []netip.Prefix) []netip.Prefix {
	ps := slices.Clone(in)
	for i := range ps {
		ps[i] = ps[i].Masked()
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits() // the shorter prefix (the larger block) first
	})
	var stack []netip.Prefix
	for _, p := range ps {
		if n := len(stack); n > 0 {
			if last := stack[n-1]; last.Addr().BitLen() == p.Addr().BitLen() && last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
				continue
			}
		}
		stack = append(stack, p)
		for len(stack) >= 2 {
			a, b := stack[len(stack)-2], stack[len(stack)-1]
			if a.Bits() != b.Bits() || a.Bits() == 0 || a.Addr().BitLen() != b.Addr().BitLen() {
				break
			}
			pa := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
			pb := netip.PrefixFrom(b.Addr(), b.Bits()-1).Masked()
			if pa != pb || a == b {
				break
			}
			stack = append(stack[:len(stack)-2], pa)
		}
	}
	return stack
}

// Subtract returns the addresses of a that are not in b (Google's documented way to get
// the "Google services" ranges: goog.json minus cloud.json).
func Subtract(a, b []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range a {
		out = diff(p, b, out)
	}
	return Aggregate(out)
}

func diff(p netip.Prefix, cuts []netip.Prefix, out []netip.Prefix) []netip.Prefix {
	var overlapping []netip.Prefix
	for _, c := range cuts {
		if c.Bits() <= p.Bits() && c.Overlaps(p) { // c covers p entirely
			return out
		}
		if c.Overlaps(p) {
			overlapping = append(overlapping, c)
		}
	}
	if len(overlapping) == 0 {
		return append(out, p)
	}
	// p strictly contains some cut: split in two halves and recurse.
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	hiAddr := p.Addr().As16()
	bit := p.Bits() + 1
	if p.Addr().Is4() {
		bit += 96
	}
	hiAddr[(bit-1)/8] |= 0x80 >> ((bit - 1) % 8)
	var hi netip.Prefix
	if p.Addr().Is4() {
		a4 := netip.AddrFrom16(hiAddr).Unmap()
		hi = netip.PrefixFrom(a4, p.Bits()+1)
	} else {
		hi = netip.PrefixFrom(netip.AddrFrom16(hiAddr), p.Bits()+1)
	}
	out = diff(lo, overlapping, out)
	return diff(hi, overlapping, out)
}

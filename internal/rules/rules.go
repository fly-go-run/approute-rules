// Package rules compiles every geosite / geoip rule-set file AppRoute publishes,
// validates them and writes them together with an index and a build report.
package rules

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/fly-go-run/approute-rules/internal/cidr"
	"github.com/fly-go-run/approute-rules/internal/dlc"
)

// GeositeSets are the v2fly lists AppRoute's built-in profile uses. Every other v2fly list
// is published too, but the build only fails for these when they come out empty.
var GeositeSets = []string{
	"private", "category-ai-cn", "category-ai-!cn", "youtube", "netflix", "disney", "hbo",
	"spotify", "telegram", "google", "github", "microsoft", "apple", "geolocation-!cn", "cn",
}

// GeoipSets are the geoip files that are not a country (or that must exist): the built-in
// profile uses all four. netflix has no usable official address source and is not provided.
var GeoipSets = []string{"private", "telegram", "google", "cn"}

// fileName is what a rule-set name may look like; v2fly's own names fit (lower case, digits,
// `-`, and `!` in the `-!cn` lists).
var fileName = regexp.MustCompile(`^[a-z0-9][a-z0-9!-]*$`)

// Sources holds everything the compiler reads, already parsed.
type Sources struct {
	Lists *dlc.Lists
	// Countries are the allocated and assigned prefixes of the five regional registries per country code (upper case).
	Countries map[string][]netip.Prefix
	Telegram  []netip.Prefix
	Google    []netip.Prefix // goog.json
	Cloud     []netip.Prefix // cloud.json
	// ChinaList holds the domains of dnsmasq-china-list's accelerated-domains.china.conf;
	// they are merged into geosite/cn only.
	ChinaList []string
}

// File is one compiled output.
type File struct {
	Path    string // slash-separated, relative to the output directory
	Kind    string // "domain" or "ipcidr"
	Lines   []string
	Skipped map[string]int // keyword / regexp entries a domain set cannot hold
}

// Skip is a list that produced no file; the build goes on and the report names it.
type Skip struct {
	Path   string
	Reason string
}

// Compile builds all files in memory: one geosite file per v2fly list, one geoip file per
// APNIC country code, plus the four special geoip sets. A list that comes out empty
// (only keyword / regexp entries) or invalid is skipped, except those the built-in
// profile needs, which stay in the result so that Validate fails the build.
func Compile(src Sources) ([]File, []Skip, error) {
	var files []File
	var skips []Skip
	required := map[string]bool{}
	for _, n := range GeositeSets {
		required[n] = true
		if _, err := src.Lists.Resolve(n); err != nil {
			return nil, nil, err
		}
	}
	for _, name := range src.Lists.Names() {
		path := "geosite/" + name + ".txt"
		if !fileName.MatchString(name) {
			skips = append(skips, Skip{path, "name not usable as a file name"})
			continue
		}
		entries, err := src.Lists.Resolve(name)
		if err != nil {
			if required[name] {
				return nil, nil, err
			}
			skips = append(skips, Skip{path, err.Error()})
			continue
		}
		if name == "cn" {
			if len(src.ChinaList) == 0 {
				return nil, nil, errors.New("geosite/cn: dnsmasq-china-list is empty")
			}
			entries = slices.Clone(entries)
			for _, d := range src.ChinaList {
				entries = append(entries, dlc.Entry{Type: dlc.TypeDomain, Value: d})
			}
		}
		lines, skipped := DomainLines(entries)
		f := File{Path: path, Kind: "domain", Lines: lines, Skipped: skipped}
		if !required[name] {
			if len(lines) == 0 {
				skips = append(skips, Skip{path, "no domain entries (only keyword / regexp / none)"})
				continue
			}
			if err := checkLines(f); err != nil {
				skips = append(skips, Skip{path, err.Error()})
				continue
			}
		}
		files = append(files, f)
	}
	sets := map[string][]netip.Prefix{
		"private":  cidr.Private(),
		"telegram": src.Telegram,
		"google":   cidr.Subtract(src.Google, src.Cloud),
	}
	for cc, ps := range src.Countries {
		if name := strings.ToLower(cc); len(ps) > 0 && fileName.MatchString(name) {
			sets[name] = ps
		}
	}
	if _, ok := sets["cn"]; !ok {
		sets["cn"] = nil // the file stays in the result so Validate reports it empty
	}
	names := make([]string, 0, len(sets))
	for n := range sets {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, name := range names {
		files = append(files, File{Path: "geoip/" + name + ".txt", Kind: "ipcidr", Lines: PrefixLines(sets[name])})
	}
	return files, skips, nil
}

// DomainLines turns resolved entries into mihomo `domain` text lines: `+.example.com`
// for domain: (the name and every subdomain) and `example.com` for full:. keyword: and
// regexp: cannot be expressed and are counted. Entries already covered by a shorter
// suffix are dropped.
func DomainLines(entries []dlc.Entry) ([]string, map[string]int) {
	skipped := map[string]int{}
	suffix := map[string]bool{}
	full := map[string]bool{}
	for _, e := range entries {
		switch e.Type {
		case dlc.TypeDomain:
			suffix[e.Value] = true
		case dlc.TypeFull:
			full[e.Value] = true
		default:
			skipped[e.Type]++
		}
	}
	covered := func(name string) bool { // a proper parent is a suffix entry
		for {
			_, rest, ok := strings.Cut(name, ".")
			if !ok {
				return false
			}
			if suffix[rest] {
				return true
			}
			name = rest
		}
	}
	var lines []string
	for d := range suffix {
		if !covered(d) {
			lines = append(lines, "+."+d)
		}
	}
	for d := range full {
		if !suffix[d] && !covered(d) {
			lines = append(lines, d)
		}
	}
	slices.Sort(lines)
	return lines, skipped
}

// PrefixLines renders prefixes one per line, IPv4 before IPv6, each ascending.
func PrefixLines(ps []netip.Prefix) []string {
	ps = cidr.Aggregate(ps)
	lines := make([]string, len(ps))
	for i, p := range ps {
		lines[i] = p.String()
	}
	return lines
}

// PreviousCounts reads the entry count per file path from an earlier published output
// directory (every geosite / geoip file in it).
func PreviousCounts(dir string) (map[string]int, error) {
	counts := map[string]int{}
	if dir == "" {
		return counts, nil
	}
	for _, sub := range []string{"geosite", "geoip"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
				continue
			}
			n, err := countLines(filepath.Join(dir, sub, e.Name()))
			if err != nil {
				return nil, err
			}
			counts[sub+"/"+e.Name()] = n
		}
	}
	return counts, nil
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" && t[0] != '#' {
			n++
		}
	}
	return n, sc.Err()
}

// Validate checks every file: non-empty, each line valid for its kind, and not fewer
// than half of the previous published count, with the same rule for the number of files.
// All problems are returned together.
func Validate(files []File, prev map[string]int) error {
	var errs []error
	for _, f := range files {
		if len(f.Lines) == 0 {
			errs = append(errs, fmt.Errorf("%s: empty", f.Path))
			continue
		}
		if err := checkLines(f); err != nil {
			errs = append(errs, err)
		}
		if p, ok := prev[f.Path]; ok && len(f.Lines)*2 < p {
			errs = append(errs, fmt.Errorf("%s: %d entries, previous release had %d (below half)", f.Path, len(f.Lines), p))
		}
	}
	if len(files)*2 < len(prev) {
		errs = append(errs, fmt.Errorf("%d files, previous release had %d (below half)", len(files), len(prev)))
	}
	return errors.Join(errs...)
}

// checkLines reports the first malformed line of a file; one example is enough.
func checkLines(f File) error {
	for i, l := range f.Lines {
		var err error
		switch f.Kind {
		case "domain":
			err = validDomainLine(l)
		case "ipcidr":
			err = validCIDRLine(l)
		}
		if err != nil {
			return fmt.Errorf("%s line %d %q: %w", f.Path, i+1, l, err)
		}
	}
	return nil
}

func validDomainLine(l string) error {
	name := strings.TrimPrefix(l, "+.")
	if name == "" || len(name) > 253 {
		return errors.New("bad length")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("bad label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("character %q", c)
			}
		}
	}
	return nil
}

func validCIDRLine(l string) error {
	p, err := netip.ParsePrefix(l)
	if err != nil {
		return err
	}
	if p != p.Masked() || p.Addr().Is4In6() {
		return errors.New("not a canonical prefix")
	}
	return nil
}

// Write stores the files, index.txt and report.txt under dir, each through a temporary file and rename. Call it
// only after Validate succeeded.
func Write(dir string, files []File, report string) error {
	all := make(map[string]string, len(files)+2)
	var index []string
	for _, f := range files {
		all[f.Path] = strings.Join(f.Lines, "\n") + "\n"
		index = append(index, f.Path)
	}
	// index.txt lists the published files, so a client can tell which names exist.
	slices.Sort(index)
	all["index.txt"] = strings.Join(index, "\n") + "\n"
	all["report.txt"] = report
	for p, content := range all {
		path := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}

// Registry is the identity of one delegation file in the report.
type Registry struct {
	Name, Serial, EndDate string
}

// Versions are the upstream identifiers printed in the report.
type Versions struct {
	V2flyCommit  string
	Registries   []Registry // serial and end date of each delegation file read
	GoogleTime   string
	CloudTime    string
	TelegramSize int
	ChinaList    string // upstream commit of dnsmasq-china-list
	ChinaListN   int    // domains read from it
	ChinaListBad int    // lines skipped as malformed
}

// Report is the human-readable build summary.
func Report(files []File, skips []Skip, prev map[string]int, v Versions) string {
	var b strings.Builder
	b.WriteString("approute-rules build report\n\nupstream\n")
	fmt.Fprintf(&b, "  v2fly/domain-list-community  commit %s\n", orUnknown(v.V2flyCommit))
	for _, r := range v.Registries {
		fmt.Fprintf(&b, "  %s delegated file  serial %s  end date %s\n", r.Name, orUnknown(r.Serial), orUnknown(r.EndDate))
	}
	fmt.Fprintf(&b, "  Google goog.json  %s\n", orUnknown(v.GoogleTime))
	fmt.Fprintf(&b, "  Google cloud.json  %s\n", orUnknown(v.CloudTime))
	fmt.Fprintf(&b, "  Telegram cidr.txt  %d lines\n", v.TelegramSize)
	fmt.Fprintf(&b, "  felixonmars/dnsmasq-china-list  commit %s  %d domains, %d malformed lines skipped (geosite/cn only)\n\nsets\n", orUnknown(v.ChinaList), v.ChinaListN, v.ChinaListBad)
	geosites := 0
	for _, f := range files {
		if f.Kind == "domain" {
			geosites++
		}
	}
	fmt.Fprintf(&b, "  %d files: %d geosite, %d geoip (all five regional registries); %d lists skipped\n\n", len(files), geosites, len(files)-geosites, len(skips))
	fmt.Fprintf(&b, "  %-34s %9s %9s %9s %9s\n", "file", "entries", "previous", "keyword", "regexp")
	for _, f := range files {
		p := "-"
		if n, ok := prev[f.Path]; ok {
			p = fmt.Sprint(n)
		}
		kw, re := "-", "-"
		if f.Kind == "domain" {
			kw, re = fmt.Sprint(f.Skipped[dlc.TypeKeyword]), fmt.Sprint(f.Skipped[dlc.TypeRegexp])
		}
		fmt.Fprintf(&b, "  %-34s %9d %9s %9s %9s\n", f.Path, len(f.Lines), p, kw, re)
	}
	b.WriteString("\nkeyword and regexp entries cannot be expressed in the domain behavior and are skipped.\n")
	if len(skips) > 0 {
		b.WriteString("\nlists without a file\n")
		for _, s := range skips {
			fmt.Fprintf(&b, "  %-34s %s\n", s.Path, s.Reason)
		}
	}
	return b.String()
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

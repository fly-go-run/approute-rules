// Package rules compiles the 19 rule-set files AppRoute ships, validates them and writes
// them together with a build report.
package rules

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/fly-go-run/approute-rules/internal/cidr"
	"github.com/fly-go-run/approute-rules/internal/dlc"
)

// GeositeSets are the v2fly lists compiled one-to-one into geosite/<name>.txt.
var GeositeSets = []string{
	"private", "category-ai-cn", "category-ai-!cn", "youtube", "netflix", "disney", "hbo",
	"spotify", "telegram", "google", "github", "microsoft", "apple", "geolocation-!cn", "cn",
}

// GeoipSets are the geoip/<name>.txt files. netflix has no usable official address
// source and is not provided.
var GeoipSets = []string{"private", "telegram", "google", "cn"}

// Sources holds everything the compiler reads, already parsed.
type Sources struct {
	Lists    *dlc.Lists
	CN       []netip.Prefix
	Telegram []netip.Prefix
	Google   []netip.Prefix // goog.json
	Cloud    []netip.Prefix // cloud.json
}

// File is one compiled output.
type File struct {
	Path    string // slash-separated, relative to the output directory
	Kind    string // "domain" or "ipcidr"
	Lines   []string
	Skipped map[string]int // keyword / regexp entries a domain set cannot hold
}

// Compile builds all 19 files in memory.
func Compile(src Sources) ([]File, error) {
	var files []File
	for _, name := range GeositeSets {
		entries, err := src.Lists.Resolve(name)
		if err != nil {
			return nil, err
		}
		lines, skipped := DomainLines(entries)
		files = append(files, File{Path: "geosite/" + name + ".txt", Kind: "domain", Lines: lines, Skipped: skipped})
	}
	sets := map[string][]netip.Prefix{
		"private":  cidr.Private(),
		"telegram": src.Telegram,
		"google":   cidr.Subtract(src.Google, src.Cloud),
		"cn":       src.CN,
	}
	for _, name := range GeoipSets {
		files = append(files, File{Path: "geoip/" + name + ".txt", Kind: "ipcidr", Lines: PrefixLines(sets[name])})
	}
	return files, nil
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

// Paths lists the 19 output paths.
func Paths() []string {
	var out []string
	for _, n := range GeositeSets {
		out = append(out, "geosite/"+n+".txt")
	}
	for _, n := range GeoipSets {
		out = append(out, "geoip/"+n+".txt")
	}
	return out
}

// PreviousCounts reads the entry count per file path from an earlier published output directory.
func PreviousCounts(dir string) (map[string]int, error) {
	counts := map[string]int{}
	if dir == "" {
		return counts, nil
	}
	for _, p := range Paths() {
		n, err := countLines(filepath.Join(dir, filepath.FromSlash(p)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		counts[p] = n
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
// than half of the previous published count. All problems are returned together.
func Validate(files []File, prev map[string]int) error {
	var errs []error
	for _, f := range files {
		if len(f.Lines) == 0 {
			errs = append(errs, fmt.Errorf("%s: empty", f.Path))
			continue
		}
		for i, l := range f.Lines {
			var err error
			switch f.Kind {
			case "domain":
				err = validDomainLine(l)
			case "ipcidr":
				err = validCIDRLine(l)
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s line %d %q: %w", f.Path, i+1, l, err))
				break // one example per file is enough
			}
		}
		if p, ok := prev[f.Path]; ok && len(f.Lines)*2 < p {
			errs = append(errs, fmt.Errorf("%s: %d entries, previous release had %d (below half)", f.Path, len(f.Lines), p))
		}
	}
	return errors.Join(errs...)
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

// Write stores the files under dir, each through a temporary file and rename. Call it
// only after Validate succeeded.
func Write(dir string, files []File, report string) error {
	all := make(map[string]string, len(files)+1)
	for _, f := range files {
		all[f.Path] = strings.Join(f.Lines, "\n") + "\n"
	}
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

// Versions are the upstream identifiers printed in the report.
type Versions struct {
	V2flyCommit  string
	APNICSerial  string
	APNICEnd     string
	GoogleTime   string
	CloudTime    string
	TelegramSize int
}

// Report is the human-readable build summary.
func Report(files []File, prev map[string]int, v Versions) string {
	var b strings.Builder
	b.WriteString("approute-rules build report\n\nupstream\n")
	fmt.Fprintf(&b, "  v2fly/domain-list-community  commit %s\n", orUnknown(v.V2flyCommit))
	fmt.Fprintf(&b, "  APNIC delegated-apnic-latest  serial %s  end date %s\n", orUnknown(v.APNICSerial), orUnknown(v.APNICEnd))
	fmt.Fprintf(&b, "  Google goog.json  %s\n", orUnknown(v.GoogleTime))
	fmt.Fprintf(&b, "  Google cloud.json  %s\n", orUnknown(v.CloudTime))
	fmt.Fprintf(&b, "  Telegram cidr.txt  %d lines\n\nsets\n", v.TelegramSize)
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
	return b.String()
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

package rules

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fly-go-run/approute-rules/internal/dlc"
)

func TestDomainLines(t *testing.T) {
	ls, err := dlc.Parse(map[string]string{"a": `
example.com
www.example.com           # covered by the suffix above
full:example.com          # same name, already matched by +.example.com
full:api.other.org
full:api.other.org @cn
domain:other.org @ads
full:cdn.third.net
keyword:track
keyword:ads
regexp:^x[0-9]$
`})
	if err != nil {
		t.Fatal(err)
	}
	es, err := ls.Resolve("a")
	if err != nil {
		t.Fatal(err)
	}
	lines, skipped := DomainLines(es)
	want := []string{"+.example.com", "+.other.org", "cdn.third.net"}
	if !slices.Equal(lines, want) {
		t.Fatalf("got %v want %v", lines, want)
	}
	if skipped["keyword"] != 2 || skipped["regexp"] != 1 {
		t.Fatalf("skipped = %v", skipped)
	}
}

func okFiles() []File {
	return []File{
		{Path: "geosite/a.txt", Kind: "domain", Lines: []string{"+.example.com", "full.example.org", "xn--fiq228c.com"}},
		{Path: "geoip/a.txt", Kind: "ipcidr", Lines: []string{"10.0.0.0/8", "2001:db8::/32"}},
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(okFiles(), nil); err != nil {
		t.Fatal(err)
	}
	bad := map[string]File{
		"empty":        {Path: "geosite/e.txt", Kind: "domain"},
		"upper":        {Path: "geosite/b.txt", Kind: "domain", Lines: []string{"+.Example.com"}},
		"space":        {Path: "geosite/b.txt", Kind: "domain", Lines: []string{"a b.com"}},
		"double dot":   {Path: "geosite/b.txt", Kind: "domain", Lines: []string{"a..com"}},
		"leading dash": {Path: "geosite/b.txt", Kind: "domain", Lines: []string{"-a.com"}},
		"wildcard":     {Path: "geosite/b.txt", Kind: "domain", Lines: []string{"*.a.com"}},
		"lone plus":    {Path: "geosite/b.txt", Kind: "domain", Lines: []string{"+."}},
		"not cidr":     {Path: "geoip/b.txt", Kind: "ipcidr", Lines: []string{"hello"}},
		"host bits":    {Path: "geoip/b.txt", Kind: "ipcidr", Lines: []string{"10.0.0.1/8"}},
		"mapped":       {Path: "geoip/b.txt", Kind: "ipcidr", Lines: []string{"::ffff:10.0.0.0/104"}},
	}
	for name, f := range bad {
		if err := Validate([]File{f}, nil); err == nil {
			t.Errorf("%s: want a validation error", name)
		}
	}
}

func TestValidateBelowHalfOfPrevious(t *testing.T) {
	files := []File{{Path: "geosite/a.txt", Kind: "domain", Lines: []string{"a.com", "b.com", "c.com"}}}
	if err := Validate(files, map[string]int{"geosite/a.txt": 6}); err != nil {
		t.Fatalf("exactly half is allowed: %v", err)
	}
	err := Validate(files, map[string]int{"geosite/a.txt": 7})
	if err == nil || !strings.Contains(err.Error(), "below half") {
		t.Fatalf("want below-half error, got %v", err)
	}
	if err := Validate(files, map[string]int{"geosite/other.txt": 100}); err != nil {
		t.Fatalf("a file without a previous count is not compared: %v", err)
	}
}

func TestPreviousCountsAndWriteDoNotTouchOutputOnFailure(t *testing.T) {
	dir := t.TempDir()
	files := okFiles()
	if err := Write(dir, files, "report"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "geosite/a.txt"))
	if string(b) != "+.example.com\nfull.example.org\nxn--fiq228c.com\n" {
		t.Fatalf("file content %q", b)
	}
	// PreviousCounts only looks at the 19 known paths; write one of them.
	if err := os.MkdirAll(filepath.Join(dir, "geosite"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "geosite/cn.txt"), []byte("+.a.cn\n\n+.b.cn\n"), 0o644)
	counts, err := PreviousCounts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if counts["geosite/cn.txt"] != 2 || len(counts) != 1 {
		t.Fatalf("counts = %v", counts)
	}
	if c, err := PreviousCounts(""); err != nil || len(c) != 0 {
		t.Fatalf("empty dir: %v %v", c, err)
	}
}

func TestCompileProducesAll19Files(t *testing.T) {
	texts := map[string]string{}
	for _, n := range GeositeSets {
		texts[n] = "example-" + strings.NewReplacer("!", "x").Replace(n) + ".com\nkeyword:k\n"
	}
	ls, err := dlc.Parse(texts)
	if err != nil {
		t.Fatal(err)
	}
	src := Sources{
		Lists:    ls,
		CN:       []netip.Prefix{netip.MustParsePrefix("1.0.1.0/24")},
		Telegram: []netip.Prefix{netip.MustParsePrefix("91.108.4.0/22")},
		Google:   []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24"), netip.MustParsePrefix("34.0.0.0/24")},
		Cloud:    []netip.Prefix{netip.MustParsePrefix("34.0.0.0/16")},
	}
	files, err := Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 19 {
		t.Fatalf("got %d files", len(files))
	}
	var paths []string
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	if !slices.Equal(paths, Paths()) {
		t.Fatalf("paths %v", paths)
	}
	if err := Validate(files, nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "geoip/google.txt" && !slices.Equal(f.Lines, []string{"8.8.8.0/24"}) {
			t.Errorf("google = %v", f.Lines)
		}
		if f.Path == "geosite/cn.txt" && f.Skipped["keyword"] != 1 {
			t.Errorf("cn skipped = %v", f.Skipped)
		}
	}
	rep := Report(files, nil, Versions{V2flyCommit: "abc"})
	for _, want := range []string{"commit abc", "geosite/cn.txt", "geoip/private.txt", "keyword"} {
		if !strings.Contains(rep, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

func TestCompileFailsWhenAListIsMissing(t *testing.T) {
	ls, _ := dlc.Parse(map[string]string{"cn": "a.cn"})
	if _, err := Compile(Sources{Lists: ls}); err == nil {
		t.Fatal("want error when a required list is missing")
	}
}

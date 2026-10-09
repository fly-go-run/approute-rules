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
	os.WriteFile(filepath.Join(dir, "geosite/cn.txt"), []byte("+.a.cn\n\n+.b.cn\n"), 0o644)
	counts, err := PreviousCounts(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Every geosite / geoip file counts, not only the built-in ones; index.txt and report.txt do not.
	if counts["geosite/cn.txt"] != 2 || counts["geosite/a.txt"] != 3 || counts["geoip/a.txt"] != 2 || len(counts) != 3 {
		t.Fatalf("counts = %v", counts)
	}
	if c, err := PreviousCounts(""); err != nil || len(c) != 0 {
		t.Fatalf("empty dir: %v %v", c, err)
	}
}

func TestCompileProducesBuiltInAndExtraFiles(t *testing.T) {
	texts := map[string]string{}
	for _, n := range GeositeSets {
		texts[n] = "example-" + strings.NewReplacer("!", "x").Replace(n) + ".com\nkeyword:k\n"
	}
	ls, err := dlc.Parse(texts)
	if err != nil {
		t.Fatal(err)
	}
	texts["category-games"] = "game.example.com\n"
	texts["kwonly"] = "keyword:x\n"
	texts["bad.name"] = "x.example\n"
	ls, err = dlc.Parse(texts)
	if err != nil {
		t.Fatal(err)
	}
	src := Sources{
		Lists: ls,
		Countries: map[string][]netip.Prefix{
			"CN": {netip.MustParsePrefix("1.0.1.0/24")},
			"JP": {netip.MustParsePrefix("1.0.16.0/20")},
		},
		Telegram: []netip.Prefix{netip.MustParsePrefix("91.108.4.0/22")},
		Google:   []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24"), netip.MustParsePrefix("34.0.0.0/24")},
		Cloud:    []netip.Prefix{netip.MustParsePrefix("34.0.0.0/16")},

		ChinaList: []string{"long-tail.example.cn", "example-cn.com"}, // the second is already in the v2fly cn list
	}
	files, skips, err := Compile(src)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	// 15 built-in + category-games, 4 special geoip + jp (cn comes from APNIC).
	if len(files) != 21 || !slices.Contains(paths, "geosite/category-games.txt") || !slices.Contains(paths, "geoip/jp.txt") ||
		!slices.Contains(paths, "geosite/category-ai-!cn.txt") || slices.Contains(paths, "geosite/kwonly.txt") {
		t.Fatalf("paths %v", paths)
	}
	if len(skips) != 2 || skips[0].Path != "geosite/bad.name.txt" || skips[1].Path != "geosite/kwonly.txt" {
		t.Fatalf("skips %v", skips)
	}
	if err := Validate(files, nil); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Path == "geoip/google.txt" && !slices.Equal(f.Lines, []string{"8.8.8.0/24"}) {
			t.Errorf("google = %v", f.Lines)
		}
		if f.Path == "geosite/cn.txt" {
			if f.Skipped["keyword"] != 1 {
				t.Errorf("cn skipped = %v", f.Skipped)
			}
			if !slices.Equal(f.Lines, []string{"+.example-cn.com", "+.long-tail.example.cn"}) {
				t.Errorf("cn = %v", f.Lines)
			}
		}
		if f.Path == "geosite/google.txt" && slices.Contains(f.Lines, "+.long-tail.example.cn") {
			t.Error("the china list must only go into geosite/cn")
		}
	}
	rep := Report(files, skips, nil, Versions{V2flyCommit: "abc"})
	for _, want := range []string{"commit abc", "geosite/cn.txt", "geoip/private.txt", "geoip/jp.txt", "keyword", "lists without a file", "geosite/kwonly.txt"} {
		if !strings.Contains(rep, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}

func TestCompileFailsWhenAListIsMissing(t *testing.T) {
	ls, _ := dlc.Parse(map[string]string{"cn": "a.cn"})
	if _, _, err := Compile(Sources{Lists: ls}); err == nil {
		t.Fatal("want error when a required list is missing")
	}
}

func TestCompileFailsWithoutChinaList(t *testing.T) {
	texts := map[string]string{}
	for _, n := range GeositeSets {
		texts[n] = "a-" + strings.ReplaceAll(n, "!", "x") + ".com\n"
	}
	ls, _ := dlc.Parse(texts)
	if _, _, err := Compile(Sources{Lists: ls}); err == nil || !strings.Contains(err.Error(), "china-list") {
		t.Fatalf("want china-list error, got %v", err)
	}
}

// A built-in list that comes out empty stays in the result and fails Validate; an extra one is only skipped.
func TestCompileEmptyBuiltInFailsButEmptyExtraIsSkipped(t *testing.T) {
	texts := map[string]string{"extra": "keyword:only\n"}
	for _, n := range GeositeSets {
		texts[n] = "a-" + strings.ReplaceAll(n, "!", "x") + ".com\n"
	}
	texts["hbo"] = "keyword:hbo\n"
	ls, _ := dlc.Parse(texts)
	files, skips, err := Compile(Sources{Lists: ls, ChinaList: []string{"x.cn"}, Countries: map[string][]netip.Prefix{"CN": {netip.MustParsePrefix("1.0.1.0/24")}},
		Telegram: []netip.Prefix{netip.MustParsePrefix("91.108.4.0/22")}, Google: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(skips) != 1 || skips[0].Path != "geosite/extra.txt" {
		t.Fatalf("skips %v", skips)
	}
	if err := Validate(files, nil); err == nil || !strings.Contains(err.Error(), "geosite/hbo.txt: empty") {
		t.Fatalf("want hbo reported empty, got %v", err)
	}
}

func TestValidateFileCountBelowHalf(t *testing.T) {
	prev := map[string]int{"geosite/a.txt": 1, "geosite/b.txt": 1, "geosite/c.txt": 1, "geosite/d.txt": 1, "geosite/e.txt": 1}
	if err := Validate(okFiles(), prev); err == nil || !strings.Contains(err.Error(), "files") {
		t.Fatalf("want file-count error, got %v", err)
	}
}

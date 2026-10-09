package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fly-go-run/approute-rules/internal/rules"
)

func writeFixture(t *testing.T, work string) {
	t.Helper()
	data := filepath.Join(work, "domain-list-community", "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range rules.GeositeSets {
		body := "domain:" + strings.ReplaceAll(n, "!", "x") + ".example\n"
		if err := os.WriteFile(filepath.Join(data, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Lists beyond the 15 the built-in profile needs: one that is published, one that only has keywords.
	for n, body := range map[string]string{"category-games": "domain:games.example\n", "kwonly": "keyword:ads\n"} {
		if err := os.WriteFile(filepath.Join(data, n), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"delegated-apnic-latest":         "2|apnic|20261009|3|19830613|20261008|+1000\napnic|*|asn|*|0|summary\napnic|*|ipv4|*|2|summary\napnic|*|ipv6|*|1|summary\napnic|CN|ipv4|1.0.1.0|256|20110414|allocated\napnic|JP|ipv4|1.0.16.0|4096|20110414|allocated\napnic|CN|ipv6|2001:250::|35|20000101|allocated\n",
		"telegram-cidr.txt":              "91.108.4.0/22\n2a0a:f280::/32\n",
		"goog.json":                      `{"creationTime":"t1","prefixes":[{"ipv4Prefix":"8.8.8.0/24"},{"ipv4Prefix":"34.0.0.0/24"}]}`,
		"cloud.json":                     `{"creationTime":"t2","prefixes":[{"ipv4Prefix":"34.0.0.0/16"}]}`,
		"accelerated-domains.china.conf": "# c\nserver=/long-tail.example.cn/114.114.114.114\nserver=/bad line\n",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(work, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuildWritesOutputAndRefusesToOverwriteOnRegression(t *testing.T) {
	work, out := t.TempDir(), filepath.Join(t.TempDir(), "out")
	writeFixture(t, work)
	if err := runBuild([]string{"-work", work, "-out", out}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"geosite/cn.txt", "geosite/category-games.txt", "geosite/category-ai-!cn.txt", "geoip/cn.txt", "geoip/jp.txt",
		"geoip/private.txt", "geoip/telegram.txt", "geoip/google.txt", "index.txt", "report.txt"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(p))); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "geosite", "kwonly.txt")); err == nil {
		t.Error("a list with only keywords must not be published")
	}
	if idx, _ := os.ReadFile(filepath.Join(out, "index.txt")); !strings.Contains(string(idx), "geoip/jp.txt\n") || strings.Contains(string(idx), "kwonly") {
		t.Errorf("index.txt:\n%s", idx)
	}
	jp, _ := os.ReadFile(filepath.Join(out, "geoip", "jp.txt"))
	if string(jp) != "1.0.16.0/20\n" {
		t.Errorf("geoip/jp.txt = %q", jp)
	}
	rep, _ := os.ReadFile(filepath.Join(out, "report.txt"))
	if !strings.Contains(string(rep), "serial 20261009") || !strings.Contains(string(rep), "geosite/kwonly.txt") {
		t.Errorf("report lacks the APNIC serial:\n%s", rep)
	}

	// A previous release with far more entries makes the new build fail and leaves the output alone.
	prev := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prev, "geoip"), 0o755); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("1.0.0.0/24\n", 10)
	if err := os.WriteFile(filepath.Join(prev, "geoip", "cn.txt"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	out2 := filepath.Join(t.TempDir(), "out2")
	err := runBuild([]string{"-work", work, "-out", out2, "-prev", prev})
	if err == nil || !strings.Contains(err.Error(), "below half") {
		t.Fatalf("want below-half failure, got %v", err)
	}
	if _, statErr := os.Stat(out2); !os.IsNotExist(statErr) {
		t.Errorf("output directory must not exist after a failed validation (stat err %v)", statErr)
	}
}

func TestBuildFailsOnEmptyOrTruncatedSources(t *testing.T) {
	cases := map[string]struct{ file, content string }{
		"empty cloud {}":   {"cloud.json", `{}`},
		"empty cloud null": {"cloud.json", `null`},
		"empty cloud list": {"cloud.json", `{"prefixes":[]}`},
		"empty goog list":  {"goog.json", `{"prefixes":[]}`},
		"empty telegram":   {"telegram-cidr.txt", "# nothing\n"},
		"truncated apnic":  {"delegated-apnic-latest", "2|apnic|20261009|3|19830613|20261008|+1000\napnic|*|asn|*|0|summary\napnic|*|ipv4|*|2|summary\napnic|*|ipv6|*|1|summary\napnic|CN|ipv4|1.0.1.0|256|20110414|allocated\n"},
		"empty china list": {"accelerated-domains.china.conf", "# nothing\n"},
	}
	for name, c := range cases {
		work, out := t.TempDir(), filepath.Join(t.TempDir(), "out")
		writeFixture(t, work)
		if err := os.WriteFile(filepath.Join(work, c.file), []byte(c.content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := runBuild([]string{"-work", work, "-out", out}); err == nil {
			t.Errorf("%s: want the build to fail", name)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("%s: nothing may be written (stat err %v)", name, err)
		}
	}
}

func TestBuildFailsOnMissingList(t *testing.T) {
	work := t.TempDir()
	writeFixture(t, work)
	if err := os.Remove(filepath.Join(work, "domain-list-community", "data", "cn")); err != nil {
		t.Fatal(err)
	}
	if err := runBuild([]string{"-work", work, "-out", filepath.Join(t.TempDir(), "o")}); err == nil {
		t.Fatal("want error")
	}
}

func TestExtractDataKeepsOnlyFlatDataFilesAndReadsCommit(t *testing.T) {
	dir := t.TempDir()
	tgz := filepath.Join(dir, "x.tar.gz")
	f, _ := os.Create(tgz)
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "deadbeef"}})
	add := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	add("top/data/cn", "a.cn\n")
	add("top/data/../../evil", "x")
	add("top/README.md", "x")
	add("top/data/sub/deep", "x")
	tw.Close()
	zw.Close()
	f.Close()

	dest := filepath.Join(dir, "dlc")
	commit, err := extractData(tgz, dest)
	if err != nil {
		t.Fatal(err)
	}
	if commit != "deadbeef" {
		t.Errorf("commit = %q", commit)
	}
	entries, _ := os.ReadDir(filepath.Join(dest, "data"))
	if len(entries) != 1 || entries[0].Name() != "cn" {
		t.Errorf("entries = %v", entries)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil")); err == nil {
		t.Error("path traversal")
	}
}

// rulegen fetches the upstream rule data and compiles AppRoute's rule sets.
//
//	rulegen fetch -work DIR
//	rulegen build -work DIR -out DIR [-prev DIR]
package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/fly-go-run/approute-rules/internal/cidr"
	"github.com/fly-go-run/approute-rules/internal/dlc"
	"github.com/fly-go-run/approute-rules/internal/dnsmasq"
	"github.com/fly-go-run/approute-rules/internal/rules"
)

const (
	v2flyURL    = "https://codeload.github.com/v2fly/domain-list-community/tar.gz/refs/heads/master"
	telegramURL = "https://core.telegram.org/resources/cidr.txt"
	googURL     = "https://www.gstatic.com/ipranges/goog.json"
	cloudURL    = "https://www.gstatic.com/ipranges/cloud.json"
	chinaURL    = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
	chinaAPI    = "https://api.github.com/repos/felixonmars/dnsmasq-china-list/commits/master"
)

// registries are the five regional internet registries. name is the registry field the
// records start with; the extended files add an opaque id column and available / reserved
// records, which the parser ignores.
var registries = []struct{ name, label, url, file string }{
	{"apnic", "APNIC", "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest", "delegated-apnic-latest"},
	{"arin", "ARIN", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest", "delegated-arin-extended-latest"},
	{"ripencc", "RIPE NCC", "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest", "delegated-ripencc-extended-latest"},
	{"lacnic", "LACNIC", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest", "delegated-lacnic-extended-latest"},
	{"afrinic", "AFRINIC", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest", "delegated-afrinic-extended-latest"},
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "fetch":
		err = runFetch(os.Args[2:])
	case "build":
		err = runBuild(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rulegen:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: rulegen fetch -work DIR | rulegen build -work DIR -out DIR [-prev DIR]")
	os.Exit(2)
}

// ---- fetch ----

type versionsFile struct {
	V2flyCommit string `json:"v2flyCommit"`
	ChinaList   string `json:"chinaListCommit,omitempty"`
}

func runFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	work := fs.String("work", "work", "directory the upstream files are downloaded into")
	v2 := fs.String("v2fly-url", v2flyURL, "domain-list-community tar.gz")
	regURL := make([]*string, len(registries))
	for i, r := range registries {
		regURL[i] = fs.String(r.name+"-url", r.url, r.label+" delegation file")
	}
	tg := fs.String("telegram-url", telegramURL, "Telegram cidr.txt")
	gg := fs.String("goog-url", googURL, "goog.json")
	cl := fs.String("cloud-url", cloudURL, "cloud.json")
	ch := fs.String("china-url", chinaURL, "dnsmasq-china-list accelerated-domains.china.conf")
	chAPI := fs.String("china-commit-url", chinaAPI, "GitHub API URL that returns the dnsmasq-china-list head commit ('' to skip)")
	fs.Parse(args)

	if err := os.MkdirAll(*work, 0o755); err != nil {
		return err
	}
	for _, d := range []struct{ url, name string }{
		{*tg, "telegram-cidr.txt"}, {*gg, "goog.json"}, {*cl, "cloud.json"},
		{*ch, "accelerated-domains.china.conf"},
	} {
		if err := download(d.url, filepath.Join(*work, d.name)); err != nil {
			return err
		}
	}
	for i, r := range registries {
		if err := download(*regURL[i], filepath.Join(*work, r.file)); err != nil {
			return err
		}
	}
	tgz := filepath.Join(*work, "domain-list-community.tar.gz")
	if err := download(*v2, tgz); err != nil {
		return err
	}
	commit, err := extractData(tgz, filepath.Join(*work, "domain-list-community"))
	if err != nil {
		return err
	}
	vf := versionsFile{V2flyCommit: commit}
	if *chAPI != "" {
		// Only for the report; a failure (e.g. the API rate limit) leaves it "unknown".
		if sha, err := headCommit(*chAPI); err != nil {
			fmt.Fprintln(os.Stderr, "dnsmasq-china-list commit id not available:", err)
		} else {
			vf.ChinaList = sha
		}
	}
	vb, _ := json.Marshal(vf)
	return os.WriteFile(filepath.Join(*work, "versions.json"), vb, 0o644)
}

func headCommit(url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}
	var v struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", err
	}
	return v.SHA, nil
}

func download(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		lastErr = func() error {
			resp, err := client.Get(url)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s: %s", url, resp.Status)
			}
			tmp := dest + ".tmp"
			f, err := os.Create(tmp)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, resp.Body); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			return os.Rename(tmp, dest)
		}()
		if lastErr == nil {
			fmt.Printf("fetched %s\n", url)
			return nil
		}
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	return lastErr
}

// extractData unpacks <top>/data/* and <top>/LICENSE into dest/data and returns the
// commit id GitHub stores in the archive's global pax header.
func extractData(tgz, dest string) (string, error) {
	f, err := os.Open(tgz)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	if err := os.RemoveAll(dest); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(dest, "data"), 0o755); err != nil {
		return "", err
	}
	commit := ""
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			commit = h.PAXRecords["comment"]
			continue
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		// <top>/data/<name>: flat directory, so only the base name is used.
		parts := strings.Split(path.Clean(h.Name), "/")
		if len(parts) != 3 || parts[1] != "data" || parts[2] == "" || parts[2] == "." || parts[2] == ".." {
			continue
		}
		out, err := os.Create(filepath.Join(dest, "data", parts[2]))
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return "", err
		}
		if err := out.Close(); err != nil {
			return "", err
		}
	}
	return commit, nil
}

// ---- build ----

func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	work := fs.String("work", "work", "directory fetch downloaded into")
	out := fs.String("out", "out", "output directory")
	prevDir := fs.String("prev", "", "previous published output, for the half-count check")
	dataDir := fs.String("v2fly", "", "domain-list-community data directory (default <work>/domain-list-community/data)")
	regFile := make([]*string, len(registries))
	for i, r := range registries {
		regFile[i] = fs.String(r.name, "", r.label+" delegation file (default <work>/"+r.file+")")
	}
	tg := fs.String("telegram", "", "Telegram cidr.txt (default <work>/telegram-cidr.txt)")
	goog := fs.String("goog", "", "goog.json (default <work>/goog.json)")
	cloud := fs.String("cloud", "", "cloud.json (default <work>/cloud.json)")
	china := fs.String("chinalist", "", "accelerated-domains.china.conf (default <work>/accelerated-domains.china.conf)")
	fs.Parse(args)

	def := func(v *string, name string) string {
		if *v != "" {
			return *v
		}
		return filepath.Join(*work, name)
	}

	var src rules.Sources
	var ver rules.Versions
	var err error
	if src.Lists, err = dlc.Load(def(dataDir, "domain-list-community/data")); err != nil {
		return fmt.Errorf("v2fly data: %w", err)
	}
	if vb, err := os.ReadFile(filepath.Join(*work, "versions.json")); err == nil {
		var vf versionsFile
		if json.Unmarshal(vb, &vf) == nil {
			ver.V2flyCommit = vf.V2flyCommit
			ver.ChinaList = vf.ChinaList
		}
	}
	var parts []map[string][]netip.Prefix
	for i, r := range registries {
		f, err := os.Open(def(regFile[i], r.file))
		if err != nil {
			return err
		}
		m, info, err := cidr.ParseDelegated(f, r.name)
		f.Close()
		if err != nil {
			return err
		}
		parts = append(parts, m)
		ver.Registries = append(ver.Registries, rules.Registry{Name: r.label, Serial: info.Serial, EndDate: info.EndDate})
	}
	src.Countries = cidr.MergeCountries(parts...)

	tgPath := def(tg, "telegram-cidr.txt")
	tf, err := os.Open(tgPath)
	if err != nil {
		return err
	}
	src.Telegram, err = cidr.ParseLines(tf)
	tf.Close()
	if err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	tb, _ := os.ReadFile(tgPath)
	ver.TelegramSize = strings.Count(string(tb), "\n")

	gf, err := os.Open(def(goog, "goog.json"))
	if err != nil {
		return err
	}
	var gj cidr.GoogleJSON
	src.Google, gj, err = cidr.ParseGoogleJSON(gf)
	gf.Close()
	if err != nil {
		return fmt.Errorf("goog.json: %w", err)
	}
	ver.GoogleTime = gj.CreationTime
	cf, err := os.Open(def(cloud, "cloud.json"))
	if err != nil {
		return err
	}
	src.Cloud, gj, err = cidr.ParseGoogleJSON(cf)
	cf.Close()
	if err != nil {
		return fmt.Errorf("cloud.json: %w", err)
	}
	ver.CloudTime = gj.CreationTime

	chf, err := os.Open(def(china, "accelerated-domains.china.conf"))
	if err != nil {
		return err
	}
	src.ChinaList, ver.ChinaListBad, err = dnsmasq.ParseServerLines(chf)
	chf.Close()
	if err != nil {
		return fmt.Errorf("dnsmasq-china-list: %w", err)
	}
	ver.ChinaListN = len(src.ChinaList)

	files, skips, err := rules.Compile(src)
	if err != nil {
		return err
	}
	prev, err := rules.PreviousCounts(*prevDir)
	if err != nil {
		return err
	}
	report := rules.Report(files, skips, prev, ver)
	fmt.Print(report)
	if err := rules.Validate(files, prev); err != nil {
		return fmt.Errorf("validation failed, nothing written:\n%w", err)
	}
	return rules.Write(*out, files, report)
}

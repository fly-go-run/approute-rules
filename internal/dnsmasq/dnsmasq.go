// Package dnsmasq reads felixonmars/dnsmasq-china-list (WTFPL), whose
// accelerated-domains.china.conf lists `server=/domain/dns-ip` lines for domains that
// resolve inside mainland China.
package dnsmasq

import (
	"bufio"
	"io"
	"strings"
)

// ParseServerLines returns the domains of the server=/domain/ip lines, lowercased.
// Comments (# at line start or after the line) and blank lines are ignored; a line that
// does not have the shape server=/<valid domain>/<ip> is counted in malformed and skipped.
func ParseServerLines(r io.Reader) (domains []string, malformed int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rest, ok := strings.CutPrefix(line, "server=/")
		if !ok {
			malformed++
			continue
		}
		parts := strings.Split(rest, "/")
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			malformed++
			continue
		}
		d := strings.ToLower(parts[0])
		if !validName(d) {
			malformed++
			continue
		}
		domains = append(domains, d)
	}
	return domains, malformed, sc.Err()
}

func validName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

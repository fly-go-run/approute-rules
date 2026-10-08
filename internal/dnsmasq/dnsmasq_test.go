package dnsmasq

import (
	"slices"
	"strings"
	"testing"
)

func TestParseServerLines(t *testing.T) {
	in := `# header comment
server=/example.cn/114.114.114.114

server=/Mixed.Case.COM/114.114.114.114   # trailing comment
#server=/disabled.com/114.114.114.114 # Disabled: not stable
server=/xn--czrs0t/114.114.114.114
server=/bad domain.com/114.114.114.114
server=/double..dot.com/114.114.114.114
server=/-dash.com/114.114.114.114
server=/no-ip.com/
server=//114.114.114.114
server=/too/many/parts/1.1.1.1
address=/other.com/1.2.3.4
garbage
`
	got, malformed, err := ParseServerLines(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.cn", "mixed.case.com", "xn--czrs0t"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if malformed != 8 {
		t.Fatalf("malformed = %d", malformed)
	}
}

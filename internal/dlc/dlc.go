// Package dlc reads the v2fly/domain-list-community data directory and resolves
// include: lines and @attribute filters the way upstream's own compiler does
// (main.go in v2fly/domain-list-community, MIT): attributes are lowercased, list names
// are case-insensitive, `include:x @a @-b` keeps entries of x that carry a and not b,
// and an included list is filtered before its own redundant entries are pruned.
package dlc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Entry types as written in the data files.
const (
	TypeDomain  = "domain"
	TypeFull    = "full"
	TypeKeyword = "keyword"
	TypeRegexp  = "regexp"
)

type Entry struct {
	Type  string
	Value string
	Attrs []string // sorted, lowercase
}

func (e Entry) key() string {
	return e.Type + ":" + e.Value + ":" + strings.Join(e.Attrs, ",")
}

type inclusion struct {
	source string
	must   []string
	ban    []string
}

type list struct {
	entries    []Entry
	inclusions []inclusion
}

// Lists is a parsed data directory; Resolve expands one list.
type Lists struct {
	lists     map[string]*list
	resolved  map[string][]Entry
	resolving map[string]bool
}

// Load parses every file in dir (the data/ directory of the repository).
func Load(dir string) (*Lists, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	ls := &Lists{lists: map[string]*list{}, resolved: map[string][]Entry{}, resolving: map[string]bool{}}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if err := ls.parseFile(strings.ToLower(f.Name()), filepath.Join(dir, f.Name())); err != nil {
			return nil, err
		}
	}
	return ls, nil
}

// Parse reads one list from text; used by tests.
func Parse(texts map[string]string) (*Lists, error) {
	ls := &Lists{lists: map[string]*list{}, resolved: map[string][]Entry{}, resolving: map[string]bool{}}
	for name, text := range texts {
		if err := ls.parseLines(strings.ToLower(name), bufio.NewScanner(strings.NewReader(text)), name); err != nil {
			return nil, err
		}
	}
	return ls, nil
}

func (ls *Lists) parseFile(name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return ls.parseLines(name, bufio.NewScanner(f), path)
}

func (ls *Lists) get(name string) *list {
	l := ls.lists[name]
	if l == nil {
		l = &list{}
		ls.lists[name] = l
	}
	return l
}

func (ls *Lists) parseLines(name string, sc *bufio.Scanner, where string) error {
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	l := ls.get(name)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		typ, rest, typed := strings.Cut(line, ":")
		if !typed {
			typ, rest = TypeDomain, typ
		} else {
			typ = strings.ToLower(typ)
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return fmt.Errorf("%s:%d: empty value", where, n)
		}
		if typ == "include" {
			inc := inclusion{source: strings.ToLower(fields[0])}
			for _, f := range fields[1:] {
				switch {
				case strings.HasPrefix(f, "@-"):
					inc.ban = append(inc.ban, strings.ToLower(f[2:]))
				case strings.HasPrefix(f, "@"):
					inc.must = append(inc.must, strings.ToLower(f[1:]))
				default:
					return fmt.Errorf("%s:%d: unknown field %q in include", where, n, f)
				}
			}
			l.inclusions = append(l.inclusions, inc)
			continue
		}
		e := Entry{Type: typ, Value: fields[0]}
		switch typ {
		case TypeDomain, TypeFull, TypeKeyword:
			e.Value = strings.ToLower(e.Value)
		case TypeRegexp:
		default:
			return fmt.Errorf("%s:%d: unknown rule type %q", where, n, typ)
		}
		var affs []string
		for _, f := range fields[1:] {
			switch {
			case strings.HasPrefix(f, "@"):
				e.Attrs = append(e.Attrs, strings.ToLower(f[1:]))
			case strings.HasPrefix(f, "&"):
				affs = append(affs, strings.ToLower(f[1:]))
			default:
				return fmt.Errorf("%s:%d: unknown field %q", where, n, f)
			}
		}
		slices.Sort(e.Attrs)
		e.Attrs = slices.Compact(e.Attrs)
		l.entries = append(l.entries, e)
		// An affiliation adds the entry to another list as well.
		for _, a := range affs {
			ls.get(a).entries = append(ls.get(a).entries, e)
		}
	}
	return sc.Err()
}

// Names lists every list in the directory, sorted (lower case).
func (ls *Lists) Names() []string {
	names := make([]string, 0, len(ls.lists))
	for n := range ls.lists {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// Resolve returns the entries of a list including everything it includes, deduplicated
// and sorted. A missing list or an include cycle is an error.
func (ls *Lists) Resolve(name string) ([]Entry, error) {
	name = strings.ToLower(name)
	if r, ok := ls.resolved[name]; ok {
		return r, nil
	}
	l := ls.lists[name]
	if l == nil {
		return nil, fmt.Errorf("list %q not found", name)
	}
	if ls.resolving[name] {
		return nil, fmt.Errorf("circular include at %q", name)
	}
	ls.resolving[name] = true
	defer delete(ls.resolving, name)

	seen := map[string]Entry{}
	for _, e := range l.entries {
		seen[e.key()] = e
	}
	for _, inc := range l.inclusions {
		sub, err := ls.Resolve(inc.source)
		if err != nil {
			return nil, fmt.Errorf("include in %q: %w", name, err)
		}
		for _, e := range sub {
			if matches(e, inc) {
				seen[e.key()] = e
			}
		}
	}
	out := make([]Entry, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.key(), b.key()) })
	ls.resolved[name] = out
	return out, nil
}

// matches follows upstream: an entry without attributes passes only when no attribute
// is required (a ban cannot exclude it).
func matches(e Entry, inc inclusion) bool {
	for _, m := range inc.must {
		if !slices.Contains(e.Attrs, m) {
			return false
		}
	}
	for _, b := range inc.ban {
		if slices.Contains(e.Attrs, b) {
			return false
		}
	}
	return true
}

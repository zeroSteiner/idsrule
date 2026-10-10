package dialect

import (
	"fmt"
	"slices"
	"strings"
)

// byName indexes every keyword of every dialect by name.
var byName map[string]Keyword

func init() {
	byName = make(map[string]Keyword, len(commonKeywords)+len(snort2Keywords)+len(suricataKeywords))
	for _, table := range [][]Keyword{commonKeywords, snort2Keywords, suricataKeywords} {
		for _, k := range table {
			if _, dup := byName[k.Name]; dup {
				panic(fmt.Sprintf("dialect: duplicate keyword %q", k.Name))
			}
			byName[k.Name] = k
		}
	}
}

// Lookup returns the keyword named name if it exists in dialect d. It
// never succeeds for Unknown or for an undefined dialect.
func Lookup(d Dialect, name string) (Keyword, bool) {
	k, ok := byName[name]
	if !ok || !k.Dialects.Has(d) {
		return Keyword{}, false
	}
	return k, true
}

// LookupAny returns the keyword named name if it exists in any dialect.
func LookupAny(name string) (Keyword, bool) {
	k, ok := byName[name]
	return k, ok
}

// Keywords returns the keywords of dialect d sorted by name, or every
// keyword of every dialect for Unknown and for a dialect outside the
// defined range. The slice is the caller's.
func Keywords(d Dialect) []Keyword {
	all := d == Unknown || !d.Valid()
	out := make([]Keyword, 0, len(byName))
	for _, k := range byName {
		if all || k.Dialects.Has(d) {
			out = append(out, k)
		}
	}
	slices.SortFunc(out, func(a, b Keyword) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Package dialect names the rule languages the module understands, Snort 2.9
// and Suricata, and detects which one a file is written in from its name.
package dialect

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Dialect identifies a rule language.
type Dialect uint8

const (
	// Unknown means the dialect has not been determined. It is a valid
	// value: callers that accept it typically detect the dialect from the
	// filename.
	Unknown Dialect = iota
	// Snort2 is the Snort 2.9 rule language.
	Snort2
	// Suricata is the Suricata rule language.
	Suricata
)

// String returns "unknown", "snort2" or "suricata", or "Dialect(n)" for a
// value outside the defined range.
func (d Dialect) String() string {
	switch d {
	case Unknown:
		return "unknown"
	case Snort2:
		return "snort2"
	case Suricata:
		return "suricata"
	}
	return fmt.Sprintf("Dialect(%d)", uint8(d))
}

// Valid reports whether d is one of the defined dialects, Unknown included.
func (d Dialect) Valid() bool { return d <= Suricata }

// Set returns the singleton set containing d. Unknown (and any undefined
// value) maps to the empty set.
func (d Dialect) Set() Set {
	switch d {
	case Snort2:
		return SetSnort2
	case Suricata:
		return SetSuricata
	case Unknown:
		return 0
	}
	return 0
}

// Set is a bit set of dialects, used to say which dialects something (a
// keyword, a check) applies to.
type Set uint8

const (
	// SetSnort2 is the set containing only Snort2.
	SetSnort2 Set = 1 << iota
	// SetSuricata is the set containing only Suricata.
	SetSuricata
)

// Both is the set containing Snort2 and Suricata.
const Both = SetSnort2 | SetSuricata

// Has reports whether d is a member of s. Unknown is never a member.
func (s Set) Has(d Dialect) bool {
	ds := d.Set()
	return ds != 0 && s&ds != 0
}

// FromFilename detects the dialect from a file name by its suffix, which is
// matched exactly (case-sensitively) against the base name:
//
//	.snort.rule or .snort.rules       -> Snort2
//	.suricata.rule or .suricata.rules -> Suricata
//
// Any other name yields Unknown.
func FromFilename(name string) Dialect {
	base := filepath.Base(name)
	switch {
	case strings.HasSuffix(base, ".snort.rule"), strings.HasSuffix(base, ".snort.rules"):
		return Snort2
	case strings.HasSuffix(base, ".suricata.rule"), strings.HasSuffix(base, ".suricata.rules"):
		return Suricata
	}
	return Unknown
}

package dialect

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Version is a release of a dialect's engine: its major and minor numbers
// packed as major<<8 | minor, so that versions order as numbers do. Suricata
// 8.0 is Version(8<<8), which NewVersion(8, 0) and Suricata8 both name.
//
// The zero Version, AnyVersion, names no particular release: rules are held
// to what any release the tables describe accepts. A Version means nothing
// on its own; it is a release of the dialect it is used with.
type Version uint16

// AnyVersion is the zero Version: no particular release.
const AnyVersion Version = 0

// The Suricata releases the tables describe.
const (
	// Suricata7 is Suricata 7.0.
	Suricata7 Version = 7 << 8
	// Suricata8 is Suricata 8.0.
	Suricata8 Version = 8 << 8
)

// suricataVersions are the Suricata releases the tables describe, oldest
// first.
var suricataVersions = []Version{Suricata7, Suricata8}

// NewVersion returns the Version major.minor.
func NewVersion(major, minor uint8) Version { return Version(major)<<8 | Version(minor) }

// Major returns v's major number.
func (v Version) Major() uint8 { return uint8(v >> 8) }

// Minor returns v's minor number.
func (v Version) Minor() uint8 { return uint8(v) }

// String returns "any" for AnyVersion and "major.minor" otherwise, such as
// "8.0".
func (v Version) String() string {
	if v == AnyVersion {
		return "any"
	}
	return fmt.Sprintf("%d.%d", v.Major(), v.Minor())
}

// ParseVersion parses a version as a configuration file or a command line
// writes one: "8" or "8.0" for Suricata 8.0, and "" or "any" for
// AnyVersion. It does not check that the version is a release any dialect
// has; see Dialect.HasVersion.
func ParseVersion(s string) (Version, error) {
	if s == "" || strings.EqualFold(s, "any") {
		return AnyVersion, nil
	}
	majorText, minorText, hasMinor := strings.Cut(s, ".")
	major, err := strconv.ParseUint(majorText, 10, 8)
	if err != nil || major == 0 {
		return AnyVersion, fmt.Errorf("invalid version %q", s)
	}
	var minor uint64
	if hasMinor {
		minor, err = strconv.ParseUint(minorText, 10, 8)
		if err != nil {
			return AnyVersion, fmt.Errorf("invalid version %q", s)
		}
	}
	return NewVersion(uint8(major), uint8(minor)), nil
}

// Versions returns the releases of d the tables describe, oldest first. It
// is empty for a dialect the tables describe as a single release, Snort 2.9,
// and for Unknown. The slice is the caller's.
func (d Dialect) Versions() []Version {
	if d == Suricata {
		return slices.Clone(suricataVersions)
	}
	return nil
}

// HasVersion reports whether v is AnyVersion or one of d's Versions.
func (d Dialect) HasVersion(v Version) bool {
	return v == AnyVersion || slices.Contains(d.Versions(), v)
}

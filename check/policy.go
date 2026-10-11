// Package check holds the rule checks and what they run with: the Policy a
// rule set is held to, the Selection of which checks run and how they
// report, the SIDIndex that the cross-file sid check consults, the registry
// the checks are registered in (Register, All, Lookup), the Context a check
// sees for one file, and Run, which executes the selected checks over a
// parsed file and returns their diagnostics.
package check

import (
	"errors"
	"fmt"
	"strings"
)

// Spacing says whether whitespace is required, forbidden or left alone at a
// particular place in a rule.
type Spacing uint8

const (
	// SpacingAny accepts whitespace or its absence.
	SpacingAny Spacing = iota
	// SpacingRequire demands exactly one space.
	SpacingRequire
	// SpacingForbid demands that no whitespace be present.
	SpacingForbid
)

// String returns "any", "require" or "forbid", or "Spacing(n)" for a value
// outside the defined range.
func (s Spacing) String() string {
	switch s {
	case SpacingAny:
		return "any"
	case SpacingRequire:
		return "require"
	case SpacingForbid:
		return "forbid"
	}
	return fmt.Sprintf("Spacing(%d)", uint8(s))
}

// Valid reports whether s is one of the defined Spacing values.
func (s Spacing) Valid() bool { return s <= SpacingForbid }

// StylePolicy configures the purely cosmetic checks.
type StylePolicy struct {
	// ContinuationIndent is the whitespace expected at the start of every
	// continuation line of a rule. "" accepts any indent, provided it is
	// consistent within a rule.
	ContinuationIndent string
	// SpaceAfterColon governs whitespace between an option keyword's colon
	// and its value. The zero value is SpacingAny.
	SpaceAfterColon Spacing
	// SpaceAfterSemicolon governs whitespace after the semicolon that ends
	// an option. DefaultPolicy sets it to SpacingRequire.
	SpaceAfterSemicolon Spacing
}

// Policy is what a rule set is held to by the checks.
type Policy struct {
	// SIDMin and SIDMax bound the allowed sid range, inclusive. Either
	// bound is unchecked when zero.
	SIDMin, SIDMax uint64
	// PlaceholderBelow marks every sid below it as a placeholder that must
	// be replaced before the rule ships. Zero disables the concept.
	PlaceholderBelow uint64
	// RequireRev demands that every rule carry a rev option.
	RequireRev bool
	// MsgPrefix, when non-empty, is the prefix every msg must start with.
	MsgPrefix string
	// NormalizeMsg canonicalizes a msg before messages are compared, for
	// instance to find duplicates. nil means DefaultNormalizeMsg.
	NormalizeMsg func(string) string
	// Style configures the cosmetic checks.
	Style StylePolicy
}

// DefaultPolicy returns the policy used when none is given: a rev is
// required and a space must follow every option-ending semicolon. All other
// fields are zero: there is no sid range and no placeholder sids, the
// msg-prefix check is off, msg-duplicate normalises msgs with
// DefaultNormalizeMsg, continued lines need only be indented consistently
// within a rule, and the spacing after colons is not checked.
func DefaultPolicy() Policy {
	return Policy{
		RequireRev: true,
		Style:      StylePolicy{SpaceAfterSemicolon: SpacingRequire},
	}
}

// DefaultNormalizeMsg lowercases s, collapses every run of whitespace to a
// single space and trims leading and trailing whitespace.
func DefaultNormalizeMsg(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// Validate reports every inconsistency in p. It fails when SIDMin exceeds
// SIDMax (both nonzero), when PlaceholderBelow exceeds SIDMin (both
// nonzero), or when a Spacing field holds an undefined value.
func (p Policy) Validate() error {
	var errs []error
	if p.SIDMin != 0 && p.SIDMax != 0 && p.SIDMin > p.SIDMax {
		errs = append(errs, fmt.Errorf("sid range: SIDMin (%d) exceeds SIDMax (%d)", p.SIDMin, p.SIDMax))
	}
	if p.PlaceholderBelow != 0 && p.SIDMin != 0 && p.PlaceholderBelow > p.SIDMin {
		errs = append(errs, fmt.Errorf("placeholder threshold: PlaceholderBelow (%d) exceeds SIDMin (%d)", p.PlaceholderBelow, p.SIDMin))
	}
	if !p.Style.SpaceAfterColon.Valid() {
		errs = append(errs, fmt.Errorf("invalid Spacing value %d for Style.SpaceAfterColon", uint8(p.Style.SpaceAfterColon)))
	}
	if !p.Style.SpaceAfterSemicolon.Valid() {
		errs = append(errs, fmt.Errorf("invalid Spacing value %d for Style.SpaceAfterSemicolon", uint8(p.Style.SpaceAfterSemicolon)))
	}
	return errors.Join(errs...)
}

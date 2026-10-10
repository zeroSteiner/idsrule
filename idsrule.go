package idsrule

import (
	"errors"
	"fmt"

	"github.com/zeroSteiner/idsrule/check"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/source"
)

type (
	// Severity is an alias for [diag.Severity].
	Severity = diag.Severity
	// Diagnostic is an alias for [diag.Diagnostic].
	Diagnostic = diag.Diagnostic
	// Related is an alias for [diag.Related].
	Related = diag.Related

	// Position is an alias for [source.Position].
	Position = source.Position
	// Span is an alias for [source.Span].
	Span = source.Span
	// TextEdit is an alias for [source.TextEdit].
	TextEdit = source.TextEdit

	// Dialect is an alias for [dialect.Dialect].
	Dialect = dialect.Dialect

	// Policy is an alias for [check.Policy].
	Policy = check.Policy
	// StylePolicy is an alias for [check.StylePolicy].
	StylePolicy = check.StylePolicy
	// Spacing is an alias for [check.Spacing].
	Spacing = check.Spacing
	// Selection is an alias for [check.Selection].
	Selection = check.Selection

	// SIDIndex is an alias for [check.SIDIndex].
	SIDIndex = check.SIDIndex
	// SIDRef is an alias for [check.SIDRef].
	SIDRef = check.SIDRef
)

const (
	// SeverityError is [diag.SeverityError].
	SeverityError = diag.SeverityError
	// SeverityWarning is [diag.SeverityWarning].
	SeverityWarning = diag.SeverityWarning
)

const (
	// DialectUnknown is [dialect.Unknown]: detect the dialect from the filename.
	DialectUnknown = dialect.Unknown
	// DialectSnort2 is [dialect.Snort2].
	DialectSnort2 = dialect.Snort2
	// DialectSuricata is [dialect.Suricata].
	DialectSuricata = dialect.Suricata
)

const (
	// SpacingAny is [check.SpacingAny].
	SpacingAny = check.SpacingAny
	// SpacingRequire is [check.SpacingRequire].
	SpacingRequire = check.SpacingRequire
	// SpacingForbid is [check.SpacingForbid].
	SpacingForbid = check.SpacingForbid
)

// Options configures parsing and checking.
type Options struct {
	// Dialect selects the rule language. DialectUnknown means detect it
	// from the filename.
	Dialect Dialect
	// Policy is what the rules are held to.
	Policy Policy
	// Checks selects which checks run and how they report.
	Checks Selection
	// SIDs, when non-nil, is shared across files so that sid duplicates can
	// be found across a whole rule set.
	SIDs *SIDIndex
}

// DefaultOptions returns the options used when none are given: the dialect
// is detected from the filename and the policy is [check.DefaultPolicy].
func DefaultOptions() Options {
	return Options{Policy: check.DefaultPolicy()}
}

// knownCheck reports whether a check id is registered; Validate rejects
// a Checks selection that names an id it does not know.
var knownCheck = check.Known

// Validate reports every inconsistency in o: an undefined Dialect, an
// invalid Policy or an invalid Checks selection, which includes a check
// id that is not registered (see [CheckIDs]).
func (o Options) Validate() error {
	var errs []error
	if !o.Dialect.Valid() {
		errs = append(errs, fmt.Errorf("invalid dialect %s", o.Dialect))
	}
	if err := o.Policy.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("policy: %w", err))
	}
	if err := o.Checks.Validate(knownCheck); err != nil {
		errs = append(errs, fmt.Errorf("checks: %w", err))
	}
	return errors.Join(errs...)
}

// DialectFromFilename detects the dialect from a file name. See
// [dialect.FromFilename].
func DialectFromFilename(name string) Dialect {
	return dialect.FromFilename(name)
}

// NewSIDIndex returns an empty SID index. See [check.NewSIDIndex].
func NewSIDIndex() *SIDIndex {
	return check.NewSIDIndex()
}

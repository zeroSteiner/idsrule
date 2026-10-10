// Package diag defines the diagnostics that checks report: a position, a
// severity, the id of the check that produced it, a message, and optionally
// an autofix as a list of text edits.
package diag

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/zeroSteiner/idsrule/source"
)

// Severity is how serious a diagnostic is.
type Severity string

const (
	// SeverityError marks a diagnostic that makes the rule invalid or
	// unusable.
	SeverityError Severity = "error"
	// SeverityWarning marks a diagnostic the rule can live with.
	SeverityWarning Severity = "warning"
)

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool {
	switch s {
	case SeverityError, SeverityWarning:
		return true
	}
	return false
}

// Related points at another location that helps explain a diagnostic, such
// as the first occurrence of a duplicated SID.
type Related struct {
	File         string
	Line, Column int
	Message      string
}

// Diagnostic is a single finding reported by a check.
type Diagnostic struct {
	File     string
	Line     int // 1-based line of Span.Start
	Column   int // 1-based byte column of Span.Start
	Severity Severity
	Rule     string // kebab-case check id, e.g. "sid-duplicate"
	Message  string
	End      source.Position   // position of Span.End (exclusive)
	Span     source.Span       // bytes the diagnostic is about
	Edits    []source.TextEdit // autofix; nil when the check offers none
	Related  []Related
}

// String renders d as "file:line:column: severity [rule] message".
func (d Diagnostic) String() string {
	return fmt.Sprintf("%s:%d:%d: %s [%s] %s", d.File, d.Line, d.Column, d.Severity, d.Rule, d.Message)
}

// HasFix reports whether d carries an autofix.
func (d Diagnostic) HasFix() bool { return len(d.Edits) > 0 }

// Sort orders ds by (Line, Column, Rule, Message). The sort is stable, so
// diagnostics that compare equal keep their relative order.
func Sort(ds []Diagnostic) {
	slices.SortStableFunc(ds, func(a, b Diagnostic) int {
		return cmp.Or(
			cmp.Compare(a.Line, b.Line),
			cmp.Compare(a.Column, b.Column),
			cmp.Compare(a.Rule, b.Rule),
			cmp.Compare(a.Message, b.Message),
		)
	})
}

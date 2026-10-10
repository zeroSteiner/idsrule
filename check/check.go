package check

import "github.com/zeroSteiner/idsrule/diag"

// Check is one rule check: what it is called, how it reports and the
// function that runs it over a file. Checks are registered at init time
// with [Register] and run with [Run].
type Check struct {
	// ID is the kebab-case identifier the check reports under: its
	// diagnostics carry it as their Rule and a Selection names it. It
	// must match ^[a-z][a-z0-9]*(-[a-z0-9]+)*$ and be unique.
	ID string
	// Severity is the severity the check's diagnostics carry unless a
	// Selection overrides it or the check overrides it for one finding.
	Severity diag.Severity
	// Style marks a cosmetic check. Style checks are off by default and
	// run only when Selection.Style is set or Selection.Enable names them.
	Style bool
	// NeedsDialect marks a check that cannot run without knowing the
	// dialect. Run skips it, and reports that it did, when the Context's
	// Dialect is Unknown.
	NeedsDialect bool
	// Doc describes the check in one line.
	Doc string
	// Run reports the check's findings for one file through the Context.
	// It must never panic, whatever tree the parser produced.
	Run func(*Context)
}

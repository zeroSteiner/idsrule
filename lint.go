package idsrule

import (
	"github.com/zeroSteiner/idsrule/check"
	"github.com/zeroSteiner/idsrule/diag"
)

// RuleConfigInvalid is the id of the single diagnostic [Lint] and [Check]
// return when the Options they are given do not validate. It is not a
// registered check: [CheckIDs] does not list it and a Selection can
// neither disable it nor change its severity.
const RuleConfigInvalid = "config-invalid"

// configInvalid returns the diagnostic for invalid options, or nil when
// opts validates.
func configInvalid(file string, opts Options) []Diagnostic {
	err := opts.Validate()
	if err == nil {
		return nil
	}
	return []Diagnostic{{
		File:     file,
		Line:     1,
		Column:   1,
		End:      Position{Line: 1, Column: 1},
		Severity: SeverityError,
		Rule:     RuleConfigInvalid,
		Message:  err.Error(),
	}}
}

// Lint parses src as the rules file named file and runs the checks opts
// selects on it. The result is the syntax diagnostics of [Parse] and the
// checks' findings together, sorted by position. When opts does not
// validate the result is a single [RuleConfigInvalid] error at 1:1 and
// nothing is parsed.
//
// Lint mirrors a bytes-in, findings-out validator: the caller owns file
// discovery and output. With a shared [Options.SIDs] the caller may lint a
// whole rule set and have sid duplicates found across files. The index is
// maintained whatever checks are selected: linting a file replaces its
// entries, so the result does not depend on how many times a file was
// linted. Cross-file findings do depend on the order: a file reports a sid
// only against the files linted before it, so the first of two files that
// share a sid stays silent until it is linted again (a second pass over
// the set makes the findings symmetric). They are deterministic only when
// the files are linted one after another; concurrent calls with one index
// are safe, but the interleaving then decides which file reports.
func Lint(file string, src []byte, opts Options) []Diagnostic {
	if d := configInvalid(file, opts); d != nil {
		return d
	}
	f, diags := Parse(file, src)
	diags = append(diags, runChecks(f, opts)...)
	diag.Sort(diags)
	return diags
}

// Check runs the checks opts selects on an already-parsed file, whose Path
// is the file name the findings carry. It returns the checks' findings
// only; the syntax diagnostics are those [Parse] returned. When opts does
// not validate the result is a single [RuleConfigInvalid] error at 1:1.
func Check(f *File, opts Options) []Diagnostic {
	if f == nil {
		return nil
	}
	if d := configInvalid(f.Path, opts); d != nil {
		return d
	}
	return runChecks(f, opts)
}

// runChecks runs the checks on f with validated options: the dialect is
// opts.Dialect or, when that is DialectUnknown, detected from f.Path, and
// the version is opts.Version when it is a release of that dialect and
// VersionAny otherwise. The
// SID index, if any, is brought up to date with f before the checks run,
// whatever the selection: its entries for f.Path are replaced by the sids
// f declares.
func runChecks(f *File, opts Options) []Diagnostic {
	d := opts.Dialect
	if d == DialectUnknown {
		d = DialectFromFilename(f.Path)
	}
	v := opts.Version
	if !d.HasVersion(v) {
		v = VersionAny
	}
	ctx := &check.Context{
		File:    f.Path,
		Src:     f.Src,
		Tree:    f,
		Lines:   f.Lines(),
		Dialect: d,
		Version: v,
		Policy:  opts.Policy,
		SIDs:    opts.SIDs,
	}
	return check.Run(ctx, opts.Checks)
}

// CheckIDs returns the id of every registered check, sorted. The ids are
// what [Selection] names and what the Rule field of a check's diagnostics
// carries; the syntax-* ids of [Parse] and [RuleConfigInvalid] are not
// checks and are not listed.
func CheckIDs() []string { return check.IDs() }

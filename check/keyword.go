package check

import (
	"fmt"

	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
)

func init() {
	Register(Check{
		ID:       "keyword-unknown",
		Severity: diag.SeverityWarning,
		Doc:      "an option keyword is not known to any dialect",
		Run:      checkKeywordUnknown,
	})
	Register(Check{
		ID:           "keyword-wrong-dialect",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "an option keyword exists only in the other dialect",
		Run:          checkKeywordWrongDialect,
	})
	Register(Check{
		ID:           "keyword-version",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "an option keyword does not exist in the release of the dialect the rules are written for: it came later or was removed (with no release set, a keyword that some release removed is a warning, and one that no release has an error)",
		Run:          checkKeywordVersion,
	})
	Register(Check{
		ID:           "keyword-deprecated",
		Severity:     diag.SeverityWarning,
		NeedsDialect: true,
		Doc:          "an option keyword is deprecated in the file's dialect",
		Run:          checkKeywordDeprecated,
	})
}

func checkKeywordUnknown(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.Options() {
			if _, ok := dialect.LookupAny(o.Name()); !ok {
				ctx.Report(o.Keyword.Span(), "unknown keyword %q", o.Name())
			}
		}
	}
}

// otherDialect returns the dialect k exists in, for a keyword that does
// not exist in d.
func otherDialect(k dialect.Keyword) dialect.Dialect {
	if k.Dialects.Has(dialect.Snort2) {
		return dialect.Snort2
	}
	return dialect.Suricata
}

func checkKeywordWrongDialect(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.Options() {
			name := o.Name()
			if _, ok := dialect.Lookup(ctx.Dialect, name); ok {
				continue
			}
			k, ok := dialect.LookupAny(name)
			if !ok {
				continue
			}
			other := otherDialect(k)
			if k.Replaces != "" {
				ctx.Report(o.Keyword.Span(), "%q is a %s keyword; use %q", name, other, k.Replaces)
			} else {
				ctx.Report(o.Keyword.Span(), "%q is a %s keyword with no %s equivalent", name, other, ctx.Dialect)
			}
		}
	}
}

func checkKeywordDeprecated(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.Options() {
			k, ok := ctx.Keyword(o)
			if !ok || !k.Deprecated.Has(ctx.Dialect) {
				continue
			}
			if k.Removed != dialect.AnyVersion && ctx.at(k.Removed) {
				// The release has no such keyword to deprecate;
				// keyword-version reports it.
				continue
			}
			ctx.Report(o.Keyword.Span(), "%q is deprecated in %s%s", k.Name, ctx.Dialect, useSuccessor(k))
		}
	}
}

func checkKeywordVersion(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.Options() {
			k, ok := dialect.Lookup(ctx.Dialect, o.Name())
			if !ok {
				continue
			}
			inVersion := k.In(ctx.Dialect, ctx.Version)
			switch {
			case inVersion && (ctx.Version != dialect.AnyVersion || k.Removed == dialect.AnyVersion):
				continue
			case ctx.before(k.Added):
				ctx.Report(o.Keyword.Span(), "%q requires %s %s or later", k.Name, ctx.Dialect, k.Added)
				continue
			}
			// Removed: in this release, or, with no release set, in a
			// later one (a warning) or in every one (an error).
			d := ctx.Report(o.Keyword.Span(), "%q was removed in %s %s%s", k.Name, ctx.Dialect, k.Removed, useSuccessor(k))
			if inVersion {
				d.Severity = diag.SeverityWarning
			}
		}
	}
}

// useSuccessor returns "; use \"<successor>\"" for a keyword that names
// a successor, and "" otherwise.
func useSuccessor(k dialect.Keyword) string {
	if k.Successor == "" {
		return ""
	}
	return fmt.Sprintf("; use %q", k.Successor)
}

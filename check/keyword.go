package check

import (
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
			if k.Successor != "" {
				ctx.Report(o.Keyword.Span(), "%q is deprecated in %s; use %q", k.Name, ctx.Dialect, k.Successor)
			} else {
				ctx.Report(o.Keyword.Span(), "%q is deprecated in %s", k.Name, ctx.Dialect)
			}
		}
	}
}

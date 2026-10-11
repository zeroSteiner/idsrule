package check

import (
	"strings"

	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

func init() {
	Register(Check{
		ID:       "continuation-trailing-whitespace",
		Severity: diag.SeverityWarning,
		Doc:      "spaces or tabs follow a line continuation's backslash",
		Run:      checkContinuationTrailingWhitespace,
	})
}

func checkContinuationTrailingWhitespace(ctx *Context) {
	for _, t := range ctx.Tree.TokenStream() {
		if t.Kind != token.LineContinuation {
			continue
		}
		lit := strings.TrimSuffix(strings.TrimSuffix(t.Lit, "\n"), "\r")
		if len(lit) < 2 || lit[0] != '\\' {
			continue
		}
		span := source.Span{Start: t.Start + 1, End: t.Start + len(lit)}
		d := ctx.Report(span, "whitespace between the line continuation '\\' and the end of the line")
		d.Edits = []source.TextEdit{{Span: span}}
	}
}

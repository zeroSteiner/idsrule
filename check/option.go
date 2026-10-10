package check

import (
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
)

func init() {
	Register(Check{
		ID:       "option-duplicate",
		Severity: diag.SeverityError,
		Doc:      "a keyword that may appear only once in a rule appears again",
		Run:      checkOptionDuplicate,
	})
}

func checkOptionDuplicate(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		first := make(map[string]*cst.Option)
		for _, o := range r.Options() {
			k, ok := ctx.Keyword(o)
			if !ok || k.Repeatable {
				continue
			}
			if prev, dup := first[k.Name]; dup {
				d := ctx.Report(o.Span(), "option %q appears more than once", k.Name)
				d.Related = []diag.Related{ctx.related(prev.Span(), "first occurrence here")}
				continue
			}
			first[k.Name] = o
		}
	}
}

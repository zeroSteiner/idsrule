package check

import (
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/source"
)

// enabled returns the set of check ids sel selects: every non-style check,
// every style check when sel.Style is set, every id in sel.Enable, minus
// every id in sel.Disable.
func enabled(sel Selection) map[string]bool {
	on := make(map[string]bool)
	for _, c := range All() {
		if !c.Style || sel.Style {
			on[c.ID] = true
		}
	}
	for _, id := range sel.Enable {
		on[id] = true
	}
	for _, id := range sel.Disable {
		delete(on, id)
	}
	return on
}

// Run executes the checks sel selects over ctx.Tree, in id order, and
// returns their diagnostics resolved against ctx.File and ctx.Lines and
// sorted with [diag.Sort].
//
// A check with NeedsDialect set is skipped when ctx.Dialect is Unknown;
// when at least one was, Run adds a single dialect-unknown warning at the
// start of the file, unless sel disables that id. The severity overrides
// in sel.Severity are applied last, to every diagnostic of the id they
// name. A nil ctx or a Context without a Tree yields no diagnostics.
func Run(ctx *Context, sel Selection) []diag.Diagnostic {
	if ctx == nil || ctx.Tree == nil {
		return nil
	}
	if ctx.Src == nil {
		ctx.Src = ctx.Tree.Src
	}
	if ctx.Lines == nil {
		ctx.Lines = ctx.Tree.Lines()
	}
	ctx.builder = diag.Builder{File: ctx.File, Lines: ctx.Lines}
	ctx.out = nil
	ctx.IndexSIDs()

	on := enabled(sel)
	skipped := 0
	for _, c := range All() {
		if !on[c.ID] {
			continue
		}
		if c.NeedsDialect && ctx.Dialect == dialect.Unknown {
			skipped++
			continue
		}
		ctx.id, ctx.severity = c.ID, c.Severity
		c.Run(ctx)
	}
	if skipped > 0 && on[DialectUnknownID] {
		c, _ := Lookup(DialectUnknownID)
		ctx.id, ctx.severity = c.ID, c.Severity
		ctx.Report(source.Span{}, "dialect unknown: %d checks that need one were skipped; set the dialect or name the file *.snort.rule or *.suricata.rule", skipped)
	}

	out := make([]diag.Diagnostic, len(ctx.out))
	for i, d := range ctx.out {
		if sev, ok := sel.Severity[d.Rule]; ok {
			d.Severity = sev
		}
		out[i] = *d
	}
	ctx.out = nil
	diag.Sort(out)
	return out
}

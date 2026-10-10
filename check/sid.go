package check

import (
	"fmt"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/value"
)

func init() {
	Register(Check{
		ID:       "sid-missing",
		Severity: diag.SeverityError,
		Doc:      "a rule has no sid option",
		Run:      checkSIDMissing,
	})
	Register(Check{
		ID:       "sid-duplicate",
		Severity: diag.SeverityError,
		Doc:      "a sid is declared by more than one rule, in this file or, with a SIDIndex, in a file linted earlier",
		Run:      checkSIDDuplicate,
	})
	Register(Check{
		ID:       "sid-out-of-range",
		Severity: diag.SeverityError,
		Doc:      "a sid is outside the range Policy.SIDMin to Policy.SIDMax",
		Run:      checkSIDOutOfRange,
	})
	Register(Check{
		ID:       "sid-placeholder-without-msg",
		Severity: diag.SeverityError,
		Doc:      "a rule with a placeholder sid (below Policy.PlaceholderBelow) has no msg",
		Run:      checkSIDPlaceholderWithoutMsg,
	})
}

// ruleSpan returns the span a rule-level diagnostic covers: the rule
// without its Tail, that is from its action through its ')' or, when the
// ')' is missing, through the last token of its body.
func ruleSpan(r *cst.Rule) source.Span {
	s := r.Span()
	if len(r.Tail) > 0 {
		s.End = r.Tail[0].Start
	}
	return s
}

// ruleSID returns the first sid option of r and its decoded value. ok is
// false when the rule has no sid option or its value is not a number; opt
// is still returned in the latter case.
func ruleSID(r *cst.Rule) (sid uint64, opt *cst.Option, ok bool) {
	opt = r.Option("sid")
	if opt == nil {
		return 0, nil, false
	}
	logical, _ := opt.LogicalValue()
	sid, err := value.ParseUint(logical)
	if err != nil {
		return 0, opt, false
	}
	return sid, opt, true
}

// isPlaceholder reports whether sid is a placeholder under p.
func isPlaceholder(p Policy, sid uint64) bool {
	return p.PlaceholderBelow > 0 && sid < p.PlaceholderBelow
}

func checkSIDMissing(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		if r.Option("sid") == nil {
			ctx.Report(ruleSpan(r), "rule has no sid")
		}
	}
}

// checkSIDDuplicate reports a sid declared earlier in the file, on every
// later declaration, and then, when there is a SIDIndex, a sid declared in
// another file: once per such file, on the first declaration in this file.
// It only reads the index; [Context.IndexSIDs] maintains it.
func checkSIDDuplicate(ctx *Context) {
	first := make(map[uint64]*cst.Option)
	var order []uint64 // the keys of first in file order
	for _, r := range ctx.Tree.Rules() {
		sid, opt, ok := ruleSID(r)
		if !ok || isPlaceholder(ctx.Policy, sid) {
			continue
		}
		if prev, dup := first[sid]; dup {
			d := ctx.Report(opt.Span(), "duplicate sid %d", sid)
			d.Related = []diag.Related{ctx.related(prev.Span(), "first declared here")}
			continue
		}
		first[sid] = opt
		order = append(order, sid)
	}
	if ctx.SIDs == nil {
		return
	}
	for _, sid := range order {
		reported := make(map[string]bool)
		for _, ref := range ctx.SIDs.Lookup(sid) {
			if ref.File == ctx.File || reported[ref.File] {
				continue
			}
			reported[ref.File] = true
			d := ctx.Report(first[sid].Span(), "duplicate sid %d: also declared in %s", sid, ref.File)
			d.Related = []diag.Related{{File: ref.File, Line: ref.Line, Column: ref.Column, Message: "also declared here"}}
		}
	}
}

// sidOutOfRange renders the sid-out-of-range message for sid under p.
func sidOutOfRange(p Policy, sid uint64) string {
	switch {
	case p.SIDMin > 0 && p.SIDMax > 0:
		return fmt.Sprintf("sid %d is outside the policy range [%d, %d]", sid, p.SIDMin, p.SIDMax)
	case p.SIDMin > 0:
		return fmt.Sprintf("sid %d is outside the policy range (at least %d)", sid, p.SIDMin)
	default:
		return fmt.Sprintf("sid %d is outside the policy range (at most %d)", sid, p.SIDMax)
	}
}

func checkSIDOutOfRange(ctx *Context) {
	p := ctx.Policy
	if p.SIDMin == 0 && p.SIDMax == 0 {
		return
	}
	for _, r := range ctx.Tree.Rules() {
		sid, opt, ok := ruleSID(r)
		if !ok || isPlaceholder(p, sid) {
			continue
		}
		if (p.SIDMax > 0 && sid > p.SIDMax) || (p.SIDMin > 0 && sid < p.SIDMin) {
			ctx.Report(opt.Span(), "%s", sidOutOfRange(p, sid))
		}
	}
}

func checkSIDPlaceholderWithoutMsg(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		sid, _, ok := ruleSID(r)
		if ok && isPlaceholder(ctx.Policy, sid) && r.Option("msg") == nil {
			ctx.Report(ruleSpan(r), "rule with placeholder sid %d has no msg", sid)
		}
	}
}

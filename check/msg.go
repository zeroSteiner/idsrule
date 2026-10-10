package check

import (
	"strings"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/value"
)

func init() {
	Register(Check{
		ID:       "msg-missing",
		Severity: diag.SeverityError,
		Doc:      "a rule has no msg option (a rule with a placeholder sid is left to sid-placeholder-without-msg)",
		Run:      checkMsgMissing,
	})
	Register(Check{
		ID:       "rev-missing",
		Severity: diag.SeverityError,
		Doc:      "a rule has no rev option while Policy.RequireRev is set",
		Run:      checkRevMissing,
	})
	Register(Check{
		ID:       "msg-duplicate",
		Severity: diag.SeverityError,
		Doc:      "two rules of the file have the same msg once normalized with Policy.NormalizeMsg",
		Run:      checkMsgDuplicate,
	})
	Register(Check{
		ID:       "msg-prefix",
		Severity: diag.SeverityWarning,
		Doc:      "a msg does not start with Policy.MsgPrefix (compared case-sensitively)",
		Run:      checkMsgPrefix,
	})
}

// ruleMsg returns the first msg option of r and its decoded text. ok is
// false when the rule has no msg option or its value is not a quoted
// string; opt is still returned in the latter case.
func ruleMsg(r *cst.Rule) (text string, opt *cst.Option, ok bool) {
	opt = r.Option("msg")
	if opt == nil {
		return "", nil, false
	}
	logical, _ := opt.LogicalValue()
	text, err := value.ParseQuoted(logical)
	if err != nil {
		return "", opt, false
	}
	return text, opt, true
}

func checkMsgMissing(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		if r.Option("msg") != nil {
			continue
		}
		if sid, _, ok := ruleSID(r); ok && isPlaceholder(ctx.Policy, sid) {
			continue
		}
		ctx.Report(ruleSpan(r), "rule has no msg")
	}
}

func checkRevMissing(ctx *Context) {
	if !ctx.Policy.RequireRev {
		return
	}
	for _, r := range ctx.Tree.Rules() {
		if r.Option("rev") == nil {
			ctx.Report(ruleSpan(r), "rule has no rev")
		}
	}
}

func checkMsgDuplicate(ctx *Context) {
	first := make(map[string]*cst.Option)
	for _, r := range ctx.Tree.Rules() {
		text, opt, ok := ruleMsg(r)
		if !ok {
			continue
		}
		key := ctx.normalizeMsg(text)
		if prev, dup := first[key]; dup {
			d := ctx.Report(opt.Span(), "duplicate msg %q", text)
			d.Related = []diag.Related{ctx.related(prev.Span(), "first used here")}
			continue
		}
		first[key] = opt
	}
}

func checkMsgPrefix(ctx *Context) {
	prefix := ctx.Policy.MsgPrefix
	if prefix == "" {
		return
	}
	for _, r := range ctx.Tree.Rules() {
		text, opt, ok := ruleMsg(r)
		if ok && !strings.HasPrefix(text, prefix) {
			ctx.Report(opt.Span(), "msg does not start with %q", prefix)
		}
	}
}

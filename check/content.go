package check

import (
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/value"
)

func init() {
	Register(Check{
		ID:       "content-snort3-modifiers",
		Severity: diag.SeverityError,
		Doc:      "a content value carries Snort 3 style modifiers after its closing quote",
		Run:      checkContentSnort3Modifiers,
	})
	Register(Check{
		ID:           "modifier-without-content",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "a content modifier appears before any payload match of the rule, or a buffer transform or buffer test before any sticky buffer",
		Run:          checkModifierWithoutContent,
	})
	Register(Check{
		ID:           "sticky-buffer-empty",
		Severity:     diag.SeverityWarning,
		NeedsDialect: true,
		Doc:          "a sticky buffer is followed by another sticky buffer or the end of the rule with no payload match or buffer test in between (a transform alone does not use it)",
		Run:          checkStickyBufferEmpty,
	})
}

// closingQuote returns the offset of the quote that closes the pattern of
// a content value ParseContent accepted, or -1.
func closingQuote(s string) int {
	i := 0
	for i < len(s) && s[i] != '"' {
		i++
	}
	for i++; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}

func checkContentSnort3Modifiers(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.Options() {
			k, ok := dialect.LookupAny(o.Name())
			if !ok || k.Kind != dialect.KindContent || !o.HasValue() {
				continue
			}
			logical, at := o.LogicalValue()
			c, err := value.ParseContent(logical)
			if err != nil || c.Trailing == "" {
				continue
			}
			q := closingQuote(logical)
			if q < 0 {
				continue
			}
			span := source.Span{Start: at(q + 1), End: o.ValueSpan().End}
			ctx.Report(span, "text after the closing quote %q is Snort 3 syntax; write it as separate options", c.Trailing)
		}
	}
}

func checkModifierWithoutContent(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		payload, sticky := false, false
		for _, o := range r.Options() {
			k, ok := ctx.Keyword(o)
			if !ok {
				continue
			}
			switch {
			case k.Role == dialect.RolePayload:
				payload = true
			case k.Role == dialect.RoleStickyBuffer:
				sticky = true
			case k.Role == dialect.RoleModifier && !payload:
				ctx.Report(o.Span(), "%q modifies a content but none precedes it", k.Name)
			case (k.Role == dialect.RoleTransform || k.Role == dialect.RoleBufferTest) && !sticky:
				ctx.Report(o.Span(), "%q applies to a sticky buffer but none precedes it", k.Name)
			}
		}
	}
}

// usesBuffer reports whether an option of role r matches on, or tests,
// the active sticky buffer. A transform only rewrites it.
func usesBuffer(r dialect.Role) bool {
	return r == dialect.RolePayload || r == dialect.RoleBufferTest
}

func checkStickyBufferEmpty(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		opts := r.Options()
		roles := make([]dialect.Role, len(opts))
		known := make([]bool, len(opts))
		for i, o := range opts {
			if k, ok := ctx.Keyword(o); ok {
				roles[i], known[i] = k.Role, true
			}
		}
		for i, o := range opts {
			if !known[i] || roles[i] != dialect.RoleStickyBuffer {
				continue
			}
			empty := true
			for j := i + 1; j < len(opts); j++ {
				if !known[j] {
					continue
				}
				if usesBuffer(roles[j]) {
					empty = false
					break
				}
				if roles[j] == dialect.RoleStickyBuffer {
					break
				}
			}
			if empty {
				ctx.Report(o.Span(), "sticky buffer %q has no content, pcre or buffer test after it", o.Name())
			}
		}
	}
}

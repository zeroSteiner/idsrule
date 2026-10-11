package check

import (
	"regexp"
	"strings"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
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

// snort3Modifier matches one Snort 3 modifier as written after a content
// pattern: a bare name such as "nocase", or a name and its argument such
// as "depth 16".
var snort3Modifier = regexp.MustCompile(`^[a-z_]+( [^,;"]+)?$`)

// snort3Rewrite returns the Snort 2 options that trailing, the text after
// the closing quote of a content value, stands for: ", nocase, depth 5"
// becomes "; nocase; depth:5", spaced as style demands (no space after
// the semicolon when it forbids one, a space after the colon when it
// requires one). It reports false when the text does not start with a
// comma or when a piece between commas is not a modifier snort3Modifier
// recognizes.
func snort3Rewrite(trailing string, style StylePolicy) (string, bool) {
	pieces := strings.Split(trailing, ",")
	if strings.Trim(pieces[0], " \t") != "" {
		return "", false
	}
	semicolon, colon := "; ", ":"
	if style.SpaceAfterSemicolon == SpacingForbid {
		semicolon = ";"
	}
	if style.SpaceAfterColon == SpacingRequire {
		colon = ": "
	}
	var b strings.Builder
	for _, piece := range pieces[1:] {
		piece = strings.Trim(piece, " \t")
		if !snort3Modifier.MatchString(piece) {
			return "", false
		}
		name, arg, _ := strings.Cut(piece, " ")
		b.WriteString(semicolon)
		b.WriteString(name)
		if arg != "" {
			b.WriteString(colon)
			b.WriteString(arg)
		}
	}
	return b.String(), true
}

// spansContinuation reports whether a LineContinuation token of o's value
// starts at or after offset start.
func spansContinuation(o *cst.Option, start int) bool {
	for _, t := range o.Value {
		if t.Kind == token.LineContinuation && t.Start >= start {
			return true
		}
	}
	return false
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
			d := ctx.Report(span, "text after the closing quote %q is Snort 3 syntax; write it as separate options", c.Trailing)
			// The fix rewrites everything after the closing quote as
			// options of their own, unless a line continuation is in the
			// way: the rewrite would have to drop or move it.
			if text, ok := snort3Rewrite(c.Trailing, ctx.Policy.Style); ok && !spansContinuation(o, span.Start) {
				d.Edits = []source.TextEdit{{Span: span, NewText: text}}
			}
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

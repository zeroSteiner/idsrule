package check

import (
	"bytes"
	"strings"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

func init() {
	Register(Check{
		ID:       "style-continuation-indent",
		Severity: diag.SeverityWarning,
		Style:    true,
		Doc:      "a continuation line of a rule is not indented like the rule's first continuation line, or like Policy.Style.ContinuationIndent when that is set (a line holding only the closing parenthesis is exempt)",
		Run:      checkStyleContinuationIndent,
	})
	Register(Check{
		ID:       "style-space-after-colon",
		Severity: diag.SeverityWarning,
		Style:    true,
		Doc:      "the whitespace between an option's colon and its value is not what Policy.Style.SpaceAfterColon demands: exactly one space, or none",
		Run:      checkStyleSpaceAfterColon,
	})
	Register(Check{
		ID:       "style-space-after-semicolon",
		Severity: diag.SeverityWarning,
		Style:    true,
		Doc:      "the whitespace between an option's semicolon and the next option on the same line is not what Policy.Style.SpaceAfterSemicolon demands: exactly one space, or none",
		Run:      checkStyleSpaceAfterSemicolon,
	})
	Register(Check{
		ID:       "style-trailing-whitespace",
		Severity: diag.SeverityWarning,
		Style:    true,
		Doc:      "spaces or tabs end a line (those after a line continuation's backslash are left to continuation-trailing-whitespace)",
		Run:      checkStyleTrailingWhitespace,
	})
	Register(Check{
		ID:       "style-rules-concatenated",
		Severity: diag.SeverityWarning,
		Style:    true,
		Doc:      "a rule is followed by another rule on the same line",
		Run:      checkStyleRulesConcatenated,
	})
	Register(Check{
		ID:       "style-missing-final-newline",
		Severity: diag.SeverityWarning,
		Style:    true,
		Doc:      "the file does not end with a newline",
		Run:      checkStyleMissingFinalNewline,
	})
}

// quoteOpen reports whether a double-quoted string is open after s, given
// whether one is open before it: each unescaped quote toggles the state,
// a quote being escaped when an odd run of backslashes precedes it within
// s. The run is counted per token because it never spans a continuation:
// the lexer makes the first backslash of a "\\" before a newline a plain
// value byte and the second the continuation.
func quoteOpen(s string, open bool) bool {
	backslashes := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			backslashes++
			continue
		}
		if s[i] == '"' && backslashes%2 == 0 {
			open = !open
		}
		backslashes = 0
	}
	return open
}

// stringContinuations returns the start offsets of the line continuations
// of r that fall inside a quoted value, found by counting the unescaped
// quotes of the option's value before each one. The whitespace after such
// a continuation belongs to the value, not to the layout of the rule.
func stringContinuations(r *cst.Rule) map[int]bool {
	inString := make(map[int]bool)
	for _, o := range r.Options() {
		open := false
		for _, t := range o.Value {
			if t.Kind == token.LineContinuation {
				if open {
					inString[t.Start] = true
				}
				continue
			}
			open = quoteOpen(t.Lit, open)
		}
	}
	return inString
}

// exemptContinuation reports whether a continued line whose first
// non-whitespace token is next, or that has none when ok is false, holds
// no option line: it holds the rule's closing parenthesis alone, or
// nothing at all because a newline, another continuation, or the end of
// the rule follows (an unterminated rule ends in a zero-width Missing
// parenthesis; the file's EOF token is never among a rule's tokens).
func exemptContinuation(r *cst.Rule, next token.Token, ok bool) bool {
	if !ok {
		return true
	}
	if next.Kind == token.RParen {
		return next.Start == r.RParen.Start
	}
	return next.Kind == token.Newline || next.Kind == token.Missing || next.Kind == token.LineContinuation
}

func checkStyleContinuationIndent(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		// ref is the indent every continuation line is held to: the
		// policy's, or the first continuation line's when it has none.
		ref := ctx.Policy.Style.ContinuationIndent
		haveRef := ref != ""
		inString := stringContinuations(r)
		toks := cst.Tokens(r)
		for i, t := range toks {
			if t.Kind != token.LineContinuation || inString[t.Start] {
				continue
			}
			// The indent is the Whitespace token right after the
			// continuation, when there is one.
			indent, span := "", source.Span{Start: t.End, End: t.End}
			j := i + 1
			if j < len(toks) && toks[j].Kind == token.Whitespace {
				indent, span = toks[j].Lit, toks[j].Span()
				j++
			}
			var next token.Token
			if j < len(toks) {
				next = toks[j]
			}
			if exemptContinuation(r, next, j < len(toks)) {
				continue
			}
			if !haveRef {
				ref, haveRef = indent, true
				continue
			}
			if indent == ref {
				continue
			}
			if ctx.Policy.Style.ContinuationIndent != "" {
				ctx.Report(span, "continuation line indented with %q, not %q as the policy demands", indent, ref)
			} else {
				ctx.Report(span, "continuation line indented with %q, not %q like the rule's first continuation line", indent, ref)
			}
		}
	}
}

// reportSpacing reports the whitespace found right after the token named
// what, which ends at offset at, when it is not what want demands, and
// attaches the edit that makes it so. ws is the Whitespace token that
// follows, or nil when there is none.
func reportSpacing(ctx *Context, want Spacing, at int, ws *token.Token, what string) {
	switch want {
	case SpacingRequire:
		if ws == nil {
			span := source.Span{Start: at, End: at}
			d := ctx.Report(span, "missing space after %s", what)
			d.Edits = []source.TextEdit{{Span: span, NewText: " "}}
		} else if ws.Lit != " " {
			d := ctx.Report(ws.Span(), "%q after %s where a single space is expected", ws.Lit, what)
			d.Edits = []source.TextEdit{{Span: ws.Span(), NewText: " "}}
		}
	case SpacingForbid:
		if ws != nil {
			d := ctx.Report(ws.Span(), "whitespace after %s where none is allowed", what)
			d.Edits = []source.TextEdit{{Span: ws.Span()}}
		}
	case SpacingAny:
	}
}

func checkStyleSpaceAfterColon(ctx *Context) {
	want := ctx.Policy.Style.SpaceAfterColon
	if want == SpacingAny {
		return
	}
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.Options() {
			// An option without a value has nothing after its colon to
			// separate from it.
			if o.Colon == nil || len(o.Value) == 0 {
				continue
			}
			var ws *token.Token
			j := 0
			if o.Value[0].Kind == token.Whitespace {
				ws = &o.Value[0]
				j = 1
			}
			// A value that starts on the next line is exempt, like a
			// semicolon before a line continuation.
			if j < len(o.Value) && o.Value[j].Kind == token.LineContinuation {
				continue
			}
			reportSpacing(ctx, want, o.Colon.End, ws, "':'")
		}
	}
}

func checkStyleSpaceAfterSemicolon(ctx *Context) {
	want := ctx.Policy.Style.SpaceAfterSemicolon
	if want == SpacingAny {
		return
	}
	for _, r := range ctx.Tree.Rules() {
		kids := cst.Children(r.Body)
		for i, k := range kids {
			o, ok := k.(*cst.Option)
			if !ok || o.Semicolon.Kind != token.Semicolon {
				continue
			}
			// After the semicolon: an optional Whitespace token, then
			// whatever comes next. Only a next option on the same logical
			// line is measured; a line continuation, the closing
			// parenthesis or the end of the rule is exempt, and a run of
			// tokens that did not parse is the syntax diagnostic's
			// business.
			var ws *token.Token
			j := i + 1
			if j < len(kids) {
				if t, ok := kids[j].(token.Token); ok && t.Kind == token.Whitespace {
					ws = &t
					j++
				}
			}
			if j < len(kids) {
				if _, ok := kids[j].(*cst.Option); ok {
					reportSpacing(ctx, want, o.Semicolon.End, ws, "';'")
				}
			}
		}
	}
}

// trailingBlanks returns the span of the blanks that end a line at token i
// of toks: a Whitespace token right before a Newline or the EOF, or the
// blanks a Comment token ends with, since a comment runs to the end of its
// line. ok is false when token i ends no line with blanks.
func trailingBlanks(toks []token.Token, i int) (span source.Span, ok bool) {
	t := toks[i]
	if t.Kind == token.Whitespace {
		if i+1 >= len(toks) || (toks[i+1].Kind != token.Newline && toks[i+1].Kind != token.EOF) {
			return source.Span{}, false
		}
		return t.Span(), true
	}
	if t.Kind != token.Comment {
		return source.Span{}, false
	}
	kept := len(strings.TrimRight(t.Lit, " \t"))
	if kept == len(t.Lit) {
		return source.Span{}, false
	}
	return source.Span{Start: t.Start + kept, End: t.End}, true
}

func checkStyleTrailingWhitespace(ctx *Context) {
	toks := ctx.Tree.TokenStream()
	for i := range toks {
		span, ok := trailingBlanks(toks, i)
		if !ok {
			continue
		}
		d := ctx.Report(span, "trailing whitespace")
		// Blanks that end the file with no newline after them are the
		// business of style-missing-final-newline, whose fix replaces
		// them with the newline; two fixes must not own the same bytes.
		if span.End < len(ctx.Src) {
			d.Edits = []source.TextEdit{{Span: span}}
		}
	}
}

// hasNewline reports whether toks holds a Newline token.
func hasNewline(toks []token.Token) bool {
	for _, t := range toks {
		if t.Kind == token.Newline {
			return true
		}
	}
	return false
}

func checkStyleRulesConcatenated(ctx *Context) {
	items := ctx.Tree.Items
	for i := 0; i+1 < len(items); i++ {
		r, ok := items[i].(*cst.Rule)
		if !ok {
			continue
		}
		next, ok := items[i+1].(*cst.Rule)
		if !ok || hasNewline(r.Tail) {
			continue
		}
		start := next.Span().Start
		d := ctx.Report(source.Span{Start: r.RParen.Start, End: start}, "another rule follows on the same line")
		d.Edits = []source.TextEdit{{Span: source.Span{Start: r.RParen.End, End: start}, NewText: "\n"}}
	}
}

func checkStyleMissingFinalNewline(ctx *Context) {
	src := ctx.Src
	if len(src) == 0 || src[len(src)-1] == '\n' {
		return
	}
	at := len(src)
	d := ctx.Report(source.Span{Start: at, End: at}, "no newline at end of file")
	// The newline goes right after the last non-blank byte: blanks that
	// end the file are replaced along with it, so that the fix does not
	// leave a line of blanks behind.
	kept := len(bytes.TrimRight(src, " \t"))
	d.Edits = []source.TextEdit{{Span: source.Span{Start: kept, End: at}, NewText: "\n"}}
}

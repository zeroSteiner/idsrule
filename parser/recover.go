package parser

import (
	"fmt"
	"strconv"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/lexer"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

// The ids of the diagnostics the parser reports. The lexer's
// [lexer.RuleUnterminatedString] is passed through alongside them.
const (
	// RuleBadHeader reports a line that does not start with a rule action,
	// or a rule header that lacks a part, has a part that is not what was
	// expected, or has tokens left over before '('. It is reported at most
	// once per header.
	RuleBadHeader = "syntax-bad-header"
	// RuleUnbalancedBracket reports a '[' in a header with no matching ']'.
	RuleUnbalancedBracket = "syntax-unbalanced-bracket"
	// RuleMissingOpenParen reports a header that is not followed by '('.
	RuleMissingOpenParen = "syntax-missing-open-paren"
	// RuleMissingCloseParen reports a rule body that ran into the end of
	// the line or of the file without a ')'.
	RuleMissingCloseParen = "syntax-missing-close-paren"
	// RuleMissingSemicolon reports an option that ran into ')', the end of
	// the line or the end of the file without a ';'.
	RuleMissingSemicolon = "syntax-missing-semicolon"
	// RuleEmptyOption reports a ';' with no option before it.
	RuleEmptyOption = "syntax-empty-option"
	// RuleMissingValue reports an option with a ':' but nothing after it.
	RuleMissingValue = "syntax-missing-value"
	// RuleBadOption reports a token in a body that cannot start an option.
	RuleBadOption = "syntax-bad-option"
	// RuleTrailingText reports text after a rule's ')' on the same line.
	RuleTrailingText = "syntax-trailing-text"
)

// report records an error diagnostic for span. Positions are left for the
// caller of Parse to resolve.
func (p *parser) report(rule string, span source.Span, format string, args ...any) {
	p.diags = append(p.diags, diag.Diagnostic{
		Rule:     rule,
		Severity: diag.SeverityError,
		Span:     span,
		Message:  fmt.Sprintf(format, args...),
	})
}

// describe names a token in a message: its text quoted as Go syntax, or
// "end of line" and "end of file" for a newline and the EOF.
func describe(t token.Token) string {
	if t.Kind == token.Newline {
		return "end of line"
	}
	if t.Kind == token.EOF {
		return "end of file"
	}
	return strconv.Quote(t.Lit)
}

// missing returns a zero-width Missing token at off.
func missing(off int) token.Token {
	return token.Token{Kind: token.Missing, Start: off, End: off}
}

// emptySpan returns the zero-width span at off, where a diagnostic about
// something absent is reported.
func emptySpan(off int) source.Span { return source.Span{Start: off, End: off} }

// badLine recovers from a line that is not a rule, a comment or blank: it
// reports the first token and consumes the line through its newline, the
// leading trivia included, into a Bad.
func (p *parser) badLine(lead []token.Token, t token.Token) *cst.Bad {
	p.report(RuleBadHeader, t.Span(), "expected a rule action, got %s", describe(t))
	return p.badThroughNewline(lead)
}

// badThroughNewline consumes every token through the next newline, or up
// to the EOF, appends them to toks and returns the lot as a Bad.
func (p *parser) badThroughNewline(toks []token.Token) *cst.Bad {
	for p.peek().Kind != token.EOF {
		t := p.next()
		toks = append(toks, t)
		if t.Kind == token.Newline {
			break
		}
	}
	return p.bad(toks)
}

// badOption recovers inside a body from a token that cannot start an
// option: it consumes tokens into a Bad up to and including the next ';',
// or up to but not including the ')', newline or EOF that ends the body.
func (p *parser) badOption() *cst.Bad {
	var toks []token.Token
	for {
		t := p.peek()
		if isBodyEnd(t) {
			break
		}
		toks = append(toks, p.next())
		if t.Kind == token.Semicolon {
			break
		}
	}
	return p.bad(toks)
}

// bad wraps tokens in a sealed Bad node. An empty one sits at the current
// position.
func (p *parser) bad(toks []token.Token) *cst.Bad {
	b := &cst.Bad{Tokens: toks}
	cst.Seal(b, p.src, p.peek().Start, tokenNodes(toks)...)
	return b
}

// unterminatedIn reports whether the lexer found a string still open at the
// end of its line inside span: the option that holds the string then does
// not report its missing ';' as well, the two being one error.
//
// The lexer's diagnostics are in position order and the spans asked about
// come in position order too (options do not overlap), so a cursor that
// only moves forward answers every query in amortised constant time.
func (p *parser) unterminatedIn(span source.Span) bool {
	for p.lexCursor < len(p.lexDiags) && p.lexDiags[p.lexCursor].Span.Start < span.Start {
		p.lexCursor++
	}
	for i := p.lexCursor; i < len(p.lexDiags) && p.lexDiags[i].Span.Start < span.End; i++ {
		if p.lexDiags[i].Rule == lexer.RuleUnterminatedString {
			return true
		}
	}
	return false
}

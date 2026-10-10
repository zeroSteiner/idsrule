package parser

import (
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/token"
)

// isBodyEnd reports whether t ends a rule body: the ')' that closes it, or
// a newline or the EOF, which end the rule without one.
func isBodyEnd(t token.Token) bool {
	return t.Kind == token.RParen || t.Kind == token.Newline || t.Kind == token.EOF
}

// parseBody parses the option body from just after '(' up to but not
// including the ')', newline or EOF that ends it. Every iteration consumes
// at least one token: trivia becomes a child of the body, a keyword starts
// an option, and anything else is reported and skipped into a Bad. A ';'
// with no option before it is syntax-empty-option; any other token that
// cannot start an option is syntax-bad-option, and the Bad then runs
// through the next ';' so that the parser resynchronises on the option
// after it.
func (p *parser) parseBody() *cst.Body {
	b := &cst.Body{}
	at := p.peek().Start
	kids := make([]cst.Node, 0, 8)
	for {
		t := p.peek()
		switch {
		case isTrivia(t):
			kids = append(kids, p.next())
		case t.Kind == token.Keyword:
			o := p.parseOption()
			b.Options = append(b.Options, o)
			kids = append(kids, o)
		case isBodyEnd(t):
			cst.Seal(b, p.src, at, kids...)
			return b
		default:
			if t.Kind == token.Semicolon {
				p.report(RuleEmptyOption, t.Span(), "unexpected ';': empty option")
			} else {
				p.report(RuleBadOption, t.Span(), "unexpected %s in rule body", describe(t))
			}
			bad := p.badOption()
			b.Bads = append(b.Bads, bad)
			kids = append(kids, bad)
		}
	}
}

// parseOption parses one option starting at its keyword: the keyword,
// optionally ':' and every token up to the ';', and the ';'. Whitespace
// between the keyword and a ':' or ';' belongs to the option; whitespace
// after a keyword that is followed by anything else is left to the body.
//
// An option with a ':' but no Value token is syntax-missing-value. An
// option that runs into ')', a newline or the EOF gets a Missing ';' at
// the end of its last token and Err set; that is syntax-missing-semicolon
// unless the lexer already reported a string left open inside the value,
// in which case the two are one error and only the lexer's is kept.
func (p *parser) parseOption() *cst.Option {
	o := &cst.Option{Keyword: p.next()}
	kids := make([]cst.Node, 0, 6)
	kids = append(kids, o.Keyword)
	if k := p.afterTrivia().Kind; k == token.Colon || k == token.Semicolon {
		kids = p.triviaInto(kids)
	}
	if p.peek().Kind == token.Colon {
		colon := p.next()
		o.Colon = &colon
		kids = append(kids, colon)
		hasValue := false
		for {
			t := p.peek()
			if t.Kind == token.Value {
				hasValue = true
			} else if !isTrivia(t) {
				break
			}
			o.Value = append(o.Value, p.next())
			kids = append(kids, t)
		}
		if !hasValue {
			p.report(RuleMissingValue, colon.Span(), "option %q has ':' but no value", o.Name())
		}
	}
	if p.peek().Kind == token.Semicolon {
		o.Semicolon = p.next()
	} else {
		o.Semicolon = missing(kids[len(kids)-1].Span().End)
		o.Err = true
		if !p.unterminatedIn(o.ValueSpan()) {
			p.report(RuleMissingSemicolon, o.Semicolon.Span(), "missing ';' after option %q", o.Name())
		}
	}
	kids = append(kids, o.Semicolon)
	cst.Seal(o, p.src, 0, kids...)
	return o
}

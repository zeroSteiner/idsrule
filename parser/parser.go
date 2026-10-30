// Package parser builds the concrete syntax tree of a rule file from the
// lexer's tokens.
//
// The parser is total: it never fails, never panics and keeps every token,
// so that the tree it returns reproduces the input byte for byte whatever
// the input was. Malformed input is reported through diagnostics and
// recovered from at the granularity of a header part, an option or a line,
// so that one broken rule does not take the rules after it down with it.
// The recovery strategies are documented on the functions that implement
// them; the syntax-* diagnostic ids are the Rule* constants.
//
// Parsing is dialect-agnostic: the grammar is the one both Snort 2.9 and
// Suricata share, and what the options mean is left to the checks:
//
//	File   := ( Rule | Comment | BlankLine | BadLine )* EOF
//	Rule   := Header '(' Body ')' Tail
//	Header := Action Proto Group Group Dir Group Group
//	Group  := '!'? ( Word | '[' Group ( ',' Group )* ']' )
//	Body   := Option*
//	Option := Keyword ( ':' Value* )? ';'
//	Tail   := ( Whitespace | LineContinuation )* ( Newline | EOF )
//
// Whitespace and line continuations between the tokens above are trivia,
// kept in the tree but not written in the grammar. A line continuation is
// trivia outside a rule as well as inside one, as both engines splice
// continued lines before they look at them.
package parser

import (
	"cmp"
	"slices"
	"strings"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/lexer"
	"github.com/zeroSteiner/idsrule/token"
)

// actions are the rule actions of both dialects. A line that starts with
// one of them (after optional whitespace) is a rule.
var actions = map[string]bool{
	"alert": true, "log": true, "pass": true, "drop": true, "reject": true,
	"sdrop": true, "activate": true, "dynamic": true,
	"rejectsrc": true, "rejectdst": true, "rejectboth": true,
	"config": true, "accept": true,
}

// IsAction reports whether word is a rule action of either dialect, on its
// own or with the scope Suricata 8 writes after a ':' ("drop:flow").
func IsAction(word string) bool {
	name, _, _ := strings.Cut(word, ":")
	return actions[name]
}

// Parse lexes and parses src. It never fails: the returned file is never
// nil, its text is src byte for byte, and whatever the input the call
// returns rather than panicking.
//
// The tree references src directly: tokens copy their text but composite
// nodes read theirs from src, so the caller must not modify src after
// parsing.
//
// The diagnostics are the lexer's and the parser's together, ordered by
// the start of their span. They carry Rule, Severity, Message and Span
// only; Line, Column and End are left for the caller to resolve with
// [diag.Builder.Resolve] once it knows the file's name.
func Parse(src []byte) (*cst.File, []diag.Diagnostic) {
	toks, lexDiags := lexer.Lex(src)
	return parseTokens(src, toks, lexDiags)
}

// parseTokens parses a token stream that tiles src. The stream should end
// with an EOF token; one is appended when it does not, and lexDiags must
// be in position order. It exists so that tests can feed the parser token
// sequences the lexer never produces and check that it still terminates.
func parseTokens(src []byte, toks []token.Token, lexDiags []diag.Diagnostic) (*cst.File, []diag.Diagnostic) {
	if len(toks) == 0 || toks[len(toks)-1].Kind != token.EOF {
		toks = append(toks[:len(toks):len(toks)], token.Token{Kind: token.EOF, Start: len(src), End: len(src)})
	}
	p := &parser{src: src, toks: toks, lexDiags: lexDiags}
	f := p.parseFile()
	diags := slices.Concat(lexDiags, p.diags)
	slices.SortStableFunc(diags, func(a, b diag.Diagnostic) int {
		return cmp.Compare(a.Span.Start, b.Span.Start)
	})
	if len(diags) == 0 {
		return f, nil
	}
	return f, diags
}

// parser is the state of one parse.
type parser struct {
	src       []byte
	toks      []token.Token // ends with EOF
	pos       int           // index of the next unconsumed token
	lexDiags  []diag.Diagnostic
	lexCursor int // index into lexDiags of the first one not yet passed; see unterminatedIn
	diags     []diag.Diagnostic
}

// peek returns the next token without consuming it. The EOF is never
// consumed, so peek is always valid.
func (p *parser) peek() token.Token { return p.toks[p.pos] }

// next consumes and returns the next token. The last token, the EOF, is
// returned but never consumed.
func (p *parser) next() token.Token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

// isTrivia reports whether t is whitespace or a line continuation, the two
// kinds the parser skips between significant tokens.
func isTrivia(t token.Token) bool {
	return t.Kind == token.Whitespace || t.Kind == token.LineContinuation
}

// trivia consumes a run of whitespace and line continuation tokens and
// returns them, in order.
func (p *parser) trivia() []token.Token {
	var out []token.Token
	for isTrivia(p.peek()) {
		out = append(out, p.next())
	}
	return out
}

// triviaInto consumes a run of whitespace and line continuation tokens and
// appends them to kids, which it returns.
func (p *parser) triviaInto(kids []cst.Node) []cst.Node {
	for isTrivia(p.peek()) {
		kids = append(kids, p.next())
	}
	return kids
}

// triviaEnd returns the index of the first token at or after the current
// position that is not trivia, without consuming anything.
func (p *parser) triviaEnd() int {
	i := p.pos
	for i < len(p.toks)-1 && isTrivia(p.toks[i]) {
		i++
	}
	return i
}

// afterTrivia returns the first token at or after the current position
// that is not trivia, without consuming anything.
func (p *parser) afterTrivia() token.Token { return p.toks[p.triviaEnd()] }

// parseFile is the file loop. Every iteration consumes at least one token:
// a rule, a comment line, a blank line, or a line that is none of those,
// which becomes a Bad item and a syntax-bad-header diagnostic.
func (p *parser) parseFile() *cst.File {
	f := &cst.File{Src: p.src}
	var kids []cst.Node
	for {
		// Leading trivia is lenient: whitespace and line continuations
		// before whatever the line turns out to be join it.
		lead := p.trivia()
		t := p.peek()
		switch {
		case t.Kind == token.EOF:
			if len(lead) > 0 {
				bl := &cst.BlankLine{Tokens: lead}
				cst.Seal(bl, p.src, 0, tokenNodes(lead)...)
				f.Items = append(f.Items, bl)
				kids = append(kids, bl)
			}
			f.EOF = t
			kids = append(kids, t)
			cst.Seal(f, p.src, 0, kids...)
			return f
		case t.Kind == token.Newline:
			bl := &cst.BlankLine{Tokens: append(lead, p.next())}
			cst.Seal(bl, p.src, 0, tokenNodes(bl.Tokens)...)
			f.Items = append(f.Items, bl)
			kids = append(kids, bl)
		case t.Kind == token.Comment:
			c := &cst.Comment{Leading: lead, Hash: p.next()}
			ckids := append(tokenNodes(lead), c.Hash)
			if p.peek().Kind == token.Newline {
				nl := p.next()
				c.Newline = &nl
				ckids = append(ckids, nl)
			}
			cst.Seal(c, p.src, 0, ckids...)
			f.Items = append(f.Items, c)
			kids = append(kids, c)
		case t.Kind == token.Word && IsAction(t.Lit):
			r, trailing := p.parseRule(lead)
			f.Items = append(f.Items, r)
			kids = append(kids, r)
			if trailing != nil {
				f.Items = append(f.Items, trailing)
				kids = append(kids, trailing)
			}
		default:
			bad := p.badLine(lead, t)
			f.Items = append(f.Items, bad)
			kids = append(kids, bad)
		}
	}
}

// parseRule parses one rule starting at its action, with the leading
// trivia of its line, if any, as its first children. When text other than
// another rule follows the closing ')' it is returned as a separate Bad
// item for the file, after the rule.
func (p *parser) parseRule(lead []token.Token) (*cst.Rule, *cst.Bad) {
	r := &cst.Rule{}
	kids := make([]cst.Node, 0, len(lead)+8)
	for _, t := range lead {
		kids = append(kids, t)
	}
	r.Header = p.parseHeader()
	kids = append(kids, r.Header)
	kids = p.triviaInto(kids) // between the header and '(' the trivia is the rule's

	var trailing *cst.Bad
	if t := p.peek(); t.Kind == token.LParen {
		r.LParen = p.next()
		r.Body = p.parseBody()
		kids = append(kids, r.LParen, r.Body)
		if t := p.peek(); t.Kind == token.RParen {
			r.RParen = p.next()
			kids = append(kids, r.RParen)
			r.Tail, trailing = p.parseTail()
		} else {
			// A newline or the EOF ended the body: the lexer had already
			// switched back to Header mode. The ')' is Missing at that
			// point, and the newline is the rule's tail. The diagnostic is
			// not repeated when the last option already reported that it
			// ran into the end of the line.
			if opts := r.Body.Options; len(opts) == 0 || !opts[len(opts)-1].Err {
				p.report(RuleMissingCloseParen, emptySpan(t.Start), "expected ')' before %s", describe(t))
			}
			r.RParen = missing(t.Start)
			kids = append(kids, r.RParen)
			if t.Kind == token.Newline {
				r.Tail = []token.Token{p.next()}
			}
		}
	} else {
		// The header ran into a newline or the EOF without a '('. The
		// rule gets Missing parentheses around an empty body, all at the
		// point where the header stopped.
		p.report(RuleMissingOpenParen, emptySpan(t.Start), "expected '(' after the rule header, got %s", describe(t))
		r.LParen = missing(t.Start)
		r.Body = &cst.Body{}
		cst.Seal(r.Body, p.src, t.Start)
		r.RParen = missing(t.Start)
		kids = append(kids, r.LParen, r.Body, r.RParen)
		if t.Kind == token.Newline {
			r.Tail = []token.Token{p.next()}
		}
	}
	for _, t := range r.Tail {
		kids = append(kids, t)
	}
	cst.Seal(r, p.src, 0, kids...)
	return r, trailing
}

// parseTail parses what follows a rule's ')': a run of whitespace and line
// continuations and then the newline, or the EOF, or the action of the
// next rule written on the same logical line, which the tail then stops
// before. Anything else is reported as syntax-trailing-text and, with the
// trivia before it, consumed through the end of the line into a Bad that
// the caller adds to the file after the rule; the rule's tail is then
// empty.
func (p *parser) parseTail() ([]token.Token, *cst.Bad) {
	run := p.trivia()
	t := p.peek()
	switch {
	case t.Kind == token.Newline:
		return append(run, p.next()), nil
	case t.Kind == token.EOF, t.Kind == token.Word && IsAction(t.Lit):
		return run, nil
	}
	p.report(RuleTrailingText, t.Span(), "unexpected %s after ')'", describe(t))
	return nil, p.badThroughNewline(run)
}

// tokenNodes converts tokens to nodes.
func tokenNodes(toks []token.Token) []cst.Node {
	out := make([]cst.Node, len(toks))
	for i, t := range toks {
		out[i] = t
	}
	return out
}

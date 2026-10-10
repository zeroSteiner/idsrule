package parser

import (
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

// isHeaderEnd reports whether t ends a rule header: the '(' that opens the
// body, or a newline or the EOF, which end the rule.
func isHeaderEnd(t token.Token) bool {
	return t.Kind == token.LParen || t.Kind == token.Newline || t.Kind == token.EOF
}

// isDirection reports whether t is one of the two direction operators.
func isDirection(t token.Token) bool {
	return t.Kind == token.Word && (t.Lit == "->" || t.Lit == "<>")
}

// parseHeader parses a rule header, from the action (the current token) up
// to but not including the '(' and the trivia before it.
//
// The seven parts are taken in order from the token stream: the protocol
// and the direction are single tokens, the address and port groups are
// whitespace-delimited fields (see field). When the stream reaches '(', a
// newline or the EOF before all seven are in, the missing part is reported
// and it and every part after it become Missing tokens, or groups holding
// one, at the point where the header stopped. A token where the protocol
// or the direction should be is kept as that part whatever it is, so that
// the parts after it still line up. Tokens left over before '(' are kept
// as Extra. All of that is syntax-bad-header, reported once per header;
// an unclosed '[' is syntax-unbalanced-bracket and is reported on its own.
func (p *parser) parseHeader() *cst.Header {
	h := &cst.Header{Action: p.next()}
	kids := make([]cst.Node, 0, 16)
	kids = append(kids, h.Action)
	reported := false
	report := func(span source.Span, format string, args ...any) {
		if !reported {
			reported = true
			p.report(RuleBadHeader, span, format, args...)
		}
	}
	stopped := -1 // where the header ran out of parts, once it has

	// need prepares for the named part: it reports the header as having
	// run out when the next significant token ends the header, and
	// otherwise moves the trivia before the part into the header.
	need := func(name string) bool {
		if stopped >= 0 {
			return false
		}
		if isHeaderEnd(p.afterTrivia()) {
			stopped = p.peek().Start
			report(emptySpan(stopped), "header is missing its %s", name)
			return false
		}
		kids = p.triviaInto(kids)
		return true
	}
	word := func(name string, ok func(token.Token) bool, want string) token.Token {
		if !need(name) {
			t := missing(stopped)
			kids = append(kids, t)
			return t
		}
		t := p.next()
		kids = append(kids, t)
		if !ok(t) {
			report(t.Span(), "expected %s, got %s", want, describe(t))
		}
		return t
	}
	group := func(name string) *cst.Group {
		if !need(name) {
			t := missing(stopped)
			g := &cst.Group{Word: &t}
			cst.Seal(g, p.src, stopped, t)
			kids = append(kids, g)
			return g
		}
		g := p.parseGroup(report)
		kids = append(kids, g)
		return g
	}

	h.Proto = word("protocol", func(t token.Token) bool { return t.Kind == token.Word }, "a protocol")
	h.Src = group("source address")
	h.SrcPort = group("source port")
	h.Dir = word("direction", isDirection, "direction '->' or '<>'")
	h.Dst = group("destination address")
	h.DstPort = group("destination port")

	for stopped < 0 && !isHeaderEnd(p.afterTrivia()) {
		kids = p.triviaInto(kids)
		t := p.next()
		h.Extra = append(h.Extra, t)
		kids = append(kids, t)
		report(t.Span(), "unexpected %s in header", describe(t))
	}
	cst.Seal(h, p.src, 0, kids...)
	return h
}

// reportFn reports a syntax-bad-header diagnostic, at most once per header.
type reportFn func(span source.Span, format string, args ...any)

// parseGroup parses one address or port group: the next field of the
// header. A field that is not '!'? followed by a word or a balanced list
// becomes a Group holding every token of the field as Bad, with one
// diagnostic: syntax-unbalanced-bracket at the '[' of a list that was
// still open when the field ended, or syntax-bad-header at the first token
// that did not fit otherwise.
func (p *parser) parseGroup(report reportFn) *cst.Group {
	// The common case, a lone word, needs no field collection.
	if t := p.peek(); t.Kind == token.Word {
		if after := p.toks[p.pos+1]; isTrivia(after) || isHeaderEnd(after) {
			word := p.next()
			g := &cst.Group{Word: &word}
			cst.Seal(g, p.src, 0, word)
			return g
		}
	}
	field := p.field()
	g, err := buildGroup(p.src, field)
	if err == nil {
		return g
	}
	if err.unbalanced {
		p.report(RuleUnbalancedBracket, err.tok.Span(), "unbalanced '[': no matching ']'")
	} else {
		report(err.tok.Span(), "unexpected %s in header", describe(err.tok))
	}
	g = &cst.Group{Bad: field}
	cst.Seal(g, p.src, p.peek().Start, tokenNodes(field)...)
	return g
}

// field consumes the tokens of one header part: a run that ends at trivia
// outside brackets, at '(', at a newline or at the EOF. Inside brackets a
// run of trivia is part of the field when it is next to a bracket or a
// comma, as in "[80, 90]"; between two items, as in "[80 90", it ends the
// field, so that an unclosed '[' is confined to its own part and the parts
// after it still parse. The result is never empty: the caller has seen a
// significant token at the current position.
//
// Every token is looked at a bounded number of times: a run of trivia is
// scanned to its end once, to see what follows it, and then taken or left
// whole, and the kind of the last significant token is carried along
// rather than looked up.
func (p *parser) field() []token.Token {
	var toks []token.Token
	depth := 0
	last := token.EOF // kind of the last significant token taken
	for {
		t := p.peek()
		switch {
		case isHeaderEnd(t):
			return toks
		case isTrivia(t):
			if depth == 0 {
				return toks
			}
			end := p.triviaEnd()
			if next := p.toks[end].Kind; last != token.LBracket && last != token.Comma &&
				next != token.Comma && next != token.RBracket {
				return toks
			}
			for p.pos < end {
				toks = append(toks, p.next())
			}
			continue
		case t.Kind == token.LBracket:
			depth++
		case t.Kind == token.RBracket && depth > 0:
			depth--
		}
		last = t.Kind
		toks = append(toks, p.next())
	}
}

// fieldErr is why a field did not parse as a group: the token that did not
// fit, or, for an unclosed list, its '['.
type fieldErr struct {
	tok        token.Token
	unbalanced bool
}

// buildGroup parses the tokens of a field as '!'? ( Word | List ), with
// nothing left over.
func buildGroup(src []byte, toks []token.Token) (*cst.Group, *fieldErr) {
	if len(toks) == 0 {
		return nil, &fieldErr{}
	}
	g, i, err := groupAt(src, toks, 0)
	if err != nil {
		return nil, err
	}
	if i < len(toks) {
		return nil, &fieldErr{tok: toks[i]}
	}
	return g, nil
}

// groupAt parses a group starting at toks[i] and returns it with the index
// of the first token after it.
func groupAt(src []byte, toks []token.Token, i int) (*cst.Group, int, *fieldErr) {
	g := &cst.Group{}
	var kids []cst.Node
	if toks[i].Kind == token.Bang {
		bang := toks[i]
		g.Bang = &bang
		kids = append(kids, bang)
		i++
		if i == len(toks) {
			return nil, i, &fieldErr{tok: bang}
		}
	}
	if tok := toks[i]; tok.Kind == token.LBracket {
		list, j, err := listAt(src, toks, i)
		if err != nil {
			return nil, j, err
		}
		g.List = list
		kids = append(kids, list)
		i = j
	} else {
		if tok.Kind != token.Word {
			return nil, i, &fieldErr{tok: tok}
		}
		g.Word = &tok
		kids = append(kids, tok)
		i++
	}
	cst.Seal(g, src, 0, kids...)
	return g, i, nil
}

// listAt parses a bracketed list starting at the '[' at toks[i]: groups
// separated by commas, with trivia allowed anywhere inside, and returns it
// with the index of the first token after its ']'. A list is strict about
// its shape: an empty item (",," or a trailing ",") is an error, while "[]"
// is an empty list. Running out of tokens with the list open is the
// unbalanced error, reported at this list's '['.
func listAt(src []byte, toks []token.Token, i int) (*cst.List, int, *fieldErr) {
	l := &cst.List{LBracket: toks[i]}
	kids := []cst.Node{l.LBracket}
	i++
	wantItem := true
	for {
		if i == len(toks) {
			return nil, i, &fieldErr{tok: l.LBracket, unbalanced: true}
		}
		t := toks[i]
		switch {
		case isTrivia(t):
			kids = append(kids, t)
			i++
		case t.Kind == token.RBracket:
			if wantItem && len(l.Items) > 0 {
				return nil, i, &fieldErr{tok: t}
			}
			l.RBracket = t
			kids = append(kids, t)
			cst.Seal(l, src, 0, kids...)
			return l, i + 1, nil
		case t.Kind == token.Comma:
			if wantItem {
				return nil, i, &fieldErr{tok: t}
			}
			l.Commas = append(l.Commas, t)
			kids = append(kids, t)
			i++
			wantItem = true
		case t.Kind == token.Bang, t.Kind == token.Word, t.Kind == token.LBracket:
			if !wantItem {
				return nil, i, &fieldErr{tok: t}
			}
			item, j, err := groupAt(src, toks, i)
			if err != nil {
				return nil, j, err
			}
			l.Items = append(l.Items, item)
			kids = append(kids, item)
			i = j
			wantItem = false
		default:
			return nil, i, &fieldErr{tok: t}
		}
	}
}

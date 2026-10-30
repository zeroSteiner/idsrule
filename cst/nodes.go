package cst

import (
	"strings"
	"sync"

	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

// File is the root of the tree: one rule file.
type File struct {
	base
	Path  string      // the name the file was parsed under; informational
	Src   []byte      // the complete source
	Items []Node      // *Rule, *Comment, *BlankLine or *Bad, in source order
	EOF   token.Token // the zero-width token at len(Src)

	linesOnce sync.Once
	lines     *source.LineTable
	toksOnce  sync.Once
	toks      []token.Token
}

// Rules returns the rules of the file in source order.
func (f *File) Rules() []*Rule {
	var rules []*Rule
	for _, it := range f.Items {
		if r, ok := it.(*Rule); ok {
			rules = append(rules, r)
		}
	}
	return rules
}

// Lines returns the line table of Src. It is built on first use and cached.
func (f *File) Lines() *source.LineTable {
	f.linesOnce.Do(func() { f.lines = source.NewLineTable(f.Src) })
	return f.lines
}

// TokenStream returns every token of the file in source order, the EOF
// included. It is built on first use and cached; the slice must not be
// modified.
func (f *File) TokenStream() []token.Token {
	f.toksOnce.Do(func() { f.toks = Tokens(f) })
	return f.toks
}

// Rule is one rule: its header, the parenthesised option body and the tail
// of its logical line.
type Rule struct {
	base
	Header *Header
	LParen token.Token // Missing when the header was not followed by '('
	Body   *Body       // never nil; empty when there was no '('
	RParen token.Token // Missing when the body ran into a newline or the EOF
	// Tail is what follows ')' on the rule's logical line: a run of
	// Whitespace and LineContinuation tokens, if any, and then the Newline.
	// At the end of the file the run is not followed by a Newline, and
	// when another rule follows on the same logical line the tail stops
	// before its action; either way it is empty when nothing but ')'
	// precedes that point.
	Tail []token.Token
}

// Options returns the options of the rule in source order.
func (r *Rule) Options() []*Option {
	if r.Body == nil {
		return nil
	}
	return r.Body.Options
}

// Option returns the first option whose name is exactly name, or nil.
func (r *Rule) Option(name string) *Option {
	for _, o := range r.Options() {
		if o.Name() == name {
			return o
		}
	}
	return nil
}

// OptionsNamed returns every option whose name is exactly name, in source
// order.
func (r *Rule) OptionsNamed(name string) []*Option {
	var out []*Option
	for _, o := range r.Options() {
		if o.Name() == name {
			out = append(out, o)
		}
	}
	return out
}

// MultiLine reports whether the rule is continued across physical lines,
// that is whether it contains a LineContinuation token.
func (r *Rule) MultiLine() bool {
	found := false
	Walk(r, func(n Node) bool {
		if t, ok := n.(token.Token); ok && t.Kind == token.LineContinuation {
			found = true
		}
		return !found
	})
	return found
}

// Header is the part of a rule before '(': the action, the protocol, the
// source and destination address and port groups and the direction.
//
// Every field is set. A part the header lacks is a Missing token or a Group
// whose Word is a Missing token, placed where the part should have been.
type Header struct {
	base
	// Action is the action, with the scope Suricata 8 may give it after a
	// ':' ("drop:flow"), kept in the token: "alert", "accept:hook".
	Action token.Token
	// MoreActions are the further actions of a Suricata 8 firewall rule,
	// "accept:hook,alert", each after the ',' at the same index of
	// ActionCommas. A list that ends in a ',' has one comma more.
	MoreActions  []token.Token
	ActionCommas []token.Token
	// Proto is the protocol, with the hook Suricata 8 may give it after a
	// ':' ("http1:request_line", "tcp:all") kept in the token.
	Proto   token.Token
	Src     *Group
	SrcPort *Group
	Dir     token.Token // "->", "<>" or "=>"; kept as found when it is something else
	Dst     *Group
	DstPort *Group
	Extra   []token.Token // unexpected tokens between the last part and '('
}

// Group is an address or port expression: a word such as "any", "$HOME_NET"
// or "80:90", or a bracketed list, either optionally negated with '!'.
//
// Exactly one of Word, List and Bad is set. Bad holds the tokens of a group
// that did not parse, an unclosed list for instance; a group the header
// lacks has a Missing Word.
type Group struct {
	base
	Bang *token.Token
	Word *token.Token
	List *List
	Bad  []token.Token
}

// List is a bracketed, comma-separated list of groups. Lists nest, and
// whitespace next to the brackets and the commas is kept as children. An
// unclosed list does not become a List: its tokens are the Bad tokens of
// the enclosing Group.
//
// Suricata also reads an address or port list written without brackets,
// "10.0.0.0/8,192.168.0.0/16". Such a list is the List of its own Group,
// with Missing tokens as LBracket and RBracket; Bracketed tells the two
// apart.
type List struct {
	base
	LBracket token.Token
	Items    []*Group
	Commas   []token.Token
	RBracket token.Token
}

// Bracketed reports whether the list is written with brackets, as opposed
// to Suricata's bare "a,b".
func (l *List) Bracketed() bool { return l.LBracket.Kind != token.Missing }

// Body is everything strictly between a rule's '(' and ')': its options,
// the runs of tokens that did not parse as options, and the trivia between
// them.
type Body struct {
	base
	Options []*Option
	Bads    []*Bad
}

// Option is one option of a rule: a keyword, optionally ':' and a value,
// and the ';' that ends it.
type Option struct {
	base
	Keyword token.Token
	Colon   *token.Token // nil for an option without a value, such as "nocase"
	// Value holds every token between ':' and ';': Value, Whitespace and
	// LineContinuation tokens. It is empty when there is no ':' or when
	// nothing follows it.
	Value     []token.Token
	Semicolon token.Token // Missing when the option was not ended by ';'
	Err       bool        // the option ran into ')', a newline or the EOF
}

// Name returns the option's keyword.
func (o *Option) Name() string { return o.Keyword.Lit }

// HasValue reports whether the option has a ':' and so a value, possibly an
// empty one.
func (o *Option) HasValue() bool { return o.Colon != nil }

// ValueSpan returns the span of the value: from the first to the last token
// of Value, or an empty span just after the ':' (or the keyword when there
// is none) when Value is empty.
func (o *Option) ValueSpan() source.Span {
	if len(o.Value) == 0 {
		end := o.Keyword.End
		if o.Colon != nil {
			end = o.Colon.End
		}
		return source.Span{Start: end, End: end}
	}
	return source.Span{Start: o.Value[0].Start, End: o.Value[len(o.Value)-1].End}
}

// RawValue returns the source text of ValueSpan, line continuations and all.
func (o *Option) RawValue() string {
	var b strings.Builder
	for _, t := range o.Value {
		b.WriteString(t.Lit)
	}
	return b.String()
}

// LogicalValue returns the value as the engines see it: the Value tokens
// concatenated with the line continuations dropped and the whitespace kept,
// then trimmed of spaces and tabs at both ends. The returned function maps
// an offset in that string to the byte offset in the source of the same
// byte; an offset at or past the end maps to ValueSpan().End.
func (o *Option) LogicalValue() (string, func(logicalOff int) int) {
	type segment struct{ logical, src, n int }
	var segs []segment
	var b strings.Builder
	for _, t := range o.Value {
		if t.Kind == token.LineContinuation {
			continue
		}
		segs = append(segs, segment{logical: b.Len(), src: t.Start, n: len(t.Lit)})
		b.WriteString(t.Lit)
	}
	full := b.String()
	lead := len(full) - len(strings.TrimLeft(full, " \t"))
	logical := strings.TrimRight(full[lead:], " \t")
	end := o.ValueSpan().End
	mapper := func(off int) int {
		if off >= len(logical) {
			return end
		}
		off = max(off, 0) + lead
		for _, s := range segs {
			if off < s.logical+s.n {
				return s.src + off - s.logical
			}
		}
		return end
	}
	return logical, mapper
}

// Comment is a comment line: a '#' at the start of the line (after optional
// trivia) through the end of the line.
type Comment struct {
	base
	Leading []token.Token // the Whitespace and LineContinuation tokens before '#'
	Hash    token.Token   // the Comment token, '#' through the end of the line
	Newline *token.Token  // the line's Newline, or nil at the end of the file
}

// BlankLine is a line with nothing but trivia on it: a run of Whitespace
// and LineContinuation tokens and an optional Newline, at least one token.
type BlankLine struct {
	base
	Tokens []token.Token
}

// Bad is a run of tokens that did not parse: at file level a line that is
// not a rule, a comment or blank, through its newline, or the text after a
// rule's ')'; inside a body a run of tokens skipped to resynchronise on the
// next option.
type Bad struct {
	base
	Tokens []token.Token
}

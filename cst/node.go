// Package cst is the lossless concrete syntax tree of a rule file.
//
// Every byte of the source is in the tree: the leaves are the lexer's
// tokens, trivia included, and the children of every node are contiguous
// and cover exactly the node's span, so that the text of any node is the
// concatenation of its children's text and the text of the [File] is the
// source itself. Where the parser needed a token that was not there it
// inserts a zero-width [token.Missing] token, so that the typed fields of a
// node are always set and the tree keeps its shape under errors.
//
// Trivia (whitespace, line continuations) between the first and last
// significant tokens of a node belongs to that node; trivia outside them
// belongs to the parent. The one exception is [Rule.Tail]: a rule owns the
// whitespace and newline after its closing parenthesis, so that it covers
// its whole logical line.
package cst

import "github.com/zeroSteiner/idsrule/source"

// Node is any syntax element: a [token.Token] leaf or one of the composite
// node types of this package.
type Node interface {
	// Span returns the byte range the node covers.
	Span() source.Span
	// Text returns the exact source bytes of Span.
	Text() string
}

// Composite is a [Node] with children: every node type of this package.
// [token.Token] is the only Node that is not a Composite. Only this
// package's types implement it.
type Composite interface {
	Node
	node() *base
}

// base is the state every composite node embeds: its span, the whole source
// of the file (shared by every node of the tree) and its ordered children,
// trivia and Missing tokens included.
type base struct {
	span source.Span
	src  []byte
	kids []Node
}

func (b *base) node() *base { return b }

// Span returns the byte range the node covers.
func (b *base) Span() source.Span { return b.span }

// Text returns the exact source bytes the node covers.
func (b *base) Text() string { return string(b.src[b.span.Start:b.span.End]) }

// Seal fixes the source, the children and the span of a composite node. The
// children must be in source order and contiguous; the span then runs from
// the first child's start to the last child's end, or is empty at offset at
// when there are no children. Parsers call Seal once per node, after
// setting its typed fields; a sealed node is not modified again.
func Seal(n Composite, src []byte, at int, kids ...Node) {
	b := n.node()
	b.src = src
	b.kids = kids
	b.span = source.Span{Start: at, End: at}
	if len(kids) > 0 {
		b.span = source.Span{Start: kids[0].Span().Start, End: kids[len(kids)-1].Span().End}
	}
}

// Children returns the ordered children of n, trivia and Missing tokens
// included, or nil for a token. The slice is the node's own and must not be
// modified.
func Children(n Node) []Node {
	if c, ok := n.(Composite); ok {
		return c.node().kids
	}
	return nil
}

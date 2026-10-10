package cst

import (
	"bytes"
	"fmt"

	"github.com/zeroSteiner/idsrule/token"
)

// Verify checks the structural invariants that every tree the parser
// produces satisfies, and returns the first violation it finds, or nil:
//
//   - the children of a composite node are contiguous and cover exactly its
//     span, and a node without children has an empty span;
//   - every composite node reads its text from the same source as the root
//     of the tree, and every token's text is the bytes of that source its
//     span covers, so that the text of a node is the concatenation of its
//     children's;
//   - every node a typed field refers to is also a child, in order;
//   - Missing tokens and the EOF are zero-width, and no other token is;
//   - the text of a File is its source.
//
// It runs in time linear in the size of the tree. It is meant for tests
// and for code that builds or rewrites trees.
func Verify(n Node) error {
	c, ok := n.(Composite)
	if !ok {
		// A bare token has no source to check its text against; only its
		// shape can be verified.
		if t, ok := n.(token.Token); ok {
			zero := t.Kind == token.Missing || t.Kind == token.EOF
			if (t.End-t.Start == 0) != zero {
				return fmt.Errorf("%s token at %d:%d has the wrong width", t.Kind, t.Start, t.End)
			}
			if len(t.Lit) != t.End-t.Start {
				return fmt.Errorf("%s token at %d:%d has text of length %d", t.Kind, t.Start, t.End, len(t.Lit))
			}
			return nil
		}
		return fmt.Errorf("%T is not a node type of this package", n)
	}
	src := c.node().src
	if f, ok := n.(*File); ok && (f.span.Start != 0 || f.span.End != len(f.Src) || !sameSource(f.Src, src)) {
		return fmt.Errorf("File %d:%d: text differs from Src", f.span.Start, f.span.End)
	}
	var err error
	Walk(n, func(n Node) bool {
		if err == nil {
			err = verifyNode(n, src)
		}
		return err == nil
	})
	return err
}

// verifyNode checks one node against src, the source of the root.
func verifyNode(n Node, src []byte) error {
	if t, ok := n.(token.Token); ok {
		return verifyToken(t, src)
	}
	comp, ok := n.(Composite)
	if !ok {
		return fmt.Errorf("%T is not a node type of this package", n)
	}
	c := comp.node()
	span, kids := c.span, c.kids
	where := func() string { return fmt.Sprintf("%s %d:%d", typeName(n), span.Start, span.End) }
	if span.Start > span.End {
		return fmt.Errorf("%s ends before it starts", where())
	}
	if !sameSource(c.src, src) {
		return fmt.Errorf("%s reads its text from a different source than the root", where())
	}
	if len(kids) == 0 {
		if !span.Empty() {
			return fmt.Errorf("%s has no children but a non-empty span", where())
		}
		return nil
	}
	if first := kids[0].Span().Start; first != span.Start {
		return fmt.Errorf("%s: first child starts at %d", where(), first)
	}
	if last := kids[len(kids)-1].Span().End; last != span.End {
		return fmt.Errorf("%s: last child ends at %d", where(), last)
	}
	for i := 1; i < len(kids); i++ {
		if kids[i].Span().Start != kids[i-1].Span().End {
			return fmt.Errorf("%s: child %d starts at %d, the previous one ends at %d",
				where(), i, kids[i].Span().Start, kids[i-1].Span().End)
		}
	}
	i := 0
	for _, p := range parts(n) {
		for i < len(kids) && kids[i] != p {
			i++
		}
		if i == len(kids) {
			return fmt.Errorf("%s: part %s %d:%d is not among the children in order",
				where(), typeName(p), p.Span().Start, p.Span().End)
		}
		i++
	}
	return nil
}

// verifyToken checks a token's width and that its text is what src holds.
func verifyToken(t token.Token, src []byte) error {
	if t.Start > t.End {
		return fmt.Errorf("%s token at %d:%d ends before it starts", kindName(t.Kind), t.Start, t.End)
	}
	if t.Start < 0 || t.End > len(src) {
		return fmt.Errorf("%s token at %d:%d lies outside the source of %d bytes", kindName(t.Kind), t.Start, t.End, len(src))
	}
	if zeroWidth := t.Kind == token.Missing || t.Kind == token.EOF; zeroWidth != (t.Start == t.End) {
		if zeroWidth {
			return fmt.Errorf("%s token at %d:%d is not zero-width", kindName(t.Kind), t.Start, t.End)
		}
		return fmt.Errorf("%s token at %d:%d is zero-width", kindName(t.Kind), t.Start, t.End)
	}
	if string(src[t.Start:t.End]) != t.Lit {
		return fmt.Errorf("%s token at %d:%d has text %q, the source has %q", kindName(t.Kind), t.Start, t.End, t.Lit, src[t.Start:t.End])
	}
	return nil
}

// sameSource reports whether a and b are the same source: the same bytes,
// checked by identity first so that a tree built on one source is verified
// in linear time.
func sameSource(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 || &a[0] == &b[0] {
		return true
	}
	return bytes.Equal(a, b)
}

// typeName returns the name a node prints under in Dump: the kind of a
// token, or the type name of a composite node.
func typeName(n Node) string {
	switch n := n.(type) {
	case token.Token:
		return kindName(n.Kind)
	case *File:
		return "File"
	case *Rule:
		return "Rule"
	case *Header:
		return "Header"
	case *Group:
		return "Group"
	case *List:
		return "List"
	case *Body:
		return "Body"
	case *Option:
		return "Option"
	case *Comment:
		return "Comment"
	case *BlankLine:
		return "BlankLine"
	case *Bad:
		return "Bad"
	}
	return fmt.Sprintf("%T", n)
}

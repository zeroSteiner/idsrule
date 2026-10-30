package cst

import (
	"cmp"
	"slices"

	"github.com/zeroSteiner/idsrule/token"
)

// Walk traverses the tree rooted at n in pre-order, calling visit for every
// node. When visit returns false the node's children are skipped.
func Walk(n Node, visit func(Node) bool) {
	if !visit(n) {
		return
	}
	for _, k := range Children(n) {
		Walk(k, visit)
	}
}

// Tokens returns every token in the tree rooted at n, in source order.
func Tokens(n Node) []token.Token {
	var toks []token.Token
	Walk(n, func(n Node) bool {
		if t, ok := n.(token.Token); ok {
			toks = append(toks, t)
		}
		return true
	})
	return toks
}

// parts returns the significant parts of a composite node, that is the
// nodes its typed fields hold, in source order. Every part is also one of
// the node's children; Verify checks that.
func parts(n Node) []Node {
	var out []Node
	add := func(ns ...Node) {
		for _, n := range ns {
			if n != nil {
				out = append(out, n)
			}
		}
	}
	addTok := func(t *token.Token) {
		if t != nil {
			out = append(out, *t)
		}
	}
	addToks := func(ts []token.Token) {
		for _, t := range ts {
			out = append(out, t)
		}
	}
	switch n := n.(type) {
	case *File:
		add(n.Items...)
		add(n.EOF)
	case *Rule:
		if n.Header != nil {
			add(n.Header)
		}
		add(n.LParen)
		if n.Body != nil {
			add(n.Body)
		}
		add(n.RParen)
		addToks(n.Tail)
	case *Header:
		add(n.Action)
		actions := make([]Node, 0, len(n.MoreActions)+len(n.ActionCommas))
		for _, t := range n.MoreActions {
			actions = append(actions, t)
		}
		for _, t := range n.ActionCommas {
			actions = append(actions, t)
		}
		add(sortBySpan(actions)...)
		add(n.Proto)
		add(groupNode(n.Src), groupNode(n.SrcPort))
		add(n.Dir)
		add(groupNode(n.Dst), groupNode(n.DstPort))
		addToks(n.Extra)
	case *Group:
		addTok(n.Bang)
		addTok(n.Word)
		if n.List != nil {
			add(n.List)
		}
		addToks(n.Bad)
	case *List:
		add(n.LBracket)
		items := make([]Node, 0, len(n.Items)+len(n.Commas))
		for _, g := range n.Items {
			items = append(items, g)
		}
		for _, c := range n.Commas {
			items = append(items, c)
		}
		add(sortBySpan(items)...)
		add(n.RBracket)
	case *Body:
		items := make([]Node, 0, len(n.Options)+len(n.Bads))
		for _, o := range n.Options {
			items = append(items, o)
		}
		for _, b := range n.Bads {
			items = append(items, b)
		}
		add(sortBySpan(items)...)
	case *Option:
		add(n.Keyword)
		addTok(n.Colon)
		addToks(n.Value)
		add(n.Semicolon)
	case *Comment:
		addToks(n.Leading)
		add(n.Hash)
		addTok(n.Newline)
	case *BlankLine:
		addToks(n.Tokens)
	case *Bad:
		addToks(n.Tokens)
	}
	return out
}

// groupNode converts a possibly nil *Group to a Node without producing a
// typed nil interface.
func groupNode(g *Group) Node {
	if g == nil {
		return nil
	}
	return g
}

// sortBySpan orders nodes by the start of their span; the input slice is
// sorted in place and returned.
func sortBySpan(ns []Node) []Node {
	slices.SortStableFunc(ns, func(a, b Node) int { return cmp.Compare(a.Span().Start, b.Span().Start) })
	return ns
}

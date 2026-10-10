package cst

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/zeroSteiner/idsrule/token"
)

// kindNames are the Go-style names tokens print under in Dump.
var kindNames = [...]string{
	token.EOF:              "EOF",
	token.Newline:          "Newline",
	token.Whitespace:       "Whitespace",
	token.LineContinuation: "LineContinuation",
	token.Comment:          "Comment",
	token.Word:             "Word",
	token.Bang:             "Bang",
	token.LBracket:         "LBracket",
	token.RBracket:         "RBracket",
	token.Comma:            "Comma",
	token.LParen:           "LParen",
	token.RParen:           "RParen",
	token.Keyword:          "Keyword",
	token.Colon:            "Colon",
	token.Semicolon:        "Semicolon",
	token.Value:            "Value",
	token.Bad:              "Bad",
	token.Missing:          "Missing",
}

// kindName returns the Dump name of a token kind, falling back to the
// kind's own String for a value outside the table.
func kindName(k token.Kind) string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return k.String()
}

// Dump writes the tree rooted at n to w, one node per line, indented two
// spaces per level, with the closing parenthesis of a composite node on the
// line of its last child:
//
//	(Option 31:37
//	  (Keyword 31:34 "sid")
//	  (Colon 34:35 ":")
//	  (Value 35:36 "1")
//	  (Semicolon 36:37 ";"))
//
// A token prints as its kind, its span and its text quoted as Go syntax; a
// composite node prints as its type name and its span, and one without
// children prints on a line of its own, as in "(Body 5:5)". The dump ends
// with a newline.
func Dump(w io.Writer, n Node) error {
	var buf bytes.Buffer
	dump(&buf, n, 0)
	buf.WriteByte('\n')
	_, err := w.Write(buf.Bytes())
	return err
}

func dump(w *bytes.Buffer, n Node, depth int) {
	for range depth {
		w.WriteString("  ")
	}
	span := n.Span()
	if t, ok := n.(token.Token); ok {
		fmt.Fprintf(w, "(%s %d:%d %s)", kindName(t.Kind), span.Start, span.End, strconv.Quote(t.Lit))
		return
	}
	fmt.Fprintf(w, "(%s %d:%d", typeName(n), span.Start, span.End)
	for _, k := range Children(n) {
		w.WriteByte('\n')
		dump(w, k, depth+1)
	}
	w.WriteByte(')')
}

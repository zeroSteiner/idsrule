package cst_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

// tok builds a token covering lit at offset start.
func tok(kind token.Kind, start int, lit string) token.Token {
	return token.Token{Kind: kind, Start: start, End: start + len(lit), Lit: lit}
}

// ptr returns a pointer to a copy of t.
func ptr(t token.Token) *token.Token { return &t }

// The hand-built tree below is the file "x (a:1; b;)\n": a header of one
// Missing part after the action, so that the test stays short while every
// node type but List appears.
const src = "x (a:1; b;)\n"

func buildFile(t *testing.T) *cst.File {
	t.Helper()
	b := []byte(src)
	action := tok(token.Word, 0, "x")
	h := &cst.Header{Action: action, Proto: tok(token.Missing, 1, ""), Dir: tok(token.Missing, 1, "")}
	for _, g := range []**cst.Group{&h.Src, &h.SrcPort, &h.Dst, &h.DstPort} {
		m := tok(token.Missing, 1, "")
		*g = &cst.Group{Word: &m}
		cst.Seal(*g, b, 1, m)
	}
	cst.Seal(h, b, 0, action, h.Proto, h.Src, h.SrcPort, h.Dir, h.Dst, h.DstPort)

	a := &cst.Option{Keyword: tok(token.Keyword, 3, "a"), Colon: ptr(tok(token.Colon, 4, ":")),
		Value: []token.Token{tok(token.Value, 5, "1")}, Semicolon: tok(token.Semicolon, 6, ";")}
	cst.Seal(a, b, 0, a.Keyword, *a.Colon, a.Value[0], a.Semicolon)
	bo := &cst.Option{Keyword: tok(token.Keyword, 8, "b"), Semicolon: tok(token.Semicolon, 9, ";")}
	cst.Seal(bo, b, 0, bo.Keyword, bo.Semicolon)
	ws := tok(token.Whitespace, 7, " ")
	body := &cst.Body{Options: []*cst.Option{a, bo}}
	cst.Seal(body, b, 0, a, ws, bo)

	r := &cst.Rule{Header: h, LParen: tok(token.LParen, 2, "("), Body: body, RParen: tok(token.RParen, 10, ")"),
		Tail: []token.Token{tok(token.Newline, 11, "\n")}}
	cst.Seal(r, b, 0, h, tok(token.Whitespace, 1, " "), r.LParen, body, r.RParen, r.Tail[0])

	f := &cst.File{Path: "x.rule", Src: b, Items: []cst.Node{r}, EOF: tok(token.EOF, 12, "")}
	cst.Seal(f, b, 0, r, f.EOF)
	if err := cst.Verify(f); err != nil {
		t.Fatalf("Verify(hand-built file) = %v", err)
	}
	return f
}

func TestSealSpansAndText(t *testing.T) {
	f := buildFile(t)
	r := f.Rules()[0]
	tests := []struct {
		name string
		node cst.Node
		span source.Span
		text string
	}{
		{"file", f, source.Span{Start: 0, End: 12}, src},
		{"rule", r, source.Span{Start: 0, End: 12}, src},
		{"header", r.Header, source.Span{Start: 0, End: 1}, "x"},
		{"missing group", r.Header.Src, source.Span{Start: 1, End: 1}, ""},
		{"body", r.Body, source.Span{Start: 3, End: 10}, "a:1; b;"},
		{"option", r.Body.Options[0], source.Span{Start: 3, End: 7}, "a:1;"},
		{"token", r.RParen, source.Span{Start: 10, End: 11}, ")"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.node.Span(); got != tt.span {
				t.Errorf("Span() = %v, want %v", got, tt.span)
			}
			if got := tt.node.Text(); got != tt.text {
				t.Errorf("Text() = %q, want %q", got, tt.text)
			}
		})
	}
	empty := &cst.Body{}
	cst.Seal(empty, []byte(src), 5)
	if got := empty.Span(); got != (source.Span{Start: 5, End: 5}) || empty.Text() != "" {
		t.Errorf("empty Body sealed at 5: Span() = %v, Text() = %q", got, empty.Text())
	}
}

func TestChildrenWalkTokens(t *testing.T) {
	f := buildFile(t)
	r := f.Rules()[0]
	if kids := cst.Children(f); len(kids) != 2 || kids[0] != cst.Node(r) || kids[1] != cst.Node(f.EOF) {
		t.Errorf("Children(file) = %v", kids)
	}
	if kids := cst.Children(r.RParen); kids != nil {
		t.Errorf("Children(token) = %v, want nil", kids)
	}

	// Pre-order, with the body skipped: the rule's children after the
	// body must still be visited.
	var order []string
	cst.Walk(f, func(n cst.Node) bool {
		var buf bytes.Buffer
		_ = cst.Dump(&buf, n)
		order = append(order, strings.SplitN(buf.String(), " ", 2)[0])
		_, isBody := n.(*cst.Body)
		return !isBody
	})
	want := []string{"(File", "(Rule", "(Header", "(Word", "(Missing", "(Group", "(Missing", "(Group", "(Missing",
		"(Missing", "(Group", "(Missing", "(Group", "(Missing", "(Whitespace", "(LParen", "(Body", "(RParen", "(Newline", "(EOF"}
	if strings.Join(order, " ") != strings.Join(want, " ") {
		t.Errorf("Walk order:\n got %v\nwant %v", order, want)
	}

	toks := cst.Tokens(f)
	var text strings.Builder
	for _, tk := range toks {
		text.WriteString(tk.Lit)
	}
	if text.String() != src {
		t.Errorf("Tokens() concatenate to %q, want %q", text.String(), src)
	}
	if last := toks[len(toks)-1]; last.Kind != token.EOF {
		t.Errorf("last token = %v, want EOF", last)
	}
	if got := f.TokenStream(); len(got) != len(toks) || &got[0] != &f.TokenStream()[0] {
		t.Errorf("TokenStream() is not the cached token list")
	}
}

func TestFileHelpers(t *testing.T) {
	f := buildFile(t)
	if rules := f.Rules(); len(rules) != 1 || rules[0].Text() != src {
		t.Errorf("Rules() = %v", rules)
	}
	lines := f.Lines()
	if lines != f.Lines() {
		t.Error("Lines() is not cached")
	}
	if pos := lines.Position(11); pos != (source.Position{Line: 1, Column: 12}) {
		t.Errorf("Lines().Position(11) = %v", pos)
	}
	if lines.NumLines() != 2 {
		t.Errorf("NumLines() = %d, want 2", lines.NumLines())
	}
}

func TestRuleHelpers(t *testing.T) {
	r := buildFile(t).Rules()[0]
	if got := r.Options(); len(got) != 2 || got[0].Name() != "a" || got[1].Name() != "b" {
		t.Errorf("Options() = %v", got)
	}
	if o := r.Option("b"); o == nil || o.HasValue() {
		t.Errorf("Option(b) = %+v", o)
	}
	if o := r.Option("c"); o != nil {
		t.Errorf("Option(c) = %+v, want nil", o)
	}
	if got := r.OptionsNamed("a"); len(got) != 1 || !got[0].HasValue() {
		t.Errorf("OptionsNamed(a) = %v", got)
	}
	if r.MultiLine() {
		t.Error("MultiLine() = true for a rule without a continuation")
	}
	var none cst.Rule
	if none.Options() != nil || none.Option("a") != nil {
		t.Error("a rule without a body has options")
	}
}

func TestOptionValue(t *testing.T) {
	// The option "k: ab \<nl>  cd\<nl>ef ;" with the value spread over three
	// physical lines; offsets are relative to the start of the keyword.
	b := []byte("k: ab \\\n  cd\\\nef ;")
	value := []token.Token{
		tok(token.Whitespace, 2, " "), tok(token.Value, 3, "ab "), tok(token.LineContinuation, 6, "\\\n"),
		tok(token.Whitespace, 8, "  "), tok(token.Value, 10, "cd"), tok(token.LineContinuation, 12, "\\\n"),
		tok(token.Value, 14, "ef"), tok(token.Whitespace, 16, " "),
	}
	o := &cst.Option{Keyword: tok(token.Keyword, 0, "k"), Colon: ptr(tok(token.Colon, 1, ":")),
		Value: value, Semicolon: tok(token.Semicolon, 17, ";")}
	kids := []cst.Node{o.Keyword, *o.Colon}
	for _, v := range value {
		kids = append(kids, v)
	}
	cst.Seal(o, b, 0, append(kids, o.Semicolon)...)
	if err := cst.Verify(o); err != nil {
		t.Fatal(err)
	}

	if o.Name() != "k" || !o.HasValue() {
		t.Errorf("Name() = %q, HasValue() = %v", o.Name(), o.HasValue())
	}
	if got := o.ValueSpan(); got != (source.Span{Start: 2, End: 17}) {
		t.Errorf("ValueSpan() = %v", got)
	}
	if got, want := o.RawValue(), " ab \\\n  cd\\\nef "; got != want {
		t.Errorf("RawValue() = %q, want %q", got, want)
	}
	logical, at := o.LogicalValue()
	if want := "ab   cdef"; logical != want {
		t.Errorf("LogicalValue() = %q, want %q", logical, want)
	}
	for i := range logical {
		if off := at(i); off < 0 || off >= len(b) || b[off] != logical[i] {
			t.Errorf("mapper(%d) = %d, source byte %q, want %q", i, off, b[off], logical[i])
		}
	}
	if at(len(logical)) != 17 || at(100) != 17 {
		t.Errorf("mapper past the end = %d, %d, want 17", at(len(logical)), at(100))
	}
	if at(-1) != at(0) {
		t.Errorf("mapper(-1) = %d, want %d", at(-1), at(0))
	}

	// Without a value the span is empty after the ':' or the keyword.
	bare := &cst.Option{Keyword: tok(token.Keyword, 0, "k"), Semicolon: tok(token.Semicolon, 1, ";")}
	cst.Seal(bare, []byte("k;"), 0, bare.Keyword, bare.Semicolon)
	if got := bare.ValueSpan(); got != (source.Span{Start: 1, End: 1}) || bare.RawValue() != "" {
		t.Errorf("bare ValueSpan() = %v, RawValue() = %q", got, bare.RawValue())
	}
	logical, at = bare.LogicalValue()
	if logical != "" || at(0) != 1 {
		t.Errorf("bare LogicalValue() = %q, mapper(0) = %d", logical, at(0))
	}
	empty := &cst.Option{Keyword: tok(token.Keyword, 0, "k"), Colon: ptr(tok(token.Colon, 1, ":")), Semicolon: tok(token.Semicolon, 2, ";")}
	cst.Seal(empty, []byte("k:;"), 0, empty.Keyword, *empty.Colon, empty.Semicolon)
	if got := empty.ValueSpan(); got != (source.Span{Start: 2, End: 2}) {
		t.Errorf("empty ValueSpan() = %v", got)
	}
}

func TestDump(t *testing.T) {
	f := buildFile(t)
	var buf bytes.Buffer
	if err := cst.Dump(&buf, f); err != nil {
		t.Fatal(err)
	}
	want := `(File 0:12
  (Rule 0:12
    (Header 0:1
      (Word 0:1 "x")
      (Missing 1:1 "")
      (Group 1:1
        (Missing 1:1 ""))
      (Group 1:1
        (Missing 1:1 ""))
      (Missing 1:1 "")
      (Group 1:1
        (Missing 1:1 ""))
      (Group 1:1
        (Missing 1:1 "")))
    (Whitespace 1:2 " ")
    (LParen 2:3 "(")
    (Body 3:10
      (Option 3:7
        (Keyword 3:4 "a")
        (Colon 4:5 ":")
        (Value 5:6 "1")
        (Semicolon 6:7 ";"))
      (Whitespace 7:8 " ")
      (Option 8:10
        (Keyword 8:9 "b")
        (Semicolon 9:10 ";")))
    (RParen 10:11 ")")
    (Newline 11:12 "\n"))
  (EOF 12:12 ""))
`
	if buf.String() != want {
		t.Errorf("Dump():\n%s\nwant:\n%s", buf.String(), want)
	}

	empty := &cst.Body{}
	cst.Seal(empty, nil, 5)
	buf.Reset()
	if err := cst.Dump(&buf, empty); err != nil || buf.String() != "(Body 5:5)\n" {
		t.Errorf("Dump(empty body) = %q, %v", buf.String(), err)
	}
}

func TestDumpKindNames(t *testing.T) {
	tests := []struct {
		kind token.Kind
		want string
	}{
		{token.EOF, "EOF"}, {token.Newline, "Newline"}, {token.Whitespace, "Whitespace"},
		{token.LineContinuation, "LineContinuation"}, {token.Comment, "Comment"}, {token.Word, "Word"},
		{token.Bang, "Bang"}, {token.LBracket, "LBracket"}, {token.RBracket, "RBracket"}, {token.Comma, "Comma"},
		{token.LParen, "LParen"}, {token.RParen, "RParen"}, {token.Keyword, "Keyword"}, {token.Colon, "Colon"},
		{token.Semicolon, "Semicolon"}, {token.Value, "Value"}, {token.Bad, "Bad"}, {token.Missing, "Missing"},
		{token.Kind(200), "Kind(200)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			var buf bytes.Buffer
			if err := cst.Dump(&buf, token.Token{Kind: tt.kind, Start: 1, End: 3, Lit: "\t\""}); err != nil {
				t.Fatal(err)
			}
			if want := "(" + tt.want + " 1:3 \"\\t\\\"\")\n"; buf.String() != want {
				t.Errorf("Dump() = %q, want %q", buf.String(), want)
			}
		})
	}
}

func TestDumpWriteError(t *testing.T) {
	if err := cst.Dump(failingWriter{}, buildFile(t)); err == nil {
		t.Error("Dump() to a failing writer returned nil")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

var errWrite = &writeError{}

type writeError struct{}

func (*writeError) Error() string { return "write failed" }

func TestVerify(t *testing.T) {
	b := []byte("ab")
	a, bb := tok(token.Word, 0, "a"), tok(token.Word, 1, "b")
	tests := []struct {
		name string
		node func() cst.Node
		want string // substring of the error; empty for a valid tree
	}{
		{"valid", func() cst.Node {
			bl := &cst.BlankLine{Tokens: []token.Token{a, bb}}
			cst.Seal(bl, b, 0, a, bb)
			return bl
		}, ""},
		{"gap between children", func() cst.Node {
			bl := &cst.BlankLine{Tokens: []token.Token{a, tok(token.Word, 2, "")}}
			cst.Seal(bl, b, 0, a, tok(token.Word, 2, ""))
			return bl
		}, "starts at 2, the previous one ends at 1"},
		{"foreign node type", func() cst.Node {
			bl := &cst.Bad{}
			cst.Seal(bl, b, 0)
			return &foreign{Node: bl}
		}, "*cst_test.foreign is not a node type of this package"},
		{"zero-width word", func() cst.Node {
			z := tok(token.Word, 1, "")
			bl := &cst.Bad{Tokens: []token.Token{a, z}}
			cst.Seal(bl, b, 0, a, z)
			return bl
		}, "Word token at 1:1 is zero-width"},
		{"token text differs from the source", func() cst.Node {
			x := token.Token{Kind: token.Word, Start: 1, End: 2, Lit: "x"}
			bl := &cst.Bad{Tokens: []token.Token{a, x}}
			cst.Seal(bl, b, 0, a, x)
			return bl
		}, `Word token at 1:2 has text "x", the source has "b"`},
		{"child sealed on another source", func() cst.Node {
			inner := &cst.Bad{Tokens: []token.Token{bb}}
			cst.Seal(inner, []byte("xb"), 0, bb)
			outer := &cst.Bad{Tokens: []token.Token{a}}
			cst.Seal(outer, b, 0, a, inner)
			return outer
		}, "Bad 1:2 reads its text from a different source than the root"},
		{"child sealed on an equal copy of the source", func() cst.Node {
			inner := &cst.Bad{Tokens: []token.Token{bb}}
			cst.Seal(inner, []byte("ab"), 0, bb)
			outer := &cst.Bad{Tokens: []token.Token{a}}
			cst.Seal(outer, b, 0, a, inner)
			return outer
		}, ""},
		{"missing token with width", func() cst.Node {
			m := token.Token{Kind: token.Missing, Start: 0, End: 1, Lit: "a"}
			bl := &cst.Bad{Tokens: []token.Token{m}}
			cst.Seal(bl, b, 0, m)
			return bl
		}, "Missing token at 0:1 is not zero-width"},
		{"part not among the children", func() cst.Node {
			bl := &cst.BlankLine{Tokens: []token.Token{a, bb}}
			cst.Seal(bl, b, 0, a)
			return bl
		}, "part Word 1:2 is not among the children"},
		{"parts out of order", func() cst.Node {
			c := &cst.Comment{Leading: []token.Token{bb}, Hash: a}
			cst.Seal(c, b, 0, a, bb)
			return c
		}, "part Word 0:1 is not among the children in order"},
		{"file text differs from Src", func() cst.Node {
			f := &cst.File{Src: []byte("zz"), EOF: tok(token.EOF, 2, "")}
			bl := &cst.BlankLine{Tokens: []token.Token{a, bb}}
			cst.Seal(bl, b, 0, a, bb)
			f.Items = []cst.Node{bl}
			cst.Seal(f, b, 0, bl, f.EOF)
			return f
		}, "text differs from Src"},
		{"file span misses a prefix", func() cst.Node {
			bt := tok(token.Word, 1, "b")
			f := &cst.File{Src: b, EOF: tok(token.EOF, 2, "")}
			bad := &cst.Bad{Tokens: []token.Token{bt}}
			cst.Seal(bad, b, 1, bt)
			f.Items = []cst.Node{bad}
			cst.Seal(f, b, 1, bad, f.EOF)
			return f
		}, "text differs from Src"},
		{"file span misses a suffix", func() cst.Node {
			at := tok(token.Word, 0, "a")
			f := &cst.File{Src: b, EOF: tok(token.EOF, 1, "")}
			bad := &cst.Bad{Tokens: []token.Token{at}}
			cst.Seal(bad, b, 0, at)
			f.Items = []cst.Node{bad}
			cst.Seal(f, b, 0, bad, f.EOF)
			return f
		}, "text differs from Src"},
		{"file with no children", func() cst.Node {
			f := &cst.File{Src: b}
			cst.Seal(f, b, 0)
			return f
		}, "text differs from Src"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cst.Verify(tt.node())
			if tt.want == "" {
				if err != nil {
					t.Errorf("Verify() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Verify() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

// foreign is a Node that is not one of the package's types.
type foreign struct{ cst.Node }

func (f *foreign) Span() source.Span { return source.Span{Start: 0, End: 2} }

// TestVerifyDeep checks that Verify is linear enough to handle a tree
// 100k levels deep, nested lists here, within a second (scaled under the
// race detector, which slows allocation-heavy code several times).
func TestVerifyDeep(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in short mode")
	}
	const depth = 100000
	src := make([]byte, 0, 2*depth+1)
	for range depth {
		src = append(src, '[')
	}
	src = append(src, 'x')
	for range depth {
		src = append(src, ']')
	}
	// Build from the inside out: a Group holding a Word, then depth
	// Groups each holding a List around the previous one.
	w := tok(token.Word, depth, "x")
	g := &cst.Group{Word: &w}
	cst.Seal(g, src, 0, w)
	for i := 1; i <= depth; i++ {
		l := &cst.List{LBracket: tok(token.LBracket, depth-i, "["), Items: []*cst.Group{g}, RBracket: tok(token.RBracket, depth+i, "]")}
		cst.Seal(l, src, 0, l.LBracket, g, l.RBracket)
		g = &cst.Group{List: l}
		cst.Seal(g, src, 0, l)
	}
	limit := time.Second
	if raceEnabled {
		limit *= 8
	}
	start := time.Now()
	if err := cst.Verify(g); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > limit {
		t.Errorf("Verify of a %d-deep tree took %v, want < %v", depth, elapsed, limit)
	}
	if g.Text() != string(src) {
		t.Error("outermost group text differs from the source")
	}
}

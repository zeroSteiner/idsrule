package parser

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/lexer"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

// checkFile asserts everything Parse promises for any input: a non-nil
// file whose text and tokens reproduce src, the structural invariants of
// the tree, a dump that succeeds, no more rules than action words, and
// well-formed, unresolved, ordered error diagnostics. It returns true when
// every check passed.
func checkFile(t testing.TB, src []byte, f *cst.File, diags []diag.Diagnostic) bool {
	t.Helper()
	ok := true
	fail := func(format string, args ...any) {
		t.Helper()
		ok = false
		t.Errorf(format, args...)
	}
	if f == nil {
		fail("Parse(%q) returned a nil file", src)
		return false
	}
	if got := f.Text(); got != string(src) {
		fail("file text %q differs from the input %q", got, src)
	}
	if err := cst.Verify(f); err != nil {
		fail("structural invariant: %v", err)
	}
	var text strings.Builder
	actions := 0
	for _, tk := range f.TokenStream() {
		text.WriteString(tk.Lit)
		if tk.Kind == token.Word && IsAction(tk.Lit) {
			actions++
		}
	}
	if text.String() != string(src) {
		fail("tokens concatenate to %q, want %q", text.String(), src)
	}
	if f.EOF.Kind != token.EOF || f.EOF.Start != len(src) || f.EOF.End != len(src) {
		fail("EOF = %v, want a zero-width EOF at %d", f.EOF, len(src))
	}
	if n := len(f.Rules()); n > actions {
		fail("%d rules but only %d action words", n, actions)
	}
	if err := cst.Dump(&bytes.Buffer{}, f); err != nil {
		fail("Dump: %v", err)
	}
	for i, d := range diags {
		if d.Span.Start < 0 || d.Span.End > len(src) || d.Span.Start > d.Span.End {
			fail("diagnostic %d %s has span %v outside [0, %d]", i, d.Rule, d.Span, len(src))
		}
		if d.Severity != diag.SeverityError {
			fail("diagnostic %d %s has severity %q", i, d.Rule, d.Severity)
		}
		if !strings.HasPrefix(d.Rule, "syntax-") || d.Message == "" {
			fail("diagnostic %d has rule %q and message %q", i, d.Rule, d.Message)
		}
		if d.File != "" || d.Line != 0 || d.Column != 0 || d.End.Line != 0 {
			fail("diagnostic %d %s has resolved positions: %+v", i, d.Rule, d)
		}
		if i > 0 && d.Span.Start < diags[i-1].Span.Start {
			fail("diagnostic %d %s at %d comes after %s at %d", i, d.Rule, d.Span.Start, diags[i-1].Rule, diags[i-1].Span.Start)
		}
	}
	return ok
}

// diagWant is an expected diagnostic: its rule and span.
type diagWant struct {
	rule       string
	start, end int
}

// good is the well-formed rule that follows every recovery input, to prove
// that recovery did not swallow it.
const good = "alert tcp any any -> any any (sid:2;)\n"

// recoveryRow is one error-recovery case: the input, the exact diagnostics
// it must produce, and checks on the shape of the tree.
type recoveryRow struct {
	name  string
	input string
	want  []diagWant
	check func(t *testing.T, f *cst.File)
}

var recoveryRows = []recoveryRow{
	{
		name:  "bad_header_action",
		input: "alerts tcp any any -> any any (sid:1;)\n" + good,
		want:  []diagWant{{RuleBadHeader, 0, 6}},
		check: func(t *testing.T, f *cst.File) {
			wantItems(t, f, "Bad", "Rule")
			if got := f.Items[0].Text(); got != "alerts tcp any any -> any any (sid:1;)\n" {
				t.Errorf("Bad item text = %q", got)
			}
		},
	},
	{
		name:  "missing_proto",
		input: "alert (sid:1;)\n" + good,
		want:  []diagWant{{RuleBadHeader, 5, 5}},
		check: func(t *testing.T, f *cst.File) {
			h := f.Rules()[0].Header
			wantMissing(t, "Proto", h.Proto, 5)
			wantMissingGroup(t, "DstPort", h.DstPort, 5)
			if f.Rules()[0].LParen.Kind != token.LParen {
				t.Errorf("LParen = %v", f.Rules()[0].LParen)
			}
		},
	},
	{
		name:  "missing_direction_parts",
		input: "alert tcp any any (sid:1;)\n" + good,
		want:  []diagWant{{RuleBadHeader, 17, 17}},
		check: func(t *testing.T, f *cst.File) {
			h := f.Rules()[0].Header
			if h.Proto.Lit != "tcp" || h.Src.Word == nil || h.SrcPort.Word == nil || h.SrcPort.Word.Start != 14 {
				t.Errorf("header parts before the gap = %+v", h)
			}
			wantMissing(t, "Dir", h.Dir, 17)
			wantMissingGroup(t, "Dst", h.Dst, 17)
			wantMissingGroup(t, "DstPort", h.DstPort, 17)
		},
	},
	{
		name:  "bad_direction",
		input: "alert tcp any any <- any any (sid:1;)\n" + good,
		want:  []diagWant{{RuleBadHeader, 18, 20}},
		check: func(t *testing.T, f *cst.File) {
			h := f.Rules()[0].Header
			if h.Dir.Lit != "<-" || h.Dst.Word == nil || h.DstPort.Word == nil || h.DstPort.Word.Start != 25 {
				t.Errorf("header = %+v", h)
			}
		},
	},
	{
		name:  "extra_header_token",
		input: "alert tcp any any -> any any any (sid:1;)\n" + good,
		want:  []diagWant{{RuleBadHeader, 29, 32}},
		check: func(t *testing.T, f *cst.File) {
			h := f.Rules()[0].Header
			if len(h.Extra) != 1 || h.Extra[0].Start != 29 || h.DstPort.Word == nil || h.DstPort.Word.Start != 25 {
				t.Errorf("header = %+v", h)
			}
			if got := h.Text(); got != "alert tcp any any -> any any any" {
				t.Errorf("header text = %q", got)
			}
		},
	},
	{
		name:  "unbalanced_bracket",
		input: "alert tcp [10.0.0.1,10.0.0.2 any -> any any (sid:1;)\n" + good,
		want:  []diagWant{{RuleUnbalancedBracket, 10, 11}},
		check: func(t *testing.T, f *cst.File) {
			h := f.Rules()[0].Header
			if h.Src.List != nil || h.Src.Word != nil || len(h.Src.Bad) != 4 || h.Src.Text() != "[10.0.0.1,10.0.0.2" {
				t.Errorf("Src = %+v", h.Src)
			}
			if h.SrcPort.Word == nil || h.SrcPort.Word.Lit != "any" || h.Dir.Lit != "->" || h.DstPort.Word == nil {
				t.Errorf("parts after the list = %+v", h)
			}
		},
	},
	{
		name:  "missing_open_paren",
		input: "alert tcp any any -> any any\n" + good,
		want:  []diagWant{{RuleMissingOpenParen, 28, 28}},
		check: func(t *testing.T, f *cst.File) {
			r := f.Rules()[0]
			wantMissing(t, "LParen", r.LParen, 28)
			wantMissing(t, "RParen", r.RParen, 28)
			if len(r.Body.Options) != 0 || !r.Body.Span().Empty() || len(r.Tail) != 1 || r.Tail[0].Kind != token.Newline {
				t.Errorf("rule = %+v", r)
			}
		},
	},
	{
		name:  "bad_option",
		input: "alert tcp any any -> any any (sid:1; @@; rev:1;)\n" + good,
		want:  []diagWant{{RuleBadOption, 37, 39}},
		check: func(t *testing.T, f *cst.File) {
			b := f.Rules()[0].Body
			if len(b.Bads) != 1 || b.Bads[0].Text() != "@@;" || len(b.Options) != 2 || b.Options[1].Name() != "rev" {
				t.Errorf("body = %+v", b)
			}
		},
	},
	{
		name:  "empty_option",
		input: "alert tcp any any -> any any (sid:1;; rev:1;)\n" + good,
		want:  []diagWant{{RuleEmptyOption, 36, 37}},
		check: func(t *testing.T, f *cst.File) {
			b := f.Rules()[0].Body
			if len(b.Bads) != 1 || b.Bads[0].Text() != ";" || len(b.Options) != 2 {
				t.Errorf("body = %+v", b)
			}
		},
	},
	{
		name:  "missing_value",
		input: "alert tcp any any -> any any (msg:; sid:1;)\n" + good,
		want:  []diagWant{{RuleMissingValue, 33, 34}},
		check: func(t *testing.T, f *cst.File) {
			o := f.Rules()[0].Option("msg")
			if o == nil || !o.HasValue() || len(o.Value) != 0 || o.Err || o.Semicolon.Kind != token.Semicolon {
				t.Errorf("msg = %+v", o)
			}
		},
	},
	{
		name:  "missing_semicolon_before_rparen",
		input: "alert tcp any any -> any any (sid:1; rev:1)\n" + good,
		want:  []diagWant{{RuleMissingSemicolon, 42, 42}},
		check: func(t *testing.T, f *cst.File) {
			r := f.Rules()[0]
			o := r.Option("rev")
			if o == nil || !o.Err || o.RawValue() != "1" {
				t.Errorf("rev = %+v", o)
			}
			wantMissing(t, "Semicolon", o.Semicolon, 42)
			if r.RParen.Kind != token.RParen {
				t.Errorf("RParen = %v", r.RParen)
			}
		},
	},
	{
		name:  "missing_semicolon_at_newline",
		input: "alert tcp any any -> any any (sid:1; rev:1\n" + good,
		want:  []diagWant{{RuleMissingSemicolon, 42, 42}},
		check: func(t *testing.T, f *cst.File) {
			r := f.Rules()[0]
			wantMissing(t, "Semicolon", r.Option("rev").Semicolon, 42)
			wantMissing(t, "RParen", r.RParen, 42)
			if len(r.Tail) != 1 || r.Tail[0].Kind != token.Newline {
				t.Errorf("Tail = %v", r.Tail)
			}
		},
	},
	{
		name:  "missing_close_paren",
		input: "alert tcp any any -> any any (sid:1;\n" + good,
		want:  []diagWant{{RuleMissingCloseParen, 36, 36}},
		check: func(t *testing.T, f *cst.File) {
			r := f.Rules()[0]
			wantMissing(t, "RParen", r.RParen, 36)
			if o := r.Option("sid"); o == nil || o.Err {
				t.Errorf("sid = %+v", o)
			}
			if r.Text() != "alert tcp any any -> any any (sid:1;\n" {
				t.Errorf("rule text = %q", r.Text())
			}
		},
	},
	{
		name:  "unterminated_string",
		input: "alert tcp any any -> any any (msg:\"abc\n" + good,
		want:  []diagWant{{lexer.RuleUnterminatedString, 34, 38}},
		check: func(t *testing.T, f *cst.File) {
			r := f.Rules()[0]
			o := r.Option("msg")
			if o == nil || !o.Err || o.RawValue() != "\"abc" {
				t.Errorf("msg = %+v", o)
			}
			wantMissing(t, "Semicolon", o.Semicolon, 38)
			wantMissing(t, "RParen", r.RParen, 38)
		},
	},
	{
		name:  "trailing_text",
		input: "alert tcp any any -> any any (sid:1;) junk\n" + good,
		want:  []diagWant{{RuleTrailingText, 38, 42}},
		check: func(t *testing.T, f *cst.File) {
			wantItems(t, f, "Rule", "Bad", "Rule")
			if r := f.Rules()[0]; len(r.Tail) != 0 || r.Text() != "alert tcp any any -> any any (sid:1;)" {
				t.Errorf("rule = %q, tail %v", r.Text(), r.Tail)
			}
			if got := f.Items[1].Text(); got != " junk\n" {
				t.Errorf("Bad text = %q", got)
			}
		},
	},
	{
		name:  "concatenated_rules",
		input: "alert tcp any any -> any any (sid:1;)" + good,
		check: func(t *testing.T, f *cst.File) {
			wantItems(t, f, "Rule", "Rule")
			if r := f.Rules()[0]; len(r.Tail) != 0 || r.Text() != "alert tcp any any -> any any (sid:1;)" {
				t.Errorf("rule = %q, tail %v", r.Text(), r.Tail)
			}
		},
	},
	{
		name:  "bad_line_then_rule",
		input: "this is not a rule\n" + good,
		want:  []diagWant{{RuleBadHeader, 0, 4}},
		check: func(t *testing.T, f *cst.File) {
			wantItems(t, f, "Bad", "Rule")
			if got := f.Items[0].Text(); got != "this is not a rule\n" {
				t.Errorf("Bad text = %q", got)
			}
		},
	},
}

func wantMissing(t *testing.T, name string, tok token.Token, at int) {
	t.Helper()
	if tok.Kind != token.Missing || tok.Start != at || tok.End != at {
		t.Errorf("%s = %v, want Missing at %d", name, tok, at)
	}
}

func wantMissingGroup(t *testing.T, name string, g *cst.Group, at int) {
	t.Helper()
	if g == nil || g.Word == nil || g.List != nil || g.Bad != nil {
		t.Errorf("%s = %+v, want a group with a Missing word", name, g)
		return
	}
	wantMissing(t, name+".Word", *g.Word, at)
}

// wantItems asserts the type names of the file's items.
func wantItems(t *testing.T, f *cst.File, want ...string) {
	t.Helper()
	var got []string
	for _, it := range f.Items {
		got = append(got, strings.TrimPrefix(strings.SplitN(dumpOf(it), " ", 2)[0], "("))
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("items = %v, want %v", got, want)
	}
}

func dumpOf(n cst.Node) string {
	var buf bytes.Buffer
	_ = cst.Dump(&buf, n)
	return buf.String()
}

func TestRecovery(t *testing.T) {
	for _, row := range recoveryRows {
		t.Run(row.name, func(t *testing.T) {
			src := []byte(row.input)
			f, diags := Parse(src)
			checkFile(t, src, f, diags)

			var got []diagWant
			for _, d := range diags {
				got = append(got, diagWant{d.Rule, d.Span.Start, d.Span.End})
			}
			if len(got) != len(row.want) || (len(got) > 0 && !equalDiags(got, row.want)) {
				t.Errorf("diagnostics = %v, want %v", got, row.want)
				for _, d := range diags {
					t.Logf("  %s %d:%d %s", d.Rule, d.Span.Start, d.Span.End, d.Message)
				}
			}

			// The well-formed rule after the broken one is intact.
			rules := f.Rules()
			if len(rules) == 0 {
				t.Fatal("no rules parsed")
			}
			last := rules[len(rules)-1]
			if last.Text() != good {
				t.Errorf("last rule text = %q, want %q", last.Text(), good)
			}
			if o := last.Option("sid"); o == nil || o.RawValue() != "2" || o.Err {
				t.Errorf("last rule sid = %+v", o)
			}
			for _, d := range diags {
				if d.Span.Start >= last.Span().Start {
					t.Errorf("diagnostic %s at %d lies in the following rule", d.Rule, d.Span.Start)
				}
			}
			if row.check != nil {
				row.check(t, f)
			}

			// The golden fixture of the same name holds the same input.
			fixture, err := os.ReadFile("testdata/recover_" + row.name + ".rule")
			if err != nil {
				t.Fatal(err)
			}
			if string(fixture) != row.input {
				t.Errorf("testdata/recover_%s.rule differs from the test input", row.name)
			}
		})
	}
}

func equalDiags(a, b []diagWant) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// tk is a token to hand-build a stream from: its kind and text. Offsets
// follow from the texts.
type tk struct {
	kind token.Kind
	lit  string
}

// stream builds a token stream and the source it tiles from tks.
func stream(tks []tk) ([]byte, []token.Token) {
	var src []byte
	var toks []token.Token
	for _, w := range tks {
		toks = append(toks, token.Token{Kind: w.kind, Start: len(src), End: len(src) + len(w.lit), Lit: w.lit})
		src = append(src, w.lit...)
	}
	return src, toks
}

// TestNoSpin feeds the parser token sequences the lexer never produces and
// checks that it terminates, keeps every token and reports something.
func TestNoSpin(t *testing.T) {
	tests := []struct {
		name string
		toks []tk
	}{
		{"empty stream", nil},
		{"colon at file start", []tk{{token.Colon, ":"}}},
		{"keyword at file start", []tk{{token.Keyword, "sid"}, {token.Colon, ":"}, {token.Value, "1"}, {token.Semicolon, ";"}}},
		{"value then newline", []tk{{token.Value, "x"}, {token.Newline, "\n"}, {token.Value, "y"}}},
		{"missing token at file start", []tk{{token.Missing, ""}, {token.Word, "alert"}}},
		{"continuation at file start", []tk{{token.LineContinuation, "\\\n"}, {token.Word, "alert"}, {token.Newline, "\n"}}},
		{"group punctuation at file start", []tk{{token.RBracket, "]"}, {token.Comma, ","}, {token.Bang, "!"}, {token.LBracket, "["}}},
		{"two whitespace tokens", []tk{{token.Whitespace, " "}, {token.Whitespace, "\t"}, {token.Word, "alert"}}},
		{"lone bad in body position", []tk{{token.Word, "alert"}, {token.LParen, "("}, {token.Bad, "@"}}},
		{"body kinds in the header", []tk{
			{token.Word, "alert"}, {token.Whitespace, " "}, {token.Keyword, "sid"}, {token.Whitespace, " "},
			{token.Colon, ":"}, {token.Value, "1"}, {token.Semicolon, ";"}, {token.Whitespace, " "},
			{token.Bad, "@"}, {token.LParen, "("}, {token.RParen, ")"}, {token.Newline, "\n"},
		}},
		{"header kinds in the body", []tk{
			{token.Word, "alert"}, {token.LParen, "("}, {token.Colon, ":"}, {token.Value, "v"}, {token.Keyword, "k"},
			{token.Colon, ":"}, {token.Colon, ":"}, {token.Word, "x"}, {token.Comma, ","}, {token.LBracket, "["},
			{token.Missing, ""}, {token.Comment, "#"}, {token.LParen, "("}, {token.Keyword, "k"}, {token.Whitespace, " "},
			{token.Keyword, "j"}, {token.Colon, ":"}, {token.Keyword, "b"}, {token.Semicolon, ";"}, {token.RParen, ")"},
		}},
		{"junk after rparen to eof", []tk{
			{token.Word, "alert"}, {token.LParen, "("}, {token.RParen, ")"}, {token.Colon, ":"}, {token.Keyword, "k"},
			{token.LineContinuation, "\\\n"}, {token.Whitespace, " "},
		}},
		{"eof in the middle", []tk{{token.Word, "alert"}, {token.EOF, ""}, {token.Word, "alert"}}},
		{"nested lists with junk", []tk{
			{token.Word, "alert"}, {token.Whitespace, " "}, {token.Word, "tcp"}, {token.Whitespace, " "},
			{token.LBracket, "["}, {token.LBracket, "["}, {token.Comma, ","}, {token.RParen, ")"}, {token.Whitespace, " "},
			{token.Bang, "!"}, {token.Whitespace, " "}, {token.Bang, "!"}, {token.Bang, "!"}, {token.Whitespace, " "},
			{token.LBracket, "["}, {token.Word, "a"}, {token.Whitespace, " "}, {token.RBracket, "]"}, {token.RBracket, "]"},
			{token.Whitespace, " "}, {token.LBracket, "["}, {token.Whitespace, " "}, {token.LParen, "("},
		}},
		{"list items of every kind", []tk{
			{token.Word, "alert"}, {token.Whitespace, " "}, {token.LBracket, "["}, {token.Keyword, "k"}, {token.Comma, ","},
			{token.Value, "v"}, {token.Comma, ","}, {token.Missing, ""}, {token.RBracket, "]"}, {token.Whitespace, " "},
			{token.LBracket, "["}, {token.Word, "a"}, {token.Comma, ","}, {token.RBracket, "]"}, {token.Whitespace, " "},
			{token.LBracket, "["}, {token.Comma, ","}, {token.RBracket, "]"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, toks := stream(tt.toks)
			done := make(chan struct{})
			var f *cst.File
			var diags []diag.Diagnostic
			go func() {
				defer close(done)
				f, diags = parseTokens(src, toks, nil)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("parser did not terminate")
			}
			if f == nil {
				t.Fatal("nil file")
			}
			if tt.name == "eof in the middle" {
				return // the stream does not tile src past its first EOF
			}
			checkFile(t, src, f, diags)
			if len(tt.toks) > 0 && len(diags) == 0 {
				t.Error("no diagnostics for a stream the lexer could not have produced")
			}
		})
	}
}

// TestHeaderShapes pins the diagnostics for header shapes beyond the
// recovery rows: at most one syntax-bad-header per header, and the exact
// token each list shape is reported at. X marks where the shape goes.
func TestHeaderShapes(t *testing.T) {
	const tmpl = "alert tcp X any -> any any (sid:1;)\n"
	tests := []struct {
		name  string
		input string
		want  []diagWant
		check func(t *testing.T, h *cst.Header)
	}{
		{
			name:  "seven words, bad direction, no extra report",
			input: "alert tcp any any any any any (sid:1;)\n",
			want:  []diagWant{{RuleBadHeader, 18, 21}},
			check: func(t *testing.T, h *cst.Header) {
				if h.Dir.Lit != "any" || len(h.Extra) != 0 || h.DstPort.Word == nil || h.DstPort.Word.Start != 26 {
					t.Errorf("header = %+v", h)
				}
			},
		},
		{
			name:  "unclosed list then bad direction and extra",
			input: "alert tcp [10.0.0.1 any any -> any any (sid:1;)\n",
			want:  []diagWant{{RuleUnbalancedBracket, 10, 11}, {RuleBadHeader, 24, 27}},
			check: func(t *testing.T, h *cst.Header) {
				if h.Src.List != nil || len(h.Src.Bad) != 2 || h.Dir.Lit != "any" || len(h.Extra) != 1 || h.Extra[0].Start != 35 {
					t.Errorf("header = %+v", h)
				}
			},
		},
		{
			name:  "trailing comma",
			input: strings.Replace(tmpl, "X", "[80,]", 1),
			want:  []diagWant{{RuleBadHeader, 14, 15}},
			check: func(t *testing.T, h *cst.Header) { wantBadGroup(t, h.Src, "[80,]") },
		},
		{
			name:  "leading comma",
			input: strings.Replace(tmpl, "X", "[,80]", 1),
			want:  []diagWant{{RuleBadHeader, 11, 12}},
			check: func(t *testing.T, h *cst.Header) { wantBadGroup(t, h.Src, "[,80]") },
		},
		{
			name:  "double comma",
			input: strings.Replace(tmpl, "X", "[80,,90]", 1),
			want:  []diagWant{{RuleBadHeader, 14, 15}},
			check: func(t *testing.T, h *cst.Header) { wantBadGroup(t, h.Src, "[80,,90]") },
		},
		{
			name:  "empty list",
			input: strings.Replace(tmpl, "X", "[]", 1),
			check: func(t *testing.T, h *cst.Header) {
				if h.Src.List == nil || len(h.Src.List.Items) != 0 || len(h.Src.List.Commas) != 0 || h.Src.Text() != "[]" {
					t.Errorf("Src = %+v", h.Src)
				}
			},
		},
		{
			name:  "items without a comma",
			input: strings.Replace(tmpl, "X", "[80 90]", 1),
			want:  []diagWant{{RuleUnbalancedBracket, 10, 11}, {RuleBadHeader, 16, 17}},
			check: func(t *testing.T, h *cst.Header) {
				wantBadGroup(t, h.Src, "[80")
				wantBadGroup(t, h.SrcPort, "90]")
				if h.Dir.Lit != "any" || h.Dst.Word == nil || h.Dst.Word.Lit != "->" || len(h.Extra) != 1 {
					t.Errorf("parts after the list = %+v", h)
				}
			},
		},
		{
			name:  "word glued to a list is one part",
			input: strings.Replace(tmpl, "X", "[80]90", 1),
			want:  []diagWant{{RuleBadHeader, 14, 16}},
			check: func(t *testing.T, h *cst.Header) {
				wantBadGroup(t, h.Src, "[80]90")
				if h.SrcPort.Word == nil || h.SrcPort.Word.Lit != "any" || h.Dir.Lit != "->" || len(h.Extra) != 0 {
					t.Errorf("parts after the list = %+v", h)
				}
			},
		},
		{
			name:  "whitespace next to brackets and commas",
			input: strings.Replace(tmpl, "X", "[ 80 , [ 90,91 ] ,92 ]", 1),
			check: func(t *testing.T, h *cst.Header) {
				if h.Src.List == nil || len(h.Src.List.Items) != 3 || len(h.Src.List.Commas) != 2 || h.Src.List.Items[1].List == nil {
					t.Errorf("Src = %+v", h.Src)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := []byte(tt.input)
			f, diags := Parse(src)
			checkFile(t, src, f, diags)
			var got []diagWant
			for _, d := range diags {
				got = append(got, diagWant{d.Rule, d.Span.Start, d.Span.End})
			}
			if len(got) != len(tt.want) || (len(got) > 0 && !equalDiags(got, tt.want)) {
				t.Errorf("diagnostics = %v, want %v", got, tt.want)
				for _, d := range diags {
					t.Logf("  %s %d:%d %s", d.Rule, d.Span.Start, d.Span.End, d.Message)
				}
			}
			if rules := f.Rules(); len(rules) != 1 {
				t.Fatalf("%d rules, want 1", len(rules))
			} else if tt.check != nil {
				tt.check(t, rules[0].Header)
			}
		})
	}
}

func wantBadGroup(t *testing.T, g *cst.Group, text string) {
	t.Helper()
	if g == nil || g.Word != nil || g.List != nil || len(g.Bad) == 0 || g.Text() != text {
		t.Errorf("group = %+v, want Bad tokens with text %q", g, text)
	}
}

// TestBodyAndTailShapes pins body and tail behaviour beyond the recovery
// rows: the missing ')' is suppressed only by the last option's Err, and
// trailing blanks at the end of the file are the rule's tail.
func TestBodyAndTailShapes(t *testing.T) {
	t.Run("bad run then newline reports both", func(t *testing.T) {
		src := []byte("alert tcp any any -> any any (sid:1; @@\n" + good)
		f, diags := Parse(src)
		checkFile(t, src, f, diags)
		want := []diagWant{{RuleBadOption, 37, 39}, {RuleMissingCloseParen, 39, 39}}
		var got []diagWant
		for _, d := range diags {
			got = append(got, diagWant{d.Rule, d.Span.Start, d.Span.End})
		}
		if len(got) != len(want) || !equalDiags(got, want) {
			t.Errorf("diagnostics = %v, want %v", got, want)
		}
		if r := f.Rules()[0]; len(r.Body.Bads) != 1 || r.Body.Bads[0].Text() != "@@" || r.RParen.Kind != token.Missing {
			t.Errorf("rule = %+v", r)
		}
	})
	t.Run("trailing blanks at eof are the tail", func(t *testing.T) {
		src := []byte("alert tcp any any -> any any (sid:1;)  ")
		f, diags := Parse(src)
		checkFile(t, src, f, diags)
		if len(diags) != 0 {
			t.Errorf("diagnostics = %v", diags)
		}
		r := f.Rules()[0]
		if len(r.Tail) != 1 || r.Tail[0].Kind != token.Whitespace || r.Tail[0].Lit != "  " || r.Text() != string(src) {
			t.Errorf("Tail = %v, rule text %q", r.Tail, r.Text())
		}
		if len(f.Items) != 1 {
			t.Errorf("items = %v, want the rule alone", f.Items)
		}
	})
}

// TestContinuationOutsideRule checks that a line continuation is trivia
// outside a rule as it is inside one: before a rule, after a rule's ')',
// on a blank line and before a comment.
func TestContinuationOutsideRule(t *testing.T) {
	rule := func(sid string) string { return "alert tcp any any -> any any (sid:" + sid + ";)" }
	tests := []struct {
		name  string
		input string
		rules int
		check func(t *testing.T, f *cst.File)
	}{
		{
			name:  "before a rule",
			input: "\\\n" + rule("2") + "\n",
			rules: 1,
			check: func(t *testing.T, f *cst.File) {
				r := f.Rules()[0]
				if r.Span().Start != 0 || cst.Children(r)[0].(token.Token).Kind != token.LineContinuation {
					t.Errorf("rule span %v, first child %v", r.Span(), cst.Children(r)[0])
				}
				wantItems(t, f, "Rule")
			},
		},
		{
			name:  "after a rule, then newline",
			input: rule("1") + " \\\n\n",
			rules: 1,
			check: func(t *testing.T, f *cst.File) {
				wantTail(t, f.Rules()[0], token.Whitespace, token.LineContinuation, token.Newline)
				wantItems(t, f, "Rule")
			},
		},
		{
			name:  "after a rule, then the next rule",
			input: rule("1") + " \\\n" + rule("2") + "\n",
			rules: 2,
			check: func(t *testing.T, f *cst.File) {
				wantTail(t, f.Rules()[0], token.Whitespace, token.LineContinuation)
				wantTail(t, f.Rules()[1], token.Newline)
				wantItems(t, f, "Rule", "Rule")
			},
		},
		{
			name:  "after a rule, then eof",
			input: rule("1") + "\\\n",
			rules: 1,
			check: func(t *testing.T, f *cst.File) {
				wantTail(t, f.Rules()[0], token.LineContinuation)
				wantItems(t, f, "Rule")
			},
		},
		{
			name:  "on a blank line",
			input: "  \\\n  \n" + rule("1") + "\n\\\n",
			rules: 1,
			check: func(t *testing.T, f *cst.File) {
				wantItems(t, f, "BlankLine", "Rule", "BlankLine")
				if bl := f.Items[0].(*cst.BlankLine); len(bl.Tokens) != 4 || bl.Tokens[1].Kind != token.LineContinuation {
					t.Errorf("first blank line = %v", bl.Tokens)
				}
				if bl := f.Items[2].(*cst.BlankLine); len(bl.Tokens) != 1 || bl.Tokens[0].Kind != token.LineContinuation {
					t.Errorf("last blank line = %v", bl.Tokens)
				}
			},
		},
		{
			name:  "before a comment",
			input: "\\\n  # c\n" + rule("1") + "\n",
			rules: 1,
			check: func(t *testing.T, f *cst.File) {
				wantItems(t, f, "Comment", "Rule")
				c := f.Items[0].(*cst.Comment)
				if len(c.Leading) != 2 || c.Leading[0].Kind != token.LineContinuation || c.Hash.Lit != "# c" || c.Newline == nil {
					t.Errorf("comment = %+v", c)
				}
			},
		},
		{
			name:  "after a rule, then junk, is still trailing text",
			input: rule("1") + " \\\n junk\n" + rule("2") + "\n",
			rules: 2,
			check: func(t *testing.T, f *cst.File) {
				wantItems(t, f, "Rule", "Bad", "Rule")
				if got := f.Items[1].Text(); got != " \\\n junk\n" {
					t.Errorf("Bad text = %q", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := []byte(tt.input)
			f, diags := Parse(src)
			checkFile(t, src, f, diags)
			wantDiags := 0
			if strings.Contains(tt.name, "junk") {
				wantDiags = 1
			}
			if len(diags) != wantDiags {
				t.Errorf("diagnostics = %v, want %d", diags, wantDiags)
			}
			if got := len(f.Rules()); got != tt.rules {
				t.Fatalf("%d rules, want %d", got, tt.rules)
			}
			tt.check(t, f)
		})
	}
}

func wantTail(t *testing.T, r *cst.Rule, kinds ...token.Kind) {
	t.Helper()
	var got []token.Kind
	for _, tk := range r.Tail {
		got = append(got, tk.Kind)
	}
	if len(got) != len(kinds) || !equalKinds(got, kinds) {
		t.Errorf("Tail kinds = %v, want %v", got, kinds)
	}
}

func equalKinds(a, b []token.Kind) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// raceSlowdown is the factor time budgets are scaled by under the race
// detector.
const raceSlowdown = 8

// budget returns the time budget for a scale test: d, or d scaled by
// raceSlowdown under the race detector.
func budget(d time.Duration) time.Duration {
	if raceEnabled {
		return d * raceSlowdown
	}
	return d
}

// timeParse parses src a few times, as a benchmark would, and returns the
// shortest run with its result; two runs under the race detector.
func timeParse(src []byte) (time.Duration, *cst.File, []diag.Diagnostic) {
	runs := 3
	if raceEnabled {
		runs = 2
	}
	var best time.Duration
	var f *cst.File
	var diags []diag.Diagnostic
	for i := range runs {
		start := time.Now()
		f, diags = Parse(src)
		if elapsed := time.Since(start); i == 0 || elapsed < best {
			best = elapsed
		}
	}
	return best, f, diags
}

// TestScaleUnterminated checks that an unterminated string in every rule
// does not make the parse quadratic: 100k such rules parse within ten
// seconds (a loose cap; the ratio is the real guard) and in no more than
// 40 times what 10k take (a linear parse takes
// about 10 times as long, the quadratic one took over 100 times), with one
// lexer diagnostic each and no missing-semicolon. The scale tests are
// skipped in short mode.
func TestScaleUnterminated(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in short mode")
	}
	const small, n = 10000, 100000
	const rule = "alert tcp any any -> any any (msg:\"a\n"
	tSmall, _, _ := timeParse([]byte(strings.Repeat(rule, small)))
	src := []byte(strings.Repeat(rule, n))
	elapsed, f, diags := timeParse(src)
	t.Logf("%d rules: %v; %d rules: %v", small, tSmall, n, elapsed)
	if limit := budget(10 * time.Second); elapsed > limit {
		t.Errorf("parsing %d rules took %v, want < %v", n, elapsed, limit)
	}
	if elapsed > 40*tSmall {
		t.Errorf("parsing %d rules took %v, %d rules %v: more than 40 times, not linear", n, elapsed, small, tSmall)
	}
	if got := len(f.Rules()); got != n {
		t.Errorf("%d rules, want %d", got, n)
	}
	if len(diags) != n {
		t.Errorf("%d diagnostics, want %d", len(diags), n)
	}
	for _, d := range diags {
		if d.Rule != lexer.RuleUnterminatedString {
			t.Fatalf("diagnostic %s at %d, want only %s", d.Rule, d.Span.Start, lexer.RuleUnterminatedString)
		}
	}
	if f.Text() != string(src) {
		t.Error("text differs from the input")
	}
}

// TestScaleBracketTrivia checks that trivia inside brackets does not make
// the header parse quadratic: a 100k-token run of continuations and
// blanks inside a list parses within two seconds, as List children, with
// no diagnostic.
func TestScaleBracketTrivia(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in short mode")
	}
	const n = 50000 // pairs of LineContinuation + Whitespace: 100k tokens
	run := strings.Repeat("\\\n ", n)
	tests := []struct {
		name  string
		input string
		items int
	}{
		{"before the closing bracket", "alert tcp [80,90" + run + "] any -> any any (sid:1;)\n", 2},
		{"after a comma", "alert tcp [80," + run + "90] any -> any any (sid:1;)\n", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := []byte(tt.input)
			start := time.Now()
			f, diags := Parse(src)
			elapsed := time.Since(start)
			if limit := budget(2 * time.Second); elapsed > limit {
				t.Errorf("parsing took %v, want < %v", elapsed, limit)
			}
			if len(diags) != 0 {
				t.Errorf("diagnostics = %d, want 0", len(diags))
			}
			if got := len(f.Rules()); got != 1 {
				t.Fatalf("%d rules, want 1", got)
			}
			l := f.Rules()[0].Header.Src.List
			if l == nil || len(l.Items) != tt.items || len(l.Commas) != 1 {
				t.Fatalf("Src = %+v, want a list of %d items", f.Rules()[0].Header.Src, tt.items)
			}
			trivia := 0
			for _, k := range cst.Children(l) {
				if tk, ok := k.(token.Token); ok && isTrivia(tk) {
					trivia++
				}
			}
			if trivia != 2*n {
				t.Errorf("%d trivia children in the list, want %d", trivia, 2*n)
			}
			if err := cst.Verify(f); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestParseEmpty(t *testing.T) {
	f, diags := Parse(nil)
	checkFile(t, nil, f, diags)
	if len(f.Items) != 0 || len(diags) != 0 || f.Src != nil || f.Text() != "" {
		t.Errorf("Parse(nil) = %+v, %v", f, diags)
	}
}

func TestIsAction(t *testing.T) {
	for _, w := range []string{"alert", "log", "pass", "drop", "reject", "sdrop", "activate", "dynamic", "rejectsrc", "rejectdst", "rejectboth", "config", "accept", "drop:flow", "accept:hook", "alert:"} {
		if !IsAction(w) {
			t.Errorf("IsAction(%q) = false", w)
		}
	}
	for _, w := range []string{"", "Alert", "alerts", "tcp", "->", "#", ":flow", "tcp:all"} {
		if IsAction(w) {
			t.Errorf("IsAction(%q) = true", w)
		}
	}
}

func TestDiagnosticShape(t *testing.T) {
	src := []byte("alert tcp any any -> any any (sid:1; @@; rev)\nalerts\n")
	f, diags := Parse(src)
	checkFile(t, src, f, diags)
	want := []string{
		`syntax-bad-option 37:39 unexpected "@@" in rule body`,
		`syntax-missing-semicolon 44:44 missing ';' after option "rev"`,
		`syntax-bad-header 46:52 expected a rule action, got "alerts"`,
	}
	var got []string
	for _, d := range diags {
		got = append(got, fmt.Sprintf("%s %d:%d %s", d.Rule, d.Span.Start, d.Span.End, d.Message))
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("diagnostics:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestOption(t *testing.T) {
	src := []byte("alert tcp any any -> any any (content:\"abc \\\n    def\\\n  ghi\"; nocase; metadata: deployment Datacenter, deployment SSLDecrypt ; sid:1;)\n")
	f, diags := Parse(src)
	checkFile(t, src, f, diags)
	if len(diags) != 0 {
		t.Fatalf("diagnostics: %v", diags)
	}
	r := f.Rules()[0]
	if !r.MultiLine() {
		t.Error("MultiLine() = false for a continued rule")
	}

	content := r.Option("content")
	if content == nil || content.Name() != "content" || !content.HasValue() {
		t.Fatalf("content = %+v", content)
	}
	raw := "\"abc \\\n    def\\\n  ghi\""
	start := bytes.Index(src, []byte(raw))
	if got := content.ValueSpan(); got.Start != start || got.End != start+len(raw) {
		t.Errorf("content ValueSpan() = %v, want %d:%d", got, start, start+len(raw))
	}
	if got := content.RawValue(); got != raw {
		t.Errorf("content RawValue() = %q, want %q", got, raw)
	}
	logical, at := content.LogicalValue()
	if want := "\"abc     def  ghi\""; logical != want {
		t.Errorf("content LogicalValue() = %q, want %q", logical, want)
	}
	// Map the 'g' of the third physical line back to the source.
	g := strings.Index(logical, "ghi")
	if off := at(g); src[off] != 'g' || off != bytes.Index(src, []byte("ghi")) {
		t.Errorf("mapper(%d) = %d, source byte %q", g, off, src[off])
	}
	for i := range logical {
		if off := at(i); src[off] != logical[i] {
			t.Errorf("mapper(%d) = %d: source byte %q, logical byte %q", i, off, src[off], logical[i])
		}
	}
	if at(len(logical)) != content.ValueSpan().End {
		t.Errorf("mapper(len) = %d, want %d", at(len(logical)), content.ValueSpan().End)
	}

	nocase := r.Option("nocase")
	if nocase == nil || nocase.HasValue() || nocase.RawValue() != "" {
		t.Fatalf("nocase = %+v", nocase)
	}
	if got := nocase.ValueSpan(); got != (source.Span{Start: nocase.Keyword.End, End: nocase.Keyword.End}) {
		t.Errorf("nocase ValueSpan() = %v, want empty at %d", got, nocase.Keyword.End)
	}

	metadata := r.Option("metadata")
	if metadata == nil || len(metadata.Value) != 3 || metadata.Value[0].Kind != token.Whitespace || metadata.Value[2].Kind != token.Whitespace {
		t.Fatalf("metadata = %+v", metadata)
	}
	if got := metadata.RawValue(); got != " deployment Datacenter, deployment SSLDecrypt " {
		t.Errorf("metadata RawValue() = %q", got)
	}
	logical, at = metadata.LogicalValue()
	if logical != "deployment Datacenter, deployment SSLDecrypt" || src[at(0)] != 'd' || at(0) != metadata.Value[1].Start {
		t.Errorf("metadata LogicalValue() = %q, mapper(0) = %d", logical, at(0))
	}
	if got := r.OptionsNamed("sid"); len(got) != 1 || got[0].RawValue() != "1" {
		t.Errorf("OptionsNamed(sid) = %v", got)
	}
}

// parentIn returns the type name of the node that owns the first line of
// dump that starts with prefix: the nearest line above it with one level
// less indentation.
func parentIn(t *testing.T, dump, prefix string) string {
	t.Helper()
	lines := strings.Split(dump, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimLeft(line, " "), prefix) {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		for j := i - 1; j >= 0; j-- {
			if len(lines[j])-len(strings.TrimLeft(lines[j], " ")) < indent {
				return strings.TrimPrefix(strings.SplitN(strings.TrimSpace(lines[j]), " ", 2)[0], "(")
			}
		}
		t.Fatalf("%q has no parent in the dump", prefix)
	}
	t.Fatalf("%q not found in dump:\n%s", prefix, dump)
	return ""
}

func TestTriviaOwnership(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		prefix string // of the line to find, e.g. "(Whitespace 33:"
		parent string
	}{
		{"continued blank line in body", "alert tcp any any -> any any ( \\\n    \\\n    sid:1; \\\n)\n", "(Whitespace 33:37", "Body"},
		{"continuation of blank line in body", "alert tcp any any -> any any ( \\\n    \\\n    sid:1; \\\n)\n", "(LineContinuation 37:39", "Body"},
		{"whitespace before lparen", "alert tcp any any -> any any (sid:1;)\n", "(Whitespace 28:29", "Rule"},
		{"whitespace after lparen", "alert tcp any any -> any any (  \\\n  sid:1;)\n", "(Whitespace 30:32", "Body"},
		{"continuation after lparen", "alert tcp any any -> any any (  \\\n  sid:1;)\n", "(LineContinuation 32:34", "Body"},
		{"comment between rules", "alert tcp any any -> any any (sid:1;)\n# c\nalert tcp any any -> any any (sid:2;)\n", "(Comment 38:42", "File"},
		{"comment token", "alert tcp any any -> any any (sid:1;)\n# c\n", "(Comment 38:41 ", "Comment"},
		{"whitespace between header parts", "alert tcp any any -> any any (sid:1;)\n", "(Whitespace 9:10", "Header"},
		{"whitespace between options", "alert tcp any any -> any any (sid:1; rev:1;)\n", "(Whitespace 36:37", "Body"},
		{"whitespace inside a list", "alert tcp [80, 90] any -> any any (sid:1;)\n", "(Whitespace 14:15", "List"},
		{"whitespace between keyword and colon", "alert tcp any any -> any any (sid :1;)\n", "(Whitespace 33:34", "Option"},
		{"whitespace after keyword before rparen", "alert tcp any any -> any any (nocase )\n", "(Whitespace 36:37", "Body"},
		{"leading whitespace of a rule", "  alert tcp any any -> any any (sid:1;)\n", "(Whitespace 0:2", "Rule"},
		{"tail of a rule", "alert tcp any any -> any any (sid:1;)  \n", "(Whitespace 37:39", "Rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := []byte(tt.src)
			f, diags := Parse(src)
			checkFile(t, src, f, diags)
			if got := parentIn(t, dumpOf(f), tt.prefix); got != tt.parent {
				t.Errorf("%s is owned by %s, want %s", tt.prefix, got, tt.parent)
			}
		})
	}
}

// TestSuricata8Header checks the header syntax Suricata 8 adds: a list of
// actions, scopes and hooks kept in their tokens, the "=>" direction, and
// address and port lists without brackets.
func TestSuricata8Header(t *testing.T) {
	src := []byte("accept:hook,alert http1:request_line 10.0.0.0/8,!10.1.0.0/16 80,443 => any any (sid:1;)\n" +
		"drop:flow tcp:all any any <> [1.1.1.1,2.2.2.2],3.3.3.3 any (sid:2;)\n" +
		"accept:hook, tcp any any -> any any (sid:3;)\n" +
		"alert tcp 1.1.1.1, any -> any any (sid:4;)\n")
	f, diags := Parse(src)
	if got := f.Text(); got != string(src) {
		t.Fatalf("Text() differs from the source:\n%s", got)
	}
	if err := cst.Verify(f); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	rules := f.Rules()
	if len(rules) != 4 {
		t.Fatalf("%d rules, want 4", len(rules))
	}

	h := rules[0].Header
	if h.Action.Lit != "accept:hook" || len(h.MoreActions) != 1 || h.MoreActions[0].Lit != "alert" || len(h.ActionCommas) != 1 {
		t.Errorf("rule 1 actions: %q %v %v", h.Action.Lit, h.MoreActions, h.ActionCommas)
	}
	if h.Proto.Lit != "http1:request_line" || h.Dir.Lit != "=>" {
		t.Errorf("rule 1 proto %q dir %q", h.Proto.Lit, h.Dir.Lit)
	}
	src1 := h.Src.List
	if src1 == nil || src1.Bracketed() || len(src1.Items) != 2 || src1.Items[1].Bang == nil || src1.Items[1].Word.Lit != "10.1.0.0/16" {
		t.Fatalf("rule 1 source is not the bare list 10.0.0.0/8,!10.1.0.0/16: %+v", h.Src)
	}
	if sp := h.SrcPort.List; sp == nil || sp.Bracketed() || len(sp.Items) != 2 {
		t.Errorf("rule 1 source port is not the bare list 80,443: %+v", h.SrcPort)
	}

	h = rules[1].Header
	if h.Action.Lit != "drop:flow" || h.Proto.Lit != "tcp:all" || h.Dir.Lit != "<>" {
		t.Errorf("rule 2: %q %q %q", h.Action.Lit, h.Proto.Lit, h.Dir.Lit)
	}
	if d := h.Dst.List; d == nil || d.Bracketed() || len(d.Items) != 2 || d.Items[0].List == nil || !d.Items[0].List.Bracketed() {
		t.Errorf("rule 2 destination is not the bare list [1.1.1.1,2.2.2.2],3.3.3.3: %+v", h.Dst)
	}

	var bad []int
	for _, d := range diags {
		if d.Rule == RuleBadHeader {
			bad = append(bad, f.Lines().Position(d.Span.Start).Line)
		}
	}
	if !slices.Equal(bad, []int{3, 4}) {
		t.Errorf("syntax-bad-header on lines %v, want [3 4]: %v", bad, diags)
	}
	if h := rules[2].Header; len(h.ActionCommas) != 1 || len(h.MoreActions) != 0 || h.Proto.Lit != "tcp" {
		t.Errorf("rule 3, an action list ending in ',': %v %v proto %q", h.ActionCommas, h.MoreActions, h.Proto.Lit)
	}
}

// TestConfigDirective checks that a line starting with config is a rule
// only when it has a body: Snort's configuration directives stay one bad
// line, as before Suricata's config action was known.
func TestConfigDirective(t *testing.T) {
	src := []byte("config classification: not-suspicious,Not Suspicious Traffic,3\n" +
		"config classification: misc,Misc (generic) activity,3\n" +
		"config disable_decode_alerts\n" +
		"config dns any any -> any any (dns.query; content:\"x\"; config:logging disable,type tx,scope tx; sid:1;)\n" +
		"config:packet tcp any any -> any any (sid:2;)\n")
	f, diags := Parse(src)
	if got := f.Text(); got != string(src) {
		t.Fatalf("Text() differs from the source:\n%s", got)
	}
	if n := len(f.Rules()); n != 2 {
		t.Errorf("%d rules, want 2 (the config rules with a body)", n)
	}
	if len(diags) != 3 {
		t.Fatalf("%d diagnostics, want one per directive line: %v", len(diags), diags)
	}
	for _, d := range diags {
		if d.Rule != RuleBadHeader || !strings.Contains(d.Message, `got "config"`) {
			t.Errorf("diagnostic %v, want syntax-bad-header at the config directive", d)
		}
	}
}

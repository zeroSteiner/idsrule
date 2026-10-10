package token_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

// allKinds lists every defined kind in declaration order.
var allKinds = []token.Kind{
	token.EOF, token.Newline, token.Whitespace, token.LineContinuation,
	token.Comment, token.Word, token.Bang, token.LBracket, token.RBracket,
	token.Comma, token.LParen, token.RParen, token.Keyword, token.Colon,
	token.Semicolon, token.Value, token.Bad, token.Missing,
}

func TestKindString(t *testing.T) {
	tests := []struct {
		kind token.Kind
		want string
	}{
		{token.EOF, "eof"},
		{token.Newline, "newline"},
		{token.Whitespace, "whitespace"},
		{token.LineContinuation, "line_continuation"},
		{token.Comment, "comment"},
		{token.Word, "word"},
		{token.Bang, "bang"},
		{token.LBracket, "lbracket"},
		{token.RBracket, "rbracket"},
		{token.Comma, "comma"},
		{token.LParen, "lparen"},
		{token.RParen, "rparen"},
		{token.Keyword, "keyword"},
		{token.Colon, "colon"},
		{token.Semicolon, "semicolon"},
		{token.Value, "value"},
		{token.Bad, "bad"},
		{token.Missing, "missing"},
		{token.Missing + 1, "Kind(18)"},
		{token.Kind(255), "Kind(255)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.kind.String(); got != tt.want {
				t.Errorf("Kind(%d).String() = %q, want %q", uint8(tt.kind), got, tt.want)
			}
		})
	}
}

func TestKindStringDistinct(t *testing.T) {
	seen := make(map[string]token.Kind, len(allKinds))
	for _, k := range allKinds {
		name := k.String()
		if prev, dup := seen[name]; dup {
			t.Errorf("kinds %d and %d share the name %q", uint8(prev), uint8(k), name)
		}
		seen[name] = k
	}
}

func TestKindIsTrivia(t *testing.T) {
	trivia := map[token.Kind]bool{
		token.Newline:          true,
		token.Whitespace:       true,
		token.LineContinuation: true,
		token.Comment:          true,
	}
	for _, k := range allKinds {
		t.Run(k.String(), func(t *testing.T) {
			if got, want := k.IsTrivia(), trivia[k]; got != want {
				t.Errorf("%s.IsTrivia() = %v, want %v", k, got, want)
			}
		})
	}
	if (token.Missing + 1).IsTrivia() {
		t.Error("an out-of-range kind reports itself as trivia")
	}
}

func TestToken(t *testing.T) {
	tests := []struct {
		name string
		tok  token.Token
		span source.Span
		len  int
		str  string
	}{
		{
			name: "word",
			tok:  token.Token{Kind: token.Word, Start: 6, End: 9, Lit: "tcp"},
			span: source.Span{Start: 6, End: 9},
			len:  3,
			str:  `word(6:9) "tcp"`,
		},
		{
			name: "whitespace is quoted visibly",
			tok:  token.Token{Kind: token.Whitespace, Start: 5, End: 7, Lit: " \t"},
			span: source.Span{Start: 5, End: 7},
			len:  2,
			str:  `whitespace(5:7) " \t"`,
		},
		{
			name: "eof is zero width",
			tok:  token.Token{Kind: token.EOF, Start: 40, End: 40},
			span: source.Span{Start: 40, End: 40},
			len:  0,
			str:  `eof(40:40) ""`,
		},
		{
			name: "zero value",
			tok:  token.Token{},
			span: source.Span{},
			len:  0,
			str:  `eof(0:0) ""`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tok.Span(); got != tt.span {
				t.Errorf("Span() = %+v, want %+v", got, tt.span)
			}
			if got := tt.tok.Text(); got != tt.tok.Lit {
				t.Errorf("Text() = %q, want Lit %q", got, tt.tok.Lit)
			}
			if got := tt.tok.Len(); got != tt.len {
				t.Errorf("Len() = %d, want %d", got, tt.len)
			}
			if got := tt.tok.String(); got != tt.str {
				t.Errorf("String() = %s, want %s", got, tt.str)
			}
		})
	}
}

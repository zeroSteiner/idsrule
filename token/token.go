// Package token defines the tokens the lexer produces from a rule file and
// that the parser consumes.
//
// Tokens are lossless: a token's Lit is the exact bytes it covers, trivia
// (whitespace, newlines, line continuations and comments) gets tokens of its
// own, and the tokens of a file concatenate back to the file.
package token

import (
	"fmt"

	"github.com/zeroSteiner/idsrule/source"
)

// Kind classifies a token.
//
// Rule syntax is lexed in three modes, and several kinds exist in only one of
// them: the header (from the action to the opening parenthesis) has words and
// group punctuation, the option body has keywords and ';' / ':', and an
// option value is a single raw Value token.
type Kind uint8

const (
	// EOF is the zero-width token that always ends a token stream.
	EOF Kind = iota
	// Newline is a "\n" or "\r\n" line ending.
	Newline
	// Whitespace is a run of spaces, tabs and lone '\r' bytes (a '\r' not
	// followed by '\n'); adjacent ones merge into a single token.
	Whitespace
	// LineContinuation is a '\' at the end of a line, including any spaces
	// or tabs between it and the newline, and the newline itself.
	LineContinuation
	// Comment is a '#' at the start of a line (after optional whitespace)
	// through the last byte before the newline. The lexer recognises
	// comments only between rules, that is in header mode.
	Comment
	// Word is a header word: an action, a protocol, an address or port
	// expression, a variable or a direction operator. It is a maximal run
	// of bytes that are not whitespace, newlines or group punctuation.
	Word
	// Bang is a '!' in the header.
	Bang
	// LBracket is a '[' in the header.
	LBracket
	// RBracket is a ']' in the header.
	RBracket
	// Comma is a ',' in the header.
	Comma
	// LParen is the '(' that opens the option body.
	LParen
	// RParen is a ')': the one that closes the option body, or a stray one
	// in the header.
	RParen
	// Keyword is an option name in the body: [A-Za-z0-9_.-]+.
	Keyword
	// Colon is the ':' that separates an option name from its value.
	Colon
	// Semicolon is the ';' that ends an option.
	Semicolon
	// Value is the raw text of an option value: quotes, parentheses, pipes
	// and escape pairs included, up to but not including the ';' or ')'
	// that ends it. It never contains '\n'; a quoted string that is
	// continued across lines spans several Value tokens.
	Value
	// Bad is a maximal run of bytes the lexer did not expect in the header
	// or the body.
	Bad
	// Missing is a zero-width placeholder the parser inserts where a token
	// was required but absent. The lexer never emits it.
	Missing
)

var kindNames = [...]string{
	EOF:              "eof",
	Newline:          "newline",
	Whitespace:       "whitespace",
	LineContinuation: "line_continuation",
	Comment:          "comment",
	Word:             "word",
	Bang:             "bang",
	LBracket:         "lbracket",
	RBracket:         "rbracket",
	Comma:            "comma",
	LParen:           "lparen",
	RParen:           "rparen",
	Keyword:          "keyword",
	Colon:            "colon",
	Semicolon:        "semicolon",
	Value:            "value",
	Bad:              "bad",
	Missing:          "missing",
}

// String returns the lower-case name of k, such as "line_continuation".
// A kind outside the defined range renders as "Kind(n)".
func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return fmt.Sprintf("Kind(%d)", uint8(k))
}

// IsTrivia reports whether k is one of the kinds that carry no syntax:
// Newline, Whitespace, LineContinuation and Comment.
func (k Kind) IsTrivia() bool {
	switch k {
	case Newline, Whitespace, LineContinuation, Comment:
		return true
	case EOF, Word, Bang, LBracket, RBracket, Comma, LParen, RParen,
		Keyword, Colon, Semicolon, Value, Bad, Missing:
		return false
	}
	return false
}

// Token is one lexical unit of a rule file together with its position.
//
// Kind is a field rather than a method so that the syntax tree can wrap
// tokens without the names colliding.
type Token struct {
	Kind  Kind
	Start int    // byte offset of the first byte, inclusive
	End   int    // byte offset just past the last byte, exclusive
	Lit   string // the exact source bytes src[Start:End]
}

// Span returns the byte range t covers.
func (t Token) Span() source.Span { return source.Span{Start: t.Start, End: t.End} }

// Text returns the source text of t, which is t.Lit.
func (t Token) Text() string { return t.Lit }

// Len returns the number of bytes t covers.
func (t Token) Len() int { return t.End - t.Start }

// String renders t for test failure messages as `kind(start:end) "lit"`,
// with the literal quoted as Go syntax so that whitespace is visible.
func (t Token) String() string {
	return fmt.Sprintf("%s(%d:%d) %q", t.Kind, t.Start, t.End, t.Lit)
}

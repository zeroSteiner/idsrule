// Package lexer turns the bytes of a rule file into tokens.
//
// The lexer is lossless: every byte of the input lands in exactly one token,
// in order, so that concatenating the tokens' text reproduces the input byte
// for byte. It is also total: it never fails and never panics, whatever the
// input. Bytes it does not expect become Bad tokens, and the one error it
// detects itself, a quoted string still open at the end of its line, is
// reported as a diagnostic rather than by stopping.
//
// The input is treated as bytes. Nothing is decoded as UTF-8; a non-ASCII
// byte is simply part of whichever token it falls in.
//
// # Modes
//
// Rule syntax is lexed differently in the rule header, in the option body
// and inside an option value, so the scanner is mode-driven:
//
//   - Header mode is the initial mode. It produces Word tokens for anything
//     that is not whitespace or one of the group punctuation bytes '!' '['
//     ']' ',' and the parentheses. '(' switches to Body mode. A '#' at the
//     start of a line is a Comment; comments are recognised in no other
//     mode and nowhere else on a line.
//   - Body mode, entered by '(' and re-entered by every ';', produces
//     Keyword tokens, ':' which switches to Value mode, ';' and the ')' that
//     returns to Header mode. Any other byte is Bad.
//   - Value mode, entered by ':', collects one option value as a single
//     Value token. A ';' ends the value and returns to Body mode. A ')'
//     ends the value, and the rule, when it is the last ')' on the logical
//     line, which is how both engines find the closing parenthesis: they
//     splice continued lines and take the last ')'. Any other ')' is part
//     of the value. A backslash escapes the byte after it, so an escaped
//     ';' is part of the value. Double quotes do not protect a ';' or ')',
//     because neither engine honours them when it splits options; the
//     lexer tracks them only to report a string that is still open when
//     the line ends.
//
// # Line structure
//
// Newlines and line continuations are tokens of their own in every mode. A
// line continuation ('\' followed by optional spaces and tabs and a newline)
// keeps the current mode and the string state, as both engines splice
// continued lines before parsing; a quoted string may therefore span several
// Value tokens with a LineContinuation and a Whitespace between them. A '\'
// that ends a physical line is a continuation even when the byte before it
// is another '\': both engines look for the trailing backslash before any
// escape processing, so such a pair is one ordinary byte and one
// continuation, not an escape pair. A logical line runs from the start of a
// physical line through its continuations to the next bare newline or the
// end of the input. A bare newline ends the logical line: in Body or Value
// mode the lexer flushes what it has and returns to Header mode, and leaves
// it to the parser to report the unterminated rule.
//
// A lone '\r' that is not followed by '\n' is Whitespace in Header and Body
// mode and an ordinary byte of the value in Value mode (and of a comment in
// a Comment). "\r\n" is always a Newline.
package lexer

import (
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/source"
	"github.com/zeroSteiner/idsrule/token"
)

// RuleUnterminatedString is the id of the only diagnostic the lexer emits:
// a double-quoted string that is still open when its line, or the input,
// ends.
const RuleUnterminatedString = "syntax-unterminated-string"

// Lex tokenizes src. It never fails and never panics: every byte of src
// appears in exactly one token, in order, and concatenating the tokens' Lit
// reproduces src. The last token is always a zero-width EOF at len(src).
//
// The returned diagnostics carry Rule, Severity, Message and Span only;
// Line, Column and End are left zero for the caller to resolve with
// [diag.Builder.Resolve]. The only diagnostic the lexer emits is
// [RuleUnterminatedString].
func Lex(src []byte) ([]token.Token, []diag.Diagnostic) {
	l := &lexer{src: src, atLineStart: true, parenScanEnd: -1}
	for l.pos < len(l.src) {
		switch l.mode {
		case modeHeader:
			l.lexHeader()
		case modeBody:
			l.lexBody()
		case modeValue:
			l.lexValue()
		}
	}
	l.add(token.EOF, len(src), len(src))
	return l.toks, l.diags
}

// lexer is the scanner state for one call of Lex.
type lexer struct {
	src []byte
	pos int // offset of the next unread byte

	mode        mode
	atLineStart bool // only whitespace so far on the current line
	inString    bool // Value mode: inside a double-quoted string
	stringStart int  // offset of the opening quote while inString

	// The last ')' on the logical line being scanned in Value mode, and the
	// offset at which that logical line ends; see closesRule. parenScanEnd
	// is -1 until the first ')' triggers a scan.
	lastParen    int
	parenScanEnd int

	toks  []token.Token
	diags []diag.Diagnostic
}

// add appends a token of kind k covering src[start:end] without moving pos.
func (l *lexer) add(k token.Kind, start, end int) {
	l.toks = append(l.toks, token.Token{Kind: k, Start: start, End: end, Lit: string(l.src[start:end])})
}

// emit appends a token of kind k covering src[pos:end] and advances past it.
func (l *lexer) emit(k token.Kind, end int) {
	l.add(k, l.pos, end)
	l.pos = end
}

// report records an unterminated string that began at stringStart and ends,
// exclusive, at end.
func (l *lexer) report(end int) {
	l.diags = append(l.diags, diag.Diagnostic{
		Severity: diag.SeverityError,
		Rule:     RuleUnterminatedString,
		Message:  "unterminated string",
		Span:     source.Span{Start: l.stringStart, End: end},
	})
}

// Byte classes. Everything is byte-oriented; see the package comment.

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

func isKeywordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '.' || c == '-'
}

// isWordStop reports whether c ends a header Word: whitespace, a line
// ending, or group punctuation.
func isWordStop(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '[', ']', ',', '!', '(', ')':
		return true
	}
	return false
}

// newlineAt returns the length of the newline at offset i: 1 for "\n", 2
// for "\r\n" and 0 when there is none.
func (l *lexer) newlineAt(i int) int {
	switch {
	case i >= len(l.src):
		return 0
	case l.src[i] == '\n':
		return 1
	case l.src[i] == '\r' && i+1 < len(l.src) && l.src[i+1] == '\n':
		return 2
	}
	return 0
}

// continuationAt returns the length of the line continuation at offset i,
// a '\' followed by optional blanks and a newline, or 0 when there is none.
func (l *lexer) continuationAt(i int) int {
	if i >= len(l.src) || l.src[i] != '\\' {
		return 0
	}
	j := i + 1 + l.blankRun(i+1)
	if nl := l.newlineAt(j); nl > 0 {
		return j + nl - i
	}
	return 0
}

// blankRun returns the length of the run of spaces and tabs at offset i.
func (l *lexer) blankRun(i int) int {
	j := i
	for j < len(l.src) && isBlank(l.src[j]) {
		j++
	}
	return j - i
}

// spaceRun returns the length of the Header and Body mode whitespace run at
// offset i: spaces, tabs and any '\r' that does not begin a "\r\n".
func (l *lexer) spaceRun(i int) int {
	j := i
	for j < len(l.src) {
		c := l.src[j]
		if !isBlank(c) && (c != '\r' || l.newlineAt(j) > 0) {
			break
		}
		j++
	}
	return j - i
}

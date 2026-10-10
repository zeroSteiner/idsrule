package lexer

import "github.com/zeroSteiner/idsrule/token"

// mode is the part of a rule the scanner is in. See the package comment.
type mode uint8

const (
	modeHeader mode = iota // between rules and in the rule header
	modeBody               // inside the parentheses, between options
	modeValue              // after an option's ':'
)

// lexTrivia consumes one newline, line continuation or whitespace token at
// pos, if there is one, and reports whether it did. It serves Header and
// Body mode; Value mode handles its own trivia because its rules differ.
func (l *lexer) lexTrivia() bool {
	if l.newlineAt(l.pos) > 0 {
		l.lexNewline()
		return true
	}
	if n := l.continuationAt(l.pos); n > 0 {
		l.lexContinuation(n)
		return true
	}
	if n := l.spaceRun(l.pos); n > 0 {
		l.emit(token.Whitespace, l.pos+n)
		return true
	}
	return false
}

// lexNewline emits the newline at pos and starts a new logical line: the
// mode returns to Header and the next byte is at the start of a line.
func (l *lexer) lexNewline() {
	l.emit(token.Newline, l.pos+l.newlineAt(l.pos))
	l.mode = modeHeader
	l.atLineStart = true
}

// lexContinuation emits the line continuation of n bytes at pos. The mode
// is kept, as is atLineStart: a continuation joins two physical lines into
// one logical line, so it neither starts nor ends a line.
func (l *lexer) lexContinuation(n int) {
	l.emit(token.LineContinuation, l.pos+n)
}

// lexHeader lexes one token in Header mode.
func (l *lexer) lexHeader() {
	if l.lexTrivia() {
		return
	}
	switch c := l.src[l.pos]; c {
	case '#':
		if l.atLineStart {
			l.emit(token.Comment, l.lineEnd(l.pos))
		} else {
			l.emit(token.Word, l.wordEnd(l.pos))
		}
	case '(':
		l.emit(token.LParen, l.pos+1)
		l.mode = modeBody
	case ')':
		l.emit(token.RParen, l.pos+1)
	case '!':
		l.emit(token.Bang, l.pos+1)
	case '[':
		l.emit(token.LBracket, l.pos+1)
	case ']':
		l.emit(token.RBracket, l.pos+1)
	case ',':
		l.emit(token.Comma, l.pos+1)
	default:
		l.emit(token.Word, l.wordEnd(l.pos))
	}
	l.atLineStart = false
}

// lineEnd returns the offset of the newline that ends the line containing
// offset i, or len(src) when the line is the last one.
func (l *lexer) lineEnd(i int) int {
	for i < len(l.src) && l.newlineAt(i) == 0 {
		i++
	}
	return i
}

// wordEnd returns the end of the header Word starting at offset i: the run
// continues until a word stop byte or a line continuation. A '\' that does
// not begin a continuation is an ordinary word byte.
func (l *lexer) wordEnd(i int) int {
	j := i + 1
	for j < len(l.src) && !isWordStop(l.src[j]) && l.continuationAt(j) == 0 {
		j++
	}
	return j
}

// lexBody lexes one token in Body mode.
func (l *lexer) lexBody() {
	if l.lexTrivia() {
		return
	}
	switch c := l.src[l.pos]; {
	case isKeywordByte(c):
		l.emit(token.Keyword, l.keywordEnd(l.pos))
	case c == ':':
		l.emit(token.Colon, l.pos+1)
		l.mode = modeValue
	case c == ';':
		l.emit(token.Semicolon, l.pos+1)
	case c == ')':
		l.emit(token.RParen, l.pos+1)
		l.mode = modeHeader
	default:
		l.emit(token.Bad, l.badEnd(l.pos))
	}
	l.atLineStart = false
}

// keywordEnd returns the end of the Keyword starting at offset i.
func (l *lexer) keywordEnd(i int) int {
	j := i + 1
	for j < len(l.src) && isKeywordByte(l.src[j]) {
		j++
	}
	return j
}

// badEnd returns the end of the Bad run starting at offset i: it continues
// until a byte that Body mode does expect, that is whitespace, a line
// ending, a line continuation, a keyword byte, ':', ';' or ')'. A '\' that
// does not begin a continuation is an ordinary bad byte.
func (l *lexer) badEnd(i int) int {
	j := i + 1
	for j < len(l.src) {
		c := l.src[j]
		if isBlank(c) || c == '\r' || c == '\n' || isKeywordByte(c) ||
			c == ':' || c == ';' || c == ')' || l.continuationAt(j) > 0 {
			break
		}
		j++
	}
	return j
}

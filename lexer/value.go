package lexer

import "github.com/zeroSteiner/idsrule/token"

// lexValue scans one option value: everything from just after the ':' to
// the ';' or ')' that ends it, or to the end of the logical line or of the
// input.
//
// Leading spaces and tabs are emitted as Whitespace, then the value proper
// accumulates as a pending Value token from its first byte until something
// ends or interrupts it. A line continuation interrupts the value: the
// pending text is flushed, the continuation and any blanks after it get
// tokens of their own, and the value resumes, still inside a string if it
// was in one.
//
// Backslashes: a '\' that ends the physical line (blanks before the newline
// allowed) is a continuation, and so is the second of two '\' in that
// position, because both engines look for the trailing backslash before any
// escape processing; the first of the pair is then an ordinary value byte.
// Any other '\' escapes the byte after it, so an escaped ';' does not end
// the value and an escaped quote does not toggle the string.
//
// Terminators: a ';' ends the value. A ')' ends it only when it is the last
// ')' on the logical line (see closesRule). Quotes protect neither: neither
// engine honours them when it splits a rule into options, both require a
// backslash before a ';' inside content and pcre, and real rules rely on it
// (a pcre whose regex contains a literal quote has three quotes in its
// value). The lexer tracks quotes only to report a string still open when
// the line ends.
//
// Trailing blanks are split off the pending value into a Whitespace token
// before a ';', a closing ')', a bare newline or the end of the input, so
// that the Value ends at its last meaningful byte. The split never reaches
// into an escape pair, is not made when the value ends inside an open
// string (blanks there are content), and is not made before a line
// continuation.
func (l *lexer) lexValue() {
	if n := l.blankRun(l.pos); n > 0 {
		l.emit(token.Whitespace, l.pos+n)
	}
	start := l.pos // first byte of the pending Value token
	fixed := l.pos // the trailing-blank split never reaches before this
	for l.pos < len(l.src) {
		if l.newlineAt(l.pos) > 0 {
			l.endValue(start, fixed)
			l.lexNewline()
			return
		}
		switch l.src[l.pos] {
		case '\\':
			if n := l.continuationAt(l.pos); n > 0 {
				l.flushValue(start, l.pos)
				l.emit(token.LineContinuation, l.pos+n)
				if n := l.blankRun(l.pos); n > 0 {
					l.emit(token.Whitespace, l.pos+n)
				}
				start, fixed = l.pos, l.pos
				continue
			}
			if l.continuationAt(l.pos+1) > 0 {
				// The next '\' ends the line, so it is a continuation and
				// this one is a plain value byte, not the start of a pair.
				l.pos++
				continue
			}
			// An escape pair: the backslash and the byte after it, if any.
			l.pos++
			if l.pos < len(l.src) {
				l.pos++
			}
			fixed = l.pos
			continue
		case '"':
			if !l.inString {
				l.stringStart = l.pos
			}
			l.inString = !l.inString
			l.pos++
			fixed = l.pos
			continue
		case ';':
			l.flushValue(start, fixed)
			l.inString = false
			l.emit(token.Semicolon, l.pos+1)
			l.mode = modeBody
			return
		case ')':
			if l.closesRule(l.pos) {
				l.flushValue(start, fixed)
				l.inString = false
				l.emit(token.RParen, l.pos+1)
				l.mode = modeHeader
				return
			}
		}
		l.pos++
	}
	l.endValue(start, fixed)
}

// closesRule reports whether the ')' at offset i ends the rule: it does
// when it is the last ')' on its logical line, which is the one both engines
// pick after splicing continued lines. The scan for the last ')' runs once
// per logical line, from the first ')' seen in Value mode to the bare
// newline or the end of the input, and its result is reused for every later
// ')' on that line, so the cost stays linear whatever the input looks like.
func (l *lexer) closesRule(i int) bool {
	if i > l.parenScanEnd {
		l.scanParens(i)
	}
	return i == l.lastParen
}

// scanParens records in lastParen the offset of the last ')' on the logical
// line that contains offset i, scanning from i, and in parenScanEnd the
// offset at which that logical line ends. Line continuations are stepped
// over. The scan ignores escapes, as the engines do. Note that lexValue
// consumes an escape pair before it consults lastParen, so a "\)" that is
// itself the last ')' on the line never closes the rule; that is reachable
// only when the line has no unescaped closer, i.e. the rule is malformed
// either way, and the parser reports it as an unterminated rule.
func (l *lexer) scanParens(i int) {
	last, j := -1, i
	for j < len(l.src) && l.newlineAt(j) == 0 {
		if n := l.continuationAt(j); n > 0 {
			j += n
			continue
		}
		if l.src[j] == ')' {
			last = j
		}
		j++
	}
	l.lastParen, l.parenScanEnd = last, j
}

// endValue finishes the pending value at the end of a line or of the input,
// reporting a string that is still open at that point.
func (l *lexer) endValue(start, fixed int) {
	if l.inString {
		l.report(l.pos)
	}
	l.flushValue(start, fixed)
	l.inString = false
}

// flushValue emits the pending Value token src[start:pos], if it is not
// empty. Spaces and tabs at its end, back to but not before fixed, are
// emitted as a Whitespace token after it instead, unless the value ends
// inside an open string.
func (l *lexer) flushValue(start, fixed int) {
	end := l.pos
	if l.inString {
		fixed = l.pos
	}
	for end > fixed && isBlank(l.src[end-1]) {
		end--
	}
	if end > start {
		l.add(token.Value, start, end)
	}
	if end < l.pos {
		l.add(token.Whitespace, end, l.pos)
	}
}

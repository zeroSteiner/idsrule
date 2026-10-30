// Package value decodes the values of rule options: the text after the ':'
// of an option, as the engines see it.
//
// Every decoder takes the option's logical value, what
// [cst.Option.LogicalValue] returns (line continuations removed, blanks at
// both ends trimmed), and never sees the syntax tree. Every error is an
// [*Error] that carries a byte offset into that string, so that a caller
// can map it back to the source.
package value

import (
	"fmt"

	"github.com/zeroSteiner/idsrule/dialect"
)

// Error is a decoding error: what is wrong and where in the decoded string.
type Error struct {
	// Off is the byte offset into the decoded string of the problem; it is
	// the length of the string when the value ended too early.
	Off int
	// Msg says what is wrong.
	Msg string
}

// Error returns "<Msg> at offset <Off>".
func (e *Error) Error() string { return fmt.Sprintf("%s at offset %d", e.Msg, e.Off) }

// errAt returns an *Error as an error.
func errAt(off int, msg string) error { return &Error{Off: off, Msg: msg} }

// shift returns err with its offset moved by n when it is an *Error, so
// that a decoder that decodes a piece of its input can report the error
// against the whole. Any other error, nil included, is returned as is.
func shift(err error, n int) error {
	if e, ok := err.(*Error); ok {
		return &Error{Off: e.Off + n, Msg: e.Msg}
	}
	return err
}

// Validate decodes s as a value of kind and returns the error, if any.
// KindNone accepts only the empty string, KindRaw accepts anything, and
// every other kind is decoded by its Parse function. A kind outside the
// defined range is an error.
func Validate(kind dialect.ValueKind, s string) error {
	var err error
	switch kind {
	case dialect.KindNone:
		if s != "" {
			return errAt(0, "keyword takes no value")
		}
	case dialect.KindUint:
		_, err = ParseUint(s)
	case dialect.KindIntOrVar:
		_, err = ParseIntOrVar(s)
	case dialect.KindRelInt:
		_, err = ParseRelInt(s)
	case dialect.KindUrilen:
		_, err = ParseUrilen(s)
	case dialect.KindQuoted:
		_, err = ParseQuoted(s)
	case dialect.KindIdent:
		_, err = ParseIdent(s)
	case dialect.KindContent:
		_, err = ParseContent(s)
	case dialect.KindPCRE:
		_, err = ParsePCRE(s)
	case dialect.KindFlow:
		_, err = ParseFlow(s)
	case dialect.KindFlowbits:
		_, err = ParseFlowbits(s)
	case dialect.KindReference:
		_, err = ParseReference(s)
	case dialect.KindMetadata:
		_, err = ParseMetadata(s)
	case dialect.KindThreshold:
		_, err = ParseThreshold(s)
	case dialect.KindBase64Decode:
		_, err = ParseBase64Decode(s)
	case dialect.KindFastPattern:
		_, err = ParseFastPattern(s)
	case dialect.KindIsDataAt:
		_, err = ParseIsDataAt(s)
	case dialect.KindDirection:
		_, err = ParseDirection(s)
	case dialect.KindTos:
		_, err = ParseTos(s)
	case dialect.KindQuotedUint:
		_, err = ParseQuotedUint(s)
	case dialect.KindUintEnum:
		_, err = ParseUintEnum(s)
	case dialect.KindCSV:
		_, err = ParseCSV(s)
	case dialect.KindRaw:
	default:
		return errAt(0, fmt.Sprintf("unknown value kind %s", kind))
	}
	return err
}

// isBlank reports whether c is a space or a tab, the blanks the engines
// allow inside values.
func isBlank(c byte) bool { return c == ' ' || c == '\t' }

// isDigit reports whether c is a decimal digit.
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isLetter reports whether c is an ASCII letter.
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// skipBlanks returns the offset of the first non-blank byte of s at or
// after i, or len(s).
func skipBlanks(s string, i int) int {
	for i < len(s) && isBlank(s[i]) {
		i++
	}
	return i
}

// part is a piece of a value with the offset of its first byte in the
// value.
type part struct {
	text string
	off  int
}

// splitComma splits s on every ',' and returns the pieces untrimmed, with
// their offsets. The result always has at least one part.
func splitComma(s string) []part {
	var parts []part
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, part{s[start:i], start})
			start = i + 1
		}
	}
	return append(parts, part{s[start:], start})
}

// trim returns p without the blanks at both ends, its offset adjusted.
func trim(p part) part {
	i := skipBlanks(p.text, 0)
	j := len(p.text)
	for j > i && isBlank(p.text[j-1]) {
		j--
	}
	return part{p.text[i:j], p.off + i}
}

// keyValue splits p into its first word and the trimmed rest: "count 10"
// gives key "count" and value "10", "relative" gives key "relative" and an
// empty value.
func keyValue(p part) (key, val part) {
	i := 0
	for i < len(p.text) && !isBlank(p.text[i]) {
		i++
	}
	key = part{p.text[:i], p.off}
	val = trim(part{p.text[i:], p.off + i})
	return key, val
}

// parseDigits decodes p as an unsigned decimal number into an int64.
func parseDigits(p part) (int64, error) {
	v, err := ParseUint(p.text)
	if err != nil {
		return 0, shift(err, p.off)
	}
	if v > maxInt64 {
		return 0, errAt(p.off, "number too large")
	}
	return int64(v), nil
}

// maxInt64 is the largest number parseDigits accepts.
const maxInt64 = 1<<63 - 1

package value

import (
	"fmt"
	"strings"
)

// Content is a decoded content pattern.
type Content struct {
	// Negated is set when the value starts with '!'.
	Negated bool
	// Pattern is the bytes to match, escapes and |hex| blocks decoded.
	Pattern []byte
	// Trailing is whatever followed the closing quote, trimmed. It is
	// empty for a well-formed Snort 2 or Suricata content and holds the
	// Snort 3 style modifiers of a value such as `"x", nocase`.
	Trailing string
}

// ParseContent decodes a content value: an optional '!', then a quoted
// pattern. Inside the quotes a backslash escapes '"', '\', ';', ':' or
// '|', and a pair of '|' encloses hex bytes, two digits each, with blanks
// allowed between them. An empty pattern, a missing quote, an invalid
// escape, an odd number of hex digits or a non-hex byte in a hex block is
// an error; text after the closing quote is not, it is returned as
// Trailing.
func ParseContent(s string) (Content, error) {
	var c Content
	i := 0
	if i < len(s) && s[i] == '!' {
		c.Negated = true
		i = skipBlanks(s, i+1)
	}
	if i >= len(s) || s[i] != '"' {
		return Content{}, errAt(i, `expected '"'`)
	}
	start := i + 1
	pat := []byte{}
	for i = start; i < len(s); {
		switch s[i] {
		case '"':
			if len(pat) == 0 {
				return Content{}, errAt(start, "empty content")
			}
			c.Pattern = pat
			c.Trailing = strings.Trim(s[i+1:], " \t")
			return c, nil
		case '\\':
			if i+1 >= len(s) {
				return Content{}, errAt(i, "incomplete escape")
			}
			switch e := s[i+1]; e {
			case '"', '\\', ';', ':', '|':
				pat = append(pat, e)
			default:
				return Content{}, errAt(i, fmt.Sprintf("invalid escape %q", s[i:i+2]))
			}
			i += 2
		case '|':
			var err error
			pat, i, err = hexBlock(s, i+1, pat)
			if err != nil {
				return Content{}, err
			}
		default:
			pat = append(pat, s[i])
			i++
		}
	}
	return Content{}, errAt(len(s), "unterminated string")
}

// hexBlock decodes the hex block that starts just after the '|' at s[i-1],
// appends its bytes to pat and returns the offset just past the closing
// '|'.
func hexBlock(s string, i int, pat []byte) ([]byte, int, error) {
	nibbles := 0
	var cur byte
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '|':
			if nibbles%2 != 0 {
				return nil, 0, errAt(i, "odd number of hex digits")
			}
			return pat, i + 1, nil
		case isBlank(c):
		case isHex(c):
			if nibbles%2 == 0 {
				cur = hexVal(c) << 4
			} else {
				pat = append(pat, cur|hexVal(c))
			}
			nibbles++
		default:
			return nil, 0, errAt(i, fmt.Sprintf("invalid character %q in hex block", c))
		}
	}
	return nil, 0, errAt(len(s), "unterminated hex block")
}

// isHex reports whether c is a hex digit.
func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// hexVal returns the value of the hex digit c.
func hexVal(c byte) byte {
	switch {
	case isDigit(c):
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

package value

import (
	"fmt"
	"strings"
)

// PCRE is a decoded pcre value.
type PCRE struct {
	// Negated is set when the value starts with '!'.
	Negated bool
	// Pattern is the regular expression between the delimiters, as written.
	Pattern string
	// Flags are the letters after the closing delimiter, as written.
	Flags string
}

// ParsePCRE decodes a pcre value: an optional '!', then "/pattern/flags"
// in double quotes, or Snort's "mXpatternXflags" where the delimiter X is
// any byte that is not a letter, a digit or a blank. As the engines do, it
// takes the last '"' of the value as the closing quote, so a pattern may
// contain a literal quote, and the last delimiter before it as the closing
// delimiter, so a pattern may contain the delimiter. The flags must be
// letters; neither engine's flag set is enforced. A missing quote or
// delimiter, a non-letter flag or text after the closing quote is an
// error.
func ParsePCRE(s string) (PCRE, error) {
	var p PCRE
	i := 0
	if i < len(s) && s[i] == '!' {
		p.Negated = true
		i = skipBlanks(s, i+1)
	}
	if i >= len(s) || s[i] != '"' {
		return PCRE{}, errAt(i, `expected '"'`)
	}
	open := i
	closing := strings.LastIndexByte(s, '"')
	if closing == open {
		return PCRE{}, errAt(len(s), "unterminated string")
	}
	if closing != len(s)-1 {
		return PCRE{}, errAt(closing+1, "unexpected text after closing quote")
	}
	inner := s[open+1 : closing]
	// body starts at the opening delimiter, at offset bodyOff of s.
	delim, body, bodyOff := byte('/'), inner, open+1
	switch {
	case inner == "":
		return PCRE{}, errAt(open+1, "expected '/'")
	case inner[0] == 'm':
		if len(inner) < 2 || isLetter(inner[1]) || isDigit(inner[1]) || isBlank(inner[1]) {
			return PCRE{}, errAt(open+2, "expected a delimiter after 'm'")
		}
		delim, body, bodyOff = inner[1], inner[1:], open+2
	case inner[0] != '/':
		return PCRE{}, errAt(open+1, "expected '/'")
	}
	end := strings.LastIndexByte(body, delim)
	if end == 0 {
		return PCRE{}, errAt(closing, fmt.Sprintf("missing closing %q", delim))
	}
	p.Pattern = body[1:end]
	p.Flags = body[end+1:]
	for j := 0; j < len(p.Flags); j++ {
		if !isLetter(p.Flags[j]) {
			return PCRE{}, errAt(bodyOff+end+1+j, fmt.Sprintf("invalid pcre flag %q", p.Flags[j]))
		}
	}
	return p, nil
}

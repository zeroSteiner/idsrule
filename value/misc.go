package value

import (
	"fmt"
	"strings"
)

// IsDataAt is a decoded isdataat value.
type IsDataAt struct {
	// Negated is set when the offset starts with '!'.
	Negated bool
	// Offset is the number of bytes when Var is empty.
	Offset int64
	// Var is the variable as written when the offset is one.
	Var string
	// Relative is set by the relative option.
	Relative bool
	// Rawbytes is set by the rawbytes option.
	Rawbytes bool
}

// ParseIsDataAt decodes an isdataat value: an optional '!', an offset that
// is a non-negative number or a variable, then optionally ",relative" and
// ",rawbytes" in either order, each at most once. Blanks around the pieces
// are allowed.
func ParseIsDataAt(s string) (IsDataAt, error) {
	var d IsDataAt
	parts := splitComma(s)
	off := trim(parts[0])
	if off.text == "" {
		return IsDataAt{}, errAt(off.off, "expected an offset")
	}
	if off.text[0] == '!' {
		d.Negated = true
		off = trim(part{off.text[1:], off.off + 1})
	}
	iv, err := ParseIntOrVar(off.text)
	if err != nil {
		return IsDataAt{}, shift(err, off.off)
	}
	if iv.Var == "" && iv.Value < 0 {
		return IsDataAt{}, errAt(off.off, "offset must not be negative")
	}
	d.Offset, d.Var = iv.Value, iv.Var
	for _, p := range parts[1:] {
		p = trim(p)
		switch {
		case p.text == "relative" && !d.Relative:
			d.Relative = true
		case p.text == "rawbytes" && !d.Rawbytes:
			d.Rawbytes = true
		case p.text == "relative" || p.text == "rawbytes":
			return IsDataAt{}, errAt(p.off, fmt.Sprintf("duplicate %q", p.text))
		default:
			return IsDataAt{}, errAt(p.off, fmt.Sprintf("unknown isdataat option %q", p.text))
		}
	}
	return d, nil
}

// FastPattern is a decoded fast_pattern value.
type FastPattern struct {
	// Only is set by "only".
	Only bool
	// Offset and Length are the chunk when Chunk is set.
	Offset, Length int64
	// Chunk is set by "offset,length".
	Chunk bool
}

// ParseFastPattern decodes a fast_pattern value: nothing, "only", or
// "offset,length" with unsigned numbers. Blanks around the pieces are
// allowed.
func ParseFastPattern(s string) (FastPattern, error) {
	whole := trim(part{s, 0})
	if whole.text == "" {
		return FastPattern{}, nil
	}
	if whole.text == "only" {
		return FastPattern{Only: true}, nil
	}
	parts := splitComma(s)
	if len(parts) != 2 {
		return FastPattern{}, errAt(whole.off, `expected "only" or "offset,length"`)
	}
	offset, err := parseDigits(trim(parts[0]))
	if err != nil {
		return FastPattern{}, err
	}
	length, err := parseDigits(trim(parts[1]))
	if err != nil {
		return FastPattern{}, err
	}
	return FastPattern{Offset: offset, Length: length, Chunk: true}, nil
}

// Base64Decode is a decoded base64_decode value.
type Base64Decode struct {
	// Bytes is the number of bytes to decode; zero when not given.
	Bytes int64
	// Offset is where to start; zero when not given.
	Offset int64
	// Relative is set by the relative option.
	Relative bool
}

// ParseBase64Decode decodes a base64_decode value: nothing, or the items
// "bytes N", "offset N" and "relative", comma-separated, in any order, each
// at most once. Blanks around the items are allowed.
func ParseBase64Decode(s string) (Base64Decode, error) {
	var d Base64Decode
	if trim(part{s, 0}).text == "" {
		return d, nil
	}
	seen := make(map[string]bool)
	for _, p := range splitComma(s) {
		p = trim(p)
		if p.text == "" {
			return Base64Decode{}, errAt(p.off, "empty base64_decode item")
		}
		key, val := keyValue(p)
		if seen[key.text] {
			return Base64Decode{}, errAt(key.off, fmt.Sprintf("duplicate %q", key.text))
		}
		seen[key.text] = true
		switch key.text {
		case "bytes", "offset":
			n, err := parseDigits(val)
			if err != nil {
				return Base64Decode{}, err
			}
			if key.text == "bytes" {
				d.Bytes = n
			} else {
				d.Offset = n
			}
		case "relative":
			if val.text != "" {
				return Base64Decode{}, errAt(val.off, "relative takes no value")
			}
			d.Relative = true
		default:
			return Base64Decode{}, errAt(key.off, fmt.Sprintf("unknown base64_decode item %q", key.text))
		}
	}
	return d, nil
}

// ParseQuoted decodes a double-quoted string and returns its text with the
// escapes resolved: a backslash before any byte stands for that byte, as
// both engines read a msg. A missing quote, a backslash with nothing after
// it and text after the closing quote are errors.
func ParseQuoted(s string) (string, error) {
	if s == "" || s[0] != '"' {
		return "", errAt(0, `expected '"'`)
	}
	out := make([]byte, 0, len(s))
	for i := 1; i < len(s); {
		switch s[i] {
		case '"':
			if rest := skipBlanks(s, i+1); rest != len(s) {
				return "", errAt(rest, "unexpected text after closing quote")
			}
			return string(out), nil
		case '\\':
			if i+1 >= len(s) {
				return "", errAt(i, "incomplete escape")
			}
			out = append(out, s[i+1])
			i += 2
		default:
			out = append(out, s[i])
			i++
		}
	}
	return "", errAt(len(s), "unterminated string")
}

// The directions a Suricata 8 option may name.
const (
	ToClient = "to_client"
	ToServer = "to_server"
)

// ParseDirection decodes a direction: to_client, to_server, or the empty
// string for none.
func ParseDirection(s string) (string, error) {
	switch s {
	case "", ToClient, ToServer:
		return s, nil
	}
	return "", errAt(0, `expected "to_client" or "to_server"`)
}

// CutDirection splits the direction off the start of a value of a
// Directional keyword the way Suricata 8 does: "to_client" or
// "to_server", then either nothing or a ',' and the rest of the value,
// blanks allowed around the comma. It returns the direction, the rest and
// the offset of the rest in s, with ok false (and s whole as the rest)
// when s does not start with a direction followed by nothing or a ','.
func CutDirection(s string) (dir, rest string, off int, ok bool) {
	for _, d := range []string{ToClient, ToServer} {
		if !strings.HasPrefix(s, d) {
			continue
		}
		i := skipBlanks(s, len(d))
		if i == len(s) {
			return d, "", i, true
		}
		if s[i] != ',' {
			break
		}
		i = skipBlanks(s, i+1)
		return d, s[i:], i, true
	}
	return "", s, 0, false
}

// ParseIdent decodes an identifier: one or more letters, digits, '_', '.'
// or '-'.
func ParseIdent(s string) (string, error) {
	if s == "" {
		return "", errAt(0, "expected an identifier")
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isLetter(c) && !isDigit(c) && c != '_' && c != '.' && c != '-' {
			return "", errAt(i, fmt.Sprintf("invalid character %q in identifier", c))
		}
	}
	return s, nil
}

// ParseCSV decodes a comma-separated list: the items trimmed of blanks,
// none of them empty.
func ParseCSV(s string) ([]string, error) {
	var items []string
	for _, p := range splitComma(s) {
		p = trim(p)
		if p.text == "" {
			return nil, errAt(p.off, "empty list item")
		}
		items = append(items, p.text)
	}
	return items, nil
}

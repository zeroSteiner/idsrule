package value

import "strings"

// Reference is a decoded reference value.
type Reference struct {
	// Scheme is the reference system: "cve", "url", "bugtraq".
	Scheme string
	// ID is the identifier within the system.
	ID string
}

// ParseReference decodes a reference value: a scheme of letters, digits and
// '_', a ',', and a non-empty id. The value is split on the first comma
// only, so an id may contain commas. Blanks around both parts are allowed.
func ParseReference(s string) (Reference, error) {
	comma := strings.IndexByte(s, ',')
	if comma < 0 {
		return Reference{}, errAt(len(s), "expected ','")
	}
	scheme := trim(part{s[:comma], 0})
	if scheme.text == "" {
		return Reference{}, errAt(scheme.off, "expected a reference scheme")
	}
	for i := 0; i < len(scheme.text); i++ {
		if c := scheme.text[i]; !isLetter(c) && !isDigit(c) && c != '_' {
			return Reference{}, errAt(scheme.off+i, "invalid character in reference scheme")
		}
	}
	id := trim(part{s[comma+1:], comma + 1})
	if id.text == "" {
		return Reference{}, errAt(id.off, "expected a reference id")
	}
	return Reference{Scheme: scheme.text, ID: id.text}, nil
}

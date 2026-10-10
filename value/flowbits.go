package value

import "fmt"

// Flowbits is a decoded flowbits value.
type Flowbits struct {
	// Verb is the operation: set, setx, unset, toggle, isset, isnotset,
	// noalert or reset.
	Verb string
	// Names are the flowbit names, more than one when written "a|b".
	Names []string
	// Group is the optional Snort flowbit group after the names.
	Group string
}

// flowbitsVerbs says for each verb whether it takes names: true means it
// must, false means it may not. reset, which may or may not, is handled
// apart.
var flowbitsVerbs = map[string]bool{
	"set":      true,
	"setx":     true,
	"unset":    true,
	"toggle":   true,
	"isset":    true,
	"isnotset": true,
	"noalert":  false,
}

// ParseFlowbits decodes a flowbits value: a verb, then for every verb but
// noalert a ',' and one or more names separated by '|', then optionally a
// ',' and a group name. Blanks around every piece are allowed. The verbs
// are set, unset, toggle, isset, isnotset and noalert, and Snort's setx and
// reset; reset alone takes an optional name.
func ParseFlowbits(s string) (Flowbits, error) {
	parts := splitComma(s)
	verb := trim(parts[0])
	if verb.text == "" {
		return Flowbits{}, errAt(verb.off, "expected a flowbits verb")
	}
	wantNames, known := flowbitsVerbs[verb.text]
	if !known && verb.text != "reset" {
		return Flowbits{}, errAt(verb.off, fmt.Sprintf("unknown flowbits verb %q", verb.text))
	}
	f := Flowbits{Verb: verb.text}
	if len(parts) == 1 {
		if wantNames {
			return Flowbits{}, errAt(len(s), "expected a flowbit name")
		}
		return f, nil
	}
	if known && !wantNames {
		return Flowbits{}, errAt(parts[1].off-1, fmt.Sprintf("%s takes no name", verb.text))
	}
	names := parts[1]
	start := 0
	for i := 0; i <= len(names.text); i++ {
		if i < len(names.text) && names.text[i] != '|' {
			continue
		}
		n := trim(part{names.text[start:i], names.off + start})
		if n.text == "" {
			return Flowbits{}, errAt(n.off, "expected a flowbit name")
		}
		f.Names = append(f.Names, n.text)
		start = i + 1
	}
	if len(parts) > 2 {
		group := trim(parts[2])
		if group.text == "" {
			return Flowbits{}, errAt(group.off, "expected a group name")
		}
		f.Group = group.text
	}
	if len(parts) > 3 {
		return Flowbits{}, errAt(parts[3].off-1, "unexpected ','")
	}
	return f, nil
}

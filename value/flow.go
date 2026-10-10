package value

import (
	"fmt"
	"strings"
)

// Flow is a decoded flow value.
type Flow struct {
	// Tokens are the flow tokens in the order written.
	Tokens []string
}

// flowGroups maps every flow token to the group of tokens it excludes:
// only one token of each group may be given.
var flowGroups = map[string]string{
	"established":     "state",
	"not_established": "state",
	"stateless":       "state",
	"to_client":       "direction",
	"from_server":     "direction",
	"to_server":       "direction",
	"from_client":     "direction",
	"only_stream":     "stream",
	"no_stream":       "stream",
	"only_frag":       "frag",
	"no_frag":         "frag",
}

// ParseFlow decodes a flow value: a comma-separated list of established,
// not_established, stateless, to_client, to_server, from_client,
// from_server, only_stream, no_stream, only_frag and no_frag, with blanks
// around the tokens allowed. The tokens are matched without regard to case,
// as Suricata does, and returned as written. An unknown or empty token, a
// repeated token and two tokens that contradict each other (to_client and
// to_server, established and stateless) are errors.
func ParseFlow(s string) (Flow, error) {
	var f Flow
	seen := make(map[string]string)
	written := map[string]string{}
	for _, p := range splitComma(s) {
		p = trim(p)
		if p.text == "" {
			return Flow{}, errAt(p.off, "expected a flow token")
		}
		token := strings.ToLower(p.text)
		group, ok := flowGroups[token]
		if !ok {
			return Flow{}, errAt(p.off, fmt.Sprintf("unknown flow token %q", p.text))
		}
		if prev, dup := seen[group]; dup {
			if prev == token {
				return Flow{}, errAt(p.off, fmt.Sprintf("duplicate flow token %q", p.text))
			}
			return Flow{}, errAt(p.off, fmt.Sprintf("flow token %q contradicts %q", p.text, written[group]))
		}
		seen[group] = token
		written[group] = p.text
		f.Tokens = append(f.Tokens, p.text)
	}
	return f, nil
}

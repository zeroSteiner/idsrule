package check

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/token"
)

func init() {
	Register(Check{
		ID:           "header-invalid-action",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "the rule action is not one of the dialect's or the release's, has a scope the action does not take, or breaks the rules for firewall actions (see Policy.Firewall)",
		Run:          checkHeaderInvalidAction,
	})
	Register(Check{
		ID:           "header-invalid-protocol",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "the protocol is not one of the dialect's or the release's names (compared without regard to case; protocol numbers are not accepted), or has a hook it cannot take",
		Run:          checkHeaderInvalidProtocol,
	})
	Register(Check{
		ID:           "header-invalid-direction",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "the direction is \"=>\" where it is not allowed: in Snort 2.9, in Suricata before 8.0, or in a firewall rule",
		Run:          checkHeaderInvalidDirection,
	})
	Register(Check{
		ID:       "header-invalid-address",
		Severity: diag.SeverityError,
		Doc:      "an address is not any, a $variable, an IP literal with an optional /prefix, or a list of those, or is a list without brackets in Snort 2.9 (a group the parser rejected is left to its syntax diagnostic)",
		Run:      checkHeaderInvalidAddress,
	})
	Register(Check{
		ID:       "header-invalid-port",
		Severity: diag.SeverityError,
		Doc:      "a port is not any, a $variable, a number, a range of 0 to 65535, or a list of those, or is a list without brackets in Snort 2.9 (a group the parser rejected is left to its syntax diagnostic)",
		Run:      checkHeaderInvalidPort,
	})
}

// actionScopes are the scopes each Suricata 8 action takes after a ':'.
var actionScopes = map[string][]string{
	"drop":   {"packet", "flow"},
	"pass":   {"packet", "flow"},
	"config": {"packet"},
	"accept": {"packet", "flow", "tx", "hook"},
}

// firewallFirstActions are the actions a firewall rule may start with, and
// firewallLaterActions the ones that may follow.
var (
	firewallFirstActions = []string{"accept", "config", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth"}
	firewallLaterActions = []string{"alert", "pass"}
)

// firewall reports whether the context's rules are Suricata firewall rules:
// Policy.Firewall is set for a Suricata file, and the release, if one is
// set, has firewall rules.
func (c *Context) firewall() bool {
	return c.Dialect == dialect.Suricata && c.Policy.Firewall && !c.before(dialect.Suricata8)
}

func checkHeaderInvalidAction(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		h := r.Header
		if h == nil || h.Action.Kind != token.Word {
			continue
		}
		if len(h.MoreActions) > 0 && !ctx.firewall() {
			ctx.Report(h.MoreActions[0].Span(), "only a Suricata firewall rule lists several actions")
		}
		scope := ""
		reported := len(ctx.out)
		for i, a := range append([]token.Token{h.Action}, h.MoreActions...) {
			name, sc, hasScope := strings.Cut(a.Lit, ":")
			name = strings.ToLower(name)
			if !checkAction(ctx, a, name, sc, hasScope) || !ctx.firewall() {
				continue
			}
			switch {
			case i == 0 && !slices.Contains(firewallFirstActions, name):
				ctx.Report(a.Span(), "a firewall rule starts with accept, config, drop or reject, not %q", name)
			case i > 0 && !slices.Contains(firewallLaterActions, name):
				ctx.Report(a.Span(), "only alert or pass may follow a firewall rule's first action, not %q", name)
			case i > 0 && name == "pass" && !strings.EqualFold(strings.SplitN(h.Action.Lit, ":", 2)[0], "accept"):
				ctx.Report(a.Span(), "pass follows only accept in a firewall rule")
			case name == "pass" && !hasScope && scope != "" && !slices.Contains(actionScopes["pass"], scope):
				ctx.Report(a.Span(), "pass inherits the scope %q, which it does not take; use packet or flow", scope)
			case hasScope && scope != "" && sc != scope:
				ctx.Report(a.Span(), "the actions of a firewall rule share one scope; %q differs from %q", sc, scope)
			case hasScope:
				scope = sc
			}
		}
		if ctx.firewall() && scope == "" && len(ctx.out) == reported {
			ctx.Report(h.Action.Span(), "a firewall rule needs an action scope, such as %q", h.Action.Lit+":packet")
		}
	}
}

// checkAction reports what is wrong with one action, name:scope, and
// reports whether it is otherwise valid: a known action of the release,
// accept only in a firewall rule, and a scope the action takes.
func checkAction(ctx *Context, a token.Token, name, scope string, hasScope bool) bool {
	switch {
	case !ctx.Dialect.IsAction(name):
		ctx.Report(a.Span(), "%q is not a %s action", name, ctx.Dialect)
	case ctx.before(ctx.Dialect.ActionAdded(name)):
		ctx.Report(a.Span(), "%q requires %s %s or later", name, ctx.Dialect, ctx.Dialect.ActionAdded(name))
	case name == "accept" && !ctx.Policy.Firewall:
		ctx.Report(a.Span(), "accept is only valid in firewall rules (Policy.Firewall)")
	case !hasScope:
		return true
	case ctx.Dialect != dialect.Suricata:
		ctx.Report(a.Span(), "%s actions take no scope", ctx.Dialect)
	case ctx.before(dialect.Suricata8):
		ctx.Report(a.Span(), "action scopes require %s %s or later", ctx.Dialect, dialect.Suricata8)
	case len(actionScopes[name]) == 0:
		ctx.Report(a.Span(), "%s takes no scope", name)
	case !slices.Contains(actionScopes[name], scope):
		ctx.Report(a.Span(), "%s takes the scope %s, not %q", name, strings.Join(actionScopes[name], ", "), scope)
	default:
		return true
	}
	return false
}

// packetHooks are the hooks that follow a network or transport protocol,
// and appHooks the generic ones that follow any application-layer
// protocol; an application-layer protocol also takes the name of one of
// its progress states ("http1:request_line").
var (
	packetHooks = []string{"flow_start", "pre_flow", "pre_stream", "all"}
	appHooks    = []string{"request_started", "request_complete", "response_started", "response_complete"}
)

func checkHeaderInvalidProtocol(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		if r.Header == nil || r.Header.Proto.Kind != token.Word {
			continue
		}
		p := r.Header.Proto
		name, hook, hasHook := strings.Cut(p.Lit, ":")
		switch {
		case !ctx.Dialect.IsProtocol(name):
			ctx.Report(p.Span(), "%q is not a %s protocol", name, ctx.Dialect)
			continue
		case ctx.before(ctx.Dialect.ProtocolAdded(name)):
			ctx.Report(p.Span(), "%q requires %s %s or later", name, ctx.Dialect, ctx.Dialect.ProtocolAdded(name))
			continue
		case !hasHook:
			continue
		}
		switch {
		case ctx.Dialect != dialect.Suricata:
			ctx.Report(p.Span(), "%s protocols take no hook", ctx.Dialect)
		case ctx.before(dialect.Suricata8):
			ctx.Report(p.Span(), "protocol hooks require %s %s or later", ctx.Dialect, dialect.Suricata8)
		case ctx.Dialect.IsPacketProtocol(name):
			if !slices.Contains(packetHooks, hook) {
				ctx.Report(p.Span(), "%q is not a packet hook; use %s", hook, strings.Join(packetHooks, ", "))
			}
		default:
			// "<" asks for the hook and the ones before it.
			if state := strings.TrimPrefix(hook, "<"); !isHookName(state) {
				ctx.Report(p.Span(), "%q is not a hook: use %s or a progress state of %s", hook, strings.Join(appHooks, ", "), name)
			}
		}
	}
}

// isHookName reports whether s can name an application-layer hook: a
// non-empty run of lower-case letters, digits and '_'.
func isHookName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

func checkHeaderInvalidDirection(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		if r.Header == nil || r.Header.Dir.Lit != "=>" {
			continue
		}
		d := r.Header.Dir
		switch {
		case ctx.Dialect != dialect.Suricata:
			ctx.Report(d.Span(), "%s has no \"=>\" direction", ctx.Dialect)
		case ctx.before(dialect.Suricata8):
			ctx.Report(d.Span(), "transactional \"=>\" rules require %s %s or later", ctx.Dialect, dialect.Suricata8)
		case ctx.firewall():
			ctx.Report(d.Span(), "a firewall rule cannot be a transactional \"=>\" rule")
		}
	}
}

// isVariable reports whether s is a $NAME variable reference.
func isVariable(s string) bool {
	if len(s) < 2 || s[0] != '$' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isVariableByte(s[i]) {
			return false
		}
	}
	return true
}

// isVariableByte reports whether c may appear in a variable name after
// the '$': a letter, a digit or '_'.
func isVariableByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// isAny reports whether s is the word any, in any case.
func isAny(s string) bool { return strings.EqualFold(s, "any") }

// isAddress reports whether s is a valid address word: any, a variable,
// or an IPv4 or IPv6 literal with an optional /prefix.
func isAddress(s string) bool {
	if isAny(s) || isVariable(s) {
		return true
	}
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// isPortNumber reports whether s is a decimal port number.
func isPortNumber(s string) bool {
	n, err := strconv.ParseUint(s, 10, 16)
	return err == nil && n <= 65535 && s == strconv.FormatUint(n, 10)
}

// isPort reports whether s is a valid port word: any, a variable, a
// number, or a range N:M (N <= M), N: or :M.
func isPort(s string) bool {
	if isAny(s) || isVariable(s) {
		return true
	}
	lo, hi, isRange := strings.Cut(s, ":")
	if !isRange {
		return isPortNumber(s)
	}
	if lo == "" && hi == "" || lo != "" && !isPortNumber(lo) || hi != "" && !isPortNumber(hi) {
		return false
	}
	if lo != "" && hi != "" {
		l, _ := strconv.Atoi(lo)
		h, _ := strconv.Atoi(hi)
		return l <= h
	}
	return true
}

// checkGroup reports every word of g, lists descended, that valid rejects.
// Missing words are skipped, and so is a group that did not parse: the
// parser has reported that already.
func checkGroup(ctx *Context, g *cst.Group, what string, valid func(string) bool) {
	switch {
	case g == nil, len(g.Bad) > 0:
	case g.List != nil:
		if !g.List.Bracketed() && ctx.Dialect == dialect.Snort2 {
			ctx.Report(g.Span(), "snort2 needs brackets around a list: [%s]", g.Text())
		}
		for _, item := range g.List.Items {
			checkGroup(ctx, item, what, valid)
		}
	case g.Word != nil && g.Word.Kind != token.Missing:
		if !valid(g.Word.Lit) {
			ctx.Report(g.Word.Span(), "invalid %s %q", what, g.Word.Lit)
		}
	}
}

func checkHeaderInvalidAddress(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		if r.Header == nil {
			continue
		}
		checkGroup(ctx, r.Header.Src, "address", isAddress)
		checkGroup(ctx, r.Header.Dst, "address", isAddress)
	}
}

func checkHeaderInvalidPort(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		if r.Header == nil {
			continue
		}
		checkGroup(ctx, r.Header.SrcPort, "port", isPort)
		checkGroup(ctx, r.Header.DstPort, "port", isPort)
	}
}

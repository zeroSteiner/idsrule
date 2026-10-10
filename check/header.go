package check

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/token"
)

func init() {
	Register(Check{
		ID:           "header-invalid-action",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "the rule action is not one of the dialect's",
		Run:          checkHeaderInvalidAction,
	})
	Register(Check{
		ID:           "header-invalid-protocol",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "the protocol is not one of the dialect's names (compared without regard to case; protocol numbers are not accepted)",
		Run:          checkHeaderInvalidProtocol,
	})
	Register(Check{
		ID:       "header-invalid-address",
		Severity: diag.SeverityError,
		Doc:      "an address is not any, a $variable, an IP literal with an optional /prefix, or a list of those (a group the parser rejected is left to its syntax diagnostic)",
		Run:      checkHeaderInvalidAddress,
	})
	Register(Check{
		ID:       "header-invalid-port",
		Severity: diag.SeverityError,
		Doc:      "a port is not any, a $variable, a number, a range of 0 to 65535, or a list of those (a group the parser rejected is left to its syntax diagnostic)",
		Run:      checkHeaderInvalidPort,
	})
}

func checkHeaderInvalidAction(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		if r.Header == nil || r.Header.Action.Kind != token.Word {
			continue
		}
		if a := r.Header.Action; !ctx.Dialect.IsAction(a.Lit) {
			ctx.Report(a.Span(), "%q is not a %s action", a.Lit, ctx.Dialect)
		}
	}
}

func checkHeaderInvalidProtocol(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		if r.Header == nil || r.Header.Proto.Kind != token.Word {
			continue
		}
		if p := r.Header.Proto; !ctx.Dialect.IsProtocol(p.Lit) {
			ctx.Report(p.Span(), "%q is not a %s protocol", p.Lit, ctx.Dialect)
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

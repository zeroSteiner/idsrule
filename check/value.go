package check

import (
	"errors"
	"math"
	"strings"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/value"
)

func init() {
	Register(Check{
		ID:           "value-invalid",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "an option has a value it must not, lacks one it needs, or has one its keyword does not accept (sid 0 included: an error in Suricata, a warning in Snort 2)",
		Run:          checkValueInvalid,
	})
	Register(Check{
		ID:           "value-unescaped-quote",
		Severity:     diag.SeverityWarning,
		NeedsDialect: true,
		Doc:          "a content or pcre value contains an odd number of unescaped double quotes",
		Run:          checkValueUnescapedQuote,
	})
}

func checkValueInvalid(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.Options() {
			k, ok := ctx.Keyword(o)
			if !ok {
				continue
			}
			switch {
			case k.Value == dialect.NoValue && o.HasValue():
				ctx.Report(o.ValueSpan(), "%s takes no value", k.Name)
			case k.Value == dialect.Required && !o.HasValue():
				ctx.Report(o.Keyword.Span(), "%s requires a value", k.Name)
			case o.HasValue():
				checkValue(ctx, o, k)
			}
		}
	}
}

// checkValue decodes the value of o as k's kind and reports what is wrong
// with it. An empty value is left to the parser's syntax-missing-value.
func checkValue(ctx *Context, o *cst.Option, k dialect.Keyword) {
	logical, _ := o.LogicalValue()
	if logical == "" {
		return
	}
	if k.Kind == dialect.KindDirection && ctx.before(dialect.Suricata8) {
		ctx.Report(o.ValueSpan(), "%s takes no value in %s %s; a direction requires %s", k.Name, ctx.Dialect, ctx.Version, dialect.Suricata8)
		return
	}
	// text is the value after a leading direction, at offset off in
	// logical.
	text, off := logical, 0
	if k.Directional {
		if _, rest, n, ok := value.CutDirection(logical); ok {
			if ctx.before(dialect.Suricata8) {
				ctx.Report(o.ValueSpan(), "%s: a direction requires %s %s or later", k.Name, ctx.Dialect, dialect.Suricata8)
				return
			}
			text, off = rest, n
		}
	}
	err := value.Validate(k.Kind, text)
	var ve *value.Error
	switch {
	case errors.As(err, &ve):
		d := ctx.Report(ctx.ValueSpanAt(o, off+ve.Off), "%s: %s", k.Name, ve.Msg)
		if k.Kind == dialect.KindMetadata && strings.Contains(ve.Msg, "empty") {
			// Suricata skips an empty metadata entry rather than
			// rejecting the rule.
			d.Severity = diag.SeverityWarning
		}
		return
	case err != nil:
		ctx.Report(o.ValueSpan(), "%s: %v", k.Name, err)
		return
	}
	checkIntegerForms(ctx, o, k, text)
	switch k.Name {
	case "file_data":
		// The table cannot give file_data one kind: its value is mime in
		// Snort 2.9 and a direction in Suricata 8.
		switch {
		case ctx.Dialect == dialect.Snort2 && logical != "mime":
			ctx.Report(o.ValueSpan(), `file_data: expected "mime"`)
		case ctx.Dialect != dialect.Suricata:
		case ctx.before(dialect.Suricata8):
			ctx.Report(o.ValueSpan(), "file_data takes no value in %s %s; a direction requires %s", ctx.Dialect, ctx.Version, dialect.Suricata8)
		default:
			if _, err := value.ParseDirection(logical); err != nil {
				ctx.Report(o.ValueSpan(), `file_data: expected "to_client" or "to_server"`)
			}
		}
	case "threshold":
		t, err := value.ParseThreshold(logical)
		// What Suricata 8 added: type backoff and the multiplier key.
		added := "type backoff"
		if t.Type != "backoff" {
			added = "multiplier"
		}
		switch {
		case err != nil:
		case !t.HasType:
			ctx.Report(o.ValueSpan(), "threshold requires type")
		case t.Type != "backoff" && !t.HasMultiplier:
		case ctx.Dialect != dialect.Suricata:
			ctx.Report(o.ValueSpan(), "threshold: %s has no %s", ctx.Dialect, added)
		case ctx.before(dialect.Suricata8):
			ctx.Report(o.ValueSpan(), "threshold: %s requires %s %s or later", added, ctx.Dialect, dialect.Suricata8)
		}
	case "id", "icmp_id", "icmp_seq":
		if ctx.Dialect == dialect.Snort2 && strings.Contains(logical, `"`) {
			ctx.Report(o.ValueSpan(), "%s: snort2 reads the number without quotes", k.Name)
		}
	case "rfb.secresult":
		// Suricata 7 reads only the names.
		if e, err := value.ParseUintEnum(logical); err == nil && ctx.before(dialect.Suricata8) && (e.Name == "" || e.Negated) {
			ctx.Report(o.ValueSpan(), "rfb.secresult takes ok, fail, toomany or unknown in %s %s", ctx.Dialect, ctx.Version)
		}
	case "sid":
		// Suricata refuses to load a rule with sid 0; Snort 2.9 only
		// reserves the low numbers.
		if n, err := value.ParseUint(logical); err == nil && n == 0 {
			d := ctx.Report(o.ValueSpan(), "sid must be at least 1")
			if ctx.Dialect != dialect.Suricata {
				d.Severity = diag.SeverityWarning
			}
		}
	}
}

// checkIntegerForms reports a valid integer value that uses forms the
// dialect or release does not read: any of Suricata's in Snort 2.9, and
// Suricata 8's in Suricata 7.
func checkIntegerForms(ctx *Context, o *cst.Option, k dialect.Keyword, text string) {
	var r value.RelInt
	switch k.Kind {
	case dialect.KindRelInt:
		r, _ = value.ParseRelInt(text)
	case dialect.KindUrilen:
		u, _ := value.ParseUrilen(text)
		r = u.RelInt
	case dialect.KindUintEnum:
		e, _ := value.ParseUintEnum(text)
		if e.Name != "" {
			return
		}
		r = e.RelInt
	case dialect.KindNone, dialect.KindUint, dialect.KindIntOrVar, dialect.KindQuoted,
		dialect.KindIdent, dialect.KindContent, dialect.KindPCRE, dialect.KindFlow,
		dialect.KindFlowbits, dialect.KindReference, dialect.KindMetadata, dialect.KindThreshold,
		dialect.KindBase64Decode, dialect.KindFastPattern, dialect.KindIsDataAt, dialect.KindCSV,
		dialect.KindDirection, dialect.KindTos, dialect.KindQuotedUint, dialect.KindRaw:
		return
	}
	switch {
	case ctx.Dialect == dialect.Snort2 && r.Forms != 0:
		ctx.Report(o.ValueSpan(), "%s: %s is Suricata syntax, which snort2 does not read", k.Name, describeForm(r.Forms))
	case ctx.Dialect == dialect.Suricata && k.Bits == 0 && r.Forms != 0:
		// Suricata reads such a keyword with a parser of its own, which
		// knows only plain decimal numbers.
		ctx.Report(o.ValueSpan(), "%s: %s is not read by Suricata for %s", k.Name, describeForm(r.Forms), k.Name)
	case ctx.before(dialect.Suricata8) && !r.Suricata7():
		form := describeForm(r.Forms &^ value.FormUnit)
		if r.Forms&^value.FormUnit == 0 {
			form = "a size unit on a comparison or a range"
		}
		ctx.Report(o.ValueSpan(), "%s: %s requires %s %s or later", k.Name, form, ctx.Dialect, dialect.Suricata8)
	case ctx.Dialect == dialect.Suricata && k.Bits != 0:
		checkSuricataUint(ctx, o, k, r)
	}
}

// checkSuricataUint reports what Suricata's integer parser refuses in a
// value it reads into a k.Bits-bit integer: a number too large for it, a
// range with no number strictly between its bounds (Suricata's ranges
// exclude them), and a comparison no number satisfies.
func checkSuricataUint(ctx *Context, o *cst.Option, k dialect.Keyword, r value.RelInt) {
	limit := uint64(math.MaxUint64)
	if k.Bits < 64 {
		limit = 1<<k.Bits - 1
	}
	for _, n := range []uint64{r.A, r.B} {
		if n > limit {
			ctx.Report(o.ValueSpan(), "%s: %d does not fit in %d bits (at most %d)", k.Name, n, k.Bits, limit)
			return
		}
	}
	switch r.Op {
	case "-", "<>", "!-", "!<>":
		if r.B-r.A < 2 {
			ctx.Report(o.ValueSpan(), "%s: no number lies strictly between %d and %d, and Suricata's ranges exclude their bounds", k.Name, r.A, r.B)
		}
	case "<", ">=":
		if r.A == 0 {
			ctx.Report(o.ValueSpan(), "%s: %s0 compares with the smallest number, so it is never or always true; Suricata refuses it", k.Name, r.Op)
		}
	case ">", "<=":
		if r.A == limit {
			ctx.Report(o.ValueSpan(), "%s: %s%d compares with the largest %d-bit number, so it is never or always true; Suricata refuses it", k.Name, r.Op, limit, k.Bits)
		}
	}
}

// describeForm names the first of forms, for a message.
func describeForm(forms value.RelIntForm) string {
	switch {
	case forms&value.FormBitmask != 0:
		return "a bitmask test"
	case forms&value.FormNegatedRange != 0:
		return "a negated range"
	case forms&value.FormHex != 0:
		return "a hex number"
	case forms&value.FormIECUnit != 0:
		return "a kib, mib or gib unit"
	}
	return "a size unit"
}

// unescapedQuotes counts the '"' bytes of s that are not the second byte
// of a backslash escape pair.
func unescapedQuotes(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			n++
		}
	}
	return n
}

func checkValueUnescapedQuote(ctx *Context) {
	for _, r := range ctx.Tree.Rules() {
		for _, o := range r.Options() {
			k, ok := ctx.Keyword(o)
			if !ok || !o.HasValue() || (k.Kind != dialect.KindContent && k.Kind != dialect.KindPCRE) {
				continue
			}
			logical, _ := o.LogicalValue()
			if value.Validate(k.Kind, logical) != nil {
				// value-invalid reports it.
				continue
			}
			if unescapedQuotes(logical)%2 == 1 {
				ctx.Report(o.ValueSpan(), `%s value contains an unescaped '"'; a literal quote is written \"`, k.Name)
			}
		}
	}
}

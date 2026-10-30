package check

import (
	"encoding/hex"
	"errors"

	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/value"
)

func init() {
	Register(Check{
		ID:           "content-md5-invalid",
		Severity:     diag.SeverityError,
		NeedsDialect: true,
		Doc:          "a content in a Suricata MD5 buffer (ja3.hash, ja3s.hash, ssh.hassh, ssh.hassh.server, quic.cyu.hash) is not 32 bytes, which Suricata refuses, or not all hex digits, which never matches and which Suricata 8 refuses (a warning before 8.0 or with no release set)",
		Run:          checkContentMD5,
	})
}

// md5Buffers are the Suricata sticky buffers that hold an MD5 as 32 hex
// digits, by every name they go by.
var md5Buffers = map[string]bool{
	"ja3.hash": true, "ja3_hash": true, "ja3s.hash": true,
	"ssh.hassh": true, "ssh-hassh": true, "ssh.hassh.server": true, "ssh-hassh-server": true,
	"quic.cyu.hash": true,
}

func checkContentMD5(ctx *Context) {
	if ctx.Dialect != dialect.Suricata {
		return
	}
	for _, r := range ctx.Tree.Rules() {
		buffer := ""
		for _, o := range r.Options() {
			k, ok := ctx.Keyword(o)
			switch {
			case !ok:
			case k.Role == dialect.RoleStickyBuffer:
				buffer = k.Name
			case k.Role == dialect.RoleTransform:
				// A transformed buffer is a different buffer, which
				// Suricata does not hold to the MD5 shape.
				buffer = ""
			case k.Name == "content" && md5Buffers[buffer]:
				logical, _ := o.LogicalValue()
				c, err := value.ParseContent(logical)
				if err != nil {
					continue // value-invalid reports it
				}
				if len(c.Pattern) != 32 {
					ctx.Report(o.ValueSpan(), "%s content is %d bytes; an MD5 is 32 hex digits, so Suricata refuses the rule", buffer, len(c.Pattern))
					continue
				}
				var bad hex.InvalidByteError
				if _, err := hex.DecodeString(string(c.Pattern)); errors.As(err, &bad) {
					d := ctx.Report(o.ValueSpan(), "%s content has %q, not a hex digit; it never matches, and Suricata 8 refuses the rule", buffer, rune(bad))
					if !ctx.at(dialect.Suricata8) {
						d.Severity = diag.SeverityWarning
					}
				}
			}
		}
	}
}

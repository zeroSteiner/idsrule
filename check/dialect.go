package check

import "github.com/zeroSteiner/idsrule/diag"

// DialectUnknownID is the id of the diagnostic [Run] emits when it skipped
// checks because the Context's Dialect is Unknown. It is registered as a
// check so that a Selection can disable it or change its severity; the
// check itself reports nothing, Run does.
const DialectUnknownID = "dialect-unknown"

func init() {
	Register(Check{
		ID:       DialectUnknownID,
		Severity: diag.SeverityWarning,
		Doc:      "the dialect is unknown, so the checks that need one were skipped",
		Run:      func(*Context) {},
	})
}

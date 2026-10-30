package check

import (
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/source"
)

// Context is what a check sees for one file: the parsed tree, where it
// came from, the dialect it is written in, the policy it is held to and
// the SID index shared with the other files of the rule set.
type Context struct {
	// File is the name the file was parsed under; diagnostics carry it.
	File string
	// Src is the complete source.
	Src []byte
	// Tree is the parsed file.
	Tree *cst.File
	// Lines is the line table of Src. Run fills it from Tree when nil.
	Lines *source.LineTable
	// Dialect is the dialect the file is written in. A check with
	// NeedsDialect set never sees Unknown.
	Dialect dialect.Dialect
	// Version is the release of Dialect the rules are written for, or
	// dialect.AnyVersion to hold them to what any release accepts. It is
	// AnyVersion whenever Dialect has no such release.
	Version dialect.Version
	// Policy is what the rules are held to.
	Policy Policy
	// SIDs is the cross-file SID index, or nil when sids are only checked
	// within the file. [Run] records this file's sids in it (see
	// [Context.IndexSIDs]) before any check runs, whatever checks are
	// selected.
	SIDs *SIDIndex

	id       string        // the running check's id
	severity diag.Severity // the running check's default severity
	builder  diag.Builder
	out      []*diag.Diagnostic
}

// Report appends a diagnostic for the running check: its Rule is the
// check's id, its Severity the check's default, and its positions are
// resolved from span. The returned pointer is the diagnostic in the
// output, so the caller may set Related, Edits or a different Severity on
// that one finding.
func (c *Context) Report(span source.Span, format string, args ...any) *diag.Diagnostic {
	d := c.builder.New(c.id, c.severity, span, format, args...)
	p := &d
	c.out = append(c.out, p)
	return p
}

// Keyword looks up an option's keyword in the context's dialect, or in any
// dialect when the Dialect is Unknown. It ignores the Version: a keyword of
// the dialect is found whichever releases have it (keyword-version reports
// the ones that do not).
func (c *Context) Keyword(o *cst.Option) (dialect.Keyword, bool) {
	if c.Dialect == dialect.Unknown {
		return dialect.LookupAny(o.Name())
	}
	return dialect.Lookup(c.Dialect, o.Name())
}

// ValueSpanAt maps an offset into an option's logical value, as a
// [value.Error] carries it, to the one-byte source span of the byte it
// names, clamped to the value's span: an offset at or past the end of the
// value yields the empty span at the value's end.
func (c *Context) ValueSpanAt(o *cst.Option, logicalOff int) source.Span {
	_, at := o.LogicalValue()
	vs := o.ValueSpan()
	start := at(logicalOff)
	return source.Span{Start: start, End: min(start+1, vs.End)}
}

// before reports whether the context names a release of the dialect
// earlier than v. It is false for AnyVersion.
func (c *Context) before(v dialect.Version) bool {
	return c.Version != dialect.AnyVersion && c.Version < v
}

// IndexSIDs records the file's sids in c.SIDs: in one atomic step it
// forgets every entry the index holds for c.File and adds a SIDRef for the
// sid option of the first rule that declares each sid. Placeholder sids
// and sids that do not decode are left out, and a sid the file declares
// twice is indexed once. It does nothing when c.SIDs is nil.
//
// [Run] calls it before any check runs, whatever checks are selected, so
// the index is complete for the files linted after this one; the
// sid-duplicate check only reads the index, and skips the entries of its
// own file.
func (c *Context) IndexSIDs() {
	if c.SIDs == nil || c.Tree == nil {
		return
	}
	lines := c.Lines
	if lines == nil {
		lines = c.Tree.Lines()
	}
	refs := make(map[uint64]SIDRef)
	for _, r := range c.Tree.Rules() {
		sid, opt, ok := ruleSID(r)
		if !ok || isPlaceholder(c.Policy, sid) {
			continue
		}
		if _, dup := refs[sid]; dup {
			continue
		}
		p := lines.Position(opt.Span().Start)
		refs[sid] = SIDRef{File: c.File, Line: p.Line, Column: p.Column}
	}
	c.SIDs.Replace(c.File, refs)
}

// related returns a Related entry pointing at span in the context's file.
func (c *Context) related(span source.Span, msg string) diag.Related {
	p := c.Lines.Position(span.Start)
	return diag.Related{File: c.File, Line: p.Line, Column: p.Column, Message: msg}
}

// normalizeMsg canonicalizes a msg text with the policy's NormalizeMsg,
// or DefaultNormalizeMsg when it has none.
func (c *Context) normalizeMsg(s string) string {
	if c.Policy.NormalizeMsg != nil {
		return c.Policy.NormalizeMsg(s)
	}
	return DefaultNormalizeMsg(s)
}

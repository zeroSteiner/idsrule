package diag

import (
	"fmt"

	"github.com/zeroSteiner/idsrule/source"
)

// Builder creates diagnostics for one file, resolving spans to line/column
// positions through the file's line table.
type Builder struct {
	File  string
	Lines *source.LineTable // nil behaves like the table of an empty file
}

// New returns a diagnostic for span with the given check id and severity.
// The message is formatted with fmt.Sprintf; Line, Column and End are
// resolved from span through b.Lines.
func (b Builder) New(rule string, sev Severity, span source.Span, format string, args ...any) Diagnostic {
	d := Diagnostic{
		File:     b.File,
		Severity: sev,
		Rule:     rule,
		Message:  fmt.Sprintf(format, args...),
		Span:     span,
	}
	b.Resolve(&d)
	return d
}

// Resolve (re)computes d.Line, d.Column and d.End from d.Span, and sets
// d.File to b.File when it is empty.
func (b Builder) Resolve(d *Diagnostic) {
	if d.File == "" {
		d.File = b.File
	}
	start := b.Lines.Position(d.Span.Start)
	d.Line, d.Column = start.Line, start.Column
	d.End = b.Lines.Position(d.Span.End)
}

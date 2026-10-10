// Package source holds the primitives that every other package in the module
// shares when it talks about a rule file: byte spans, line/column positions,
// text edits and the line table that maps between offsets and positions.
//
// Everything in this package is expressed in bytes. Columns are byte columns,
// not rune or display columns, so a multi-byte UTF-8 character advances the
// column by more than one.
package source

// Span is a half-open byte range [Start, End) into a source document.
// A well-formed span has Start <= End.
type Span struct {
	Start, End int
}

// Len returns the number of bytes covered by s.
func (s Span) Len() int { return s.End - s.Start }

// Empty reports whether s covers no bytes.
func (s Span) Empty() bool { return s.End <= s.Start }

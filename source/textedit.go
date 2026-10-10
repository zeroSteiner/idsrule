package source

// TextEdit describes replacing the bytes covered by Span with NewText.
//
// An empty NewText deletes the span, and an empty Span inserts NewText at
// Span.Start. The zero value is therefore a no-op edit at offset 0.
type TextEdit struct {
	Span    Span
	NewText string
}

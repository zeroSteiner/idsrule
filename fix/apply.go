// Package fix applies text edits to a source document safely. Validate
// checks that a set of edits lies within the document and that no two of
// them overlap, and Apply builds the edited document in a single pass
// without modifying or aliasing the input.
package fix

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/zeroSteiner/idsrule/source"
)

// ErrOverlap is returned when two edits cover a common byte, or when an
// insertion falls strictly inside another edit.
var ErrOverlap = errors.New("fix: overlapping edits")

// ErrBounds is returned when an edit's span is not a well-formed range
// within the document.
var ErrBounds = errors.New("fix: edit out of bounds")

// sorted returns a copy of edits in (Start, End) order. The sort is stable,
// so edits with the same span keep their relative order.
func sorted(edits []source.TextEdit) []source.TextEdit {
	out := slices.Clone(edits)
	slices.SortStableFunc(out, func(a, b source.TextEdit) int {
		return cmp.Or(cmp.Compare(a.Span.Start, b.Span.Start), cmp.Compare(a.Span.End, b.Span.End))
	})
	return out
}

// validateSorted implements Validate for edits already in sorted order over
// a document of n bytes.
func validateSorted(n int, edits []source.TextEdit) error {
	for _, e := range edits {
		s := e.Span
		if s.Start < 0 || s.End < s.Start || s.End > n {
			return fmt.Errorf("%w: [%d,%d) in a document of %d bytes", ErrBounds, s.Start, s.End, n)
		}
	}
	for i := 1; i < len(edits); i++ {
		prev, cur := edits[i-1].Span, edits[i].Span
		if prev.End > cur.Start {
			return fmt.Errorf("%w: [%d,%d) and [%d,%d)", ErrOverlap, prev.Start, prev.End, cur.Start, cur.End)
		}
	}
	return nil
}

// Validate reports whether edits can be applied to src: every edit lies
// within [0, len(src)] with Start <= End, and no two edits overlap. Edits
// are considered in (Start, End) order; two edits overlap when the earlier
// one's End exceeds the later one's Start. A zero-width insertion at X
// before a replacement that starts at X is therefore allowed, and lands
// first. The error wraps [ErrBounds] or [ErrOverlap] and names the
// offending spans.
func Validate(src []byte, edits []source.TextEdit) error {
	return validateSorted(len(src), sorted(edits))
}

// Apply returns a new byte slice with edits applied to src. src is never
// modified or aliased: an empty edit list returns a copy of src. It fails
// as [Validate] does.
func Apply(src []byte, edits []source.TextEdit) ([]byte, error) {
	es := sorted(edits)
	if err := validateSorted(len(src), es); err != nil {
		return nil, err
	}
	size := len(src)
	for _, e := range es {
		size += len(e.NewText) - e.Span.Len()
	}
	out := make([]byte, 0, size)
	pos := 0
	for _, e := range es {
		out = append(out, src[pos:e.Span.Start]...)
		out = append(out, e.NewText...)
		pos = e.Span.End
	}
	return append(out, src[pos:]...), nil
}

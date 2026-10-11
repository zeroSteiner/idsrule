package idsrule

import (
	"cmp"
	"slices"
	"sort"

	"github.com/zeroSteiner/idsrule/fix"
	"github.com/zeroSteiner/idsrule/source"
)

// cmpEdit orders edits by (Start, End), the order [fix.Validate] considers
// them in.
func cmpEdit(a, b source.TextEdit) int {
	return cmp.Or(cmp.Compare(a.Span.Start, b.Span.Start), cmp.Compare(a.Span.End, b.Span.End))
}

// insertionPoint returns the index at which e belongs in the sorted
// accepted list: after every edit that orders before or equal to it.
func insertionPoint(accepted []source.TextEdit, e source.TextEdit) int {
	return sort.Search(len(accepted), func(i int) bool { return cmpEdit(accepted[i], e) > 0 })
}

// fits reports whether e overlaps no edit of the sorted accepted list, by
// the rule of [fix.Validate]: the accepted edit that would precede e must
// end at or before e starts, and e must end at or before the one that
// would follow it starts. The two neighbours are enough to check because
// the accepted edits are disjoint from each other.
func fits(accepted []source.TextEdit, e source.TextEdit) bool {
	i := insertionPoint(accepted, e)
	if i > 0 && accepted[i-1].Span.End > e.Span.Start {
		return false
	}
	return i == len(accepted) || e.Span.End <= accepted[i].Span.Start
}

// Fix applies the autofixes carried by diags to src. Diagnostics are taken
// in order; a diagnostic's edits are accepted only when every one of them
// is valid and disjoint from the edits already accepted (see
// [fix.Validate]), otherwise the whole diagnostic is skipped. applied
// counts the diagnostics whose edits were applied, and out is always a new
// slice, src itself untouched. Callers re-[Lint] the result to converge: a
// skipped diagnostic is normally fixable on the next pass, and a pass that
// applies nothing returns src unchanged.
//
// Fix expects diags in position order, as [Lint] returns them: an earlier
// diagnostic wins a conflict, and the accepted edits are kept in a sorted
// slice so the cost grows with N log N. A list in another order is handled
// by the same rule, but reordering changes which diagnostic wins and can
// cost quadratic time.
func Fix(src []byte, diags []Diagnostic) (out []byte, applied int, err error) {
	var accepted []source.TextEdit // every accepted edit, in (Start, End) order
	for _, d := range diags {
		// The diagnostic's own edits must be in bounds and disjoint from
		// each other, and every one of them must fit among the accepted
		// ones; only then are they all inserted.
		if !d.HasFix() || fix.Validate(src, d.Edits) != nil {
			continue
		}
		if slices.ContainsFunc(d.Edits, func(e source.TextEdit) bool { return !fits(accepted, e) }) {
			continue
		}
		for _, e := range d.Edits {
			accepted = slices.Insert(accepted, insertionPoint(accepted, e), e)
		}
		applied++
	}
	out, err = fix.Apply(src, accepted)
	if err != nil {
		return nil, 0, err
	}
	return out, applied, nil
}

package idsrule_test

import (
	"bytes"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/fix"
)

// te builds a TextEdit.
func te(start, end int, text string) idsrule.TextEdit {
	return idsrule.TextEdit{Span: idsrule.Span{Start: start, End: end}, NewText: text}
}

// fixable builds a diagnostic that carries edits.
func fixable(rule string, edits ...idsrule.TextEdit) idsrule.Diagnostic {
	return idsrule.Diagnostic{Rule: rule, Severity: idsrule.SeverityWarning, Edits: edits}
}

func TestFix_SkipsOverlapping(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		diags   []idsrule.Diagnostic
		want    string
		applied int
	}{
		{
			"second overlaps the first",
			"abcdef",
			[]idsrule.Diagnostic{fixable("a", te(1, 4, "X")), fixable("b", te(2, 5, "Y"))},
			"aXef", 1,
		},
		{
			"a skipped diagnostic does not block a later one",
			"abcdef",
			[]idsrule.Diagnostic{fixable("a", te(1, 4, "X")), fixable("b", te(2, 5, "Y")), fixable("c", te(5, 6, "Z"))},
			"aXeZ", 2,
		},
		{
			"one bad edit skips the whole diagnostic",
			"abcdef",
			[]idsrule.Diagnostic{fixable("a", te(0, 1, "A"), te(0, 9, "")), fixable("b", te(5, 6, "F"))},
			"abcdeF", 1,
		},
		{
			"an insertion before a replacement at the same offset is not an overlap",
			"abcdef",
			[]idsrule.Diagnostic{fixable("a", te(2, 4, "R")), fixable("b", te(2, 2, "I"))},
			"abIRef", 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, applied, err := idsrule.Fix([]byte(tt.src), tt.diags)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want || applied != tt.applied {
				t.Errorf("Fix() = %q, %d; want %q, %d", got, applied, tt.want, tt.applied)
			}
		})
	}
}

func TestFix_IgnoresNoEdits(t *testing.T) {
	src := []byte("abcdef")
	diags := []idsrule.Diagnostic{
		{Rule: "a", Severity: idsrule.SeverityError},
		{Rule: "b", Severity: idsrule.SeverityWarning, Edits: []idsrule.TextEdit{}},
	}
	for _, ds := range [][]idsrule.Diagnostic{nil, diags} {
		got, applied, err := idsrule.Fix(src, ds)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, src) || applied != 0 {
			t.Errorf("Fix(%v) = %q, %d; want %q, 0", ds, got, applied, src)
		}
	}
}

func TestFix_Pure(t *testing.T) {
	src := []byte("abcdef")
	diags := []idsrule.Diagnostic{fixable("a", te(0, 1, "A"))}
	first, _, err := idsrule.Fix(src, diags)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := idsrule.Fix(src, diags)
	if err != nil {
		t.Fatal(err)
	}
	if string(src) != "abcdef" {
		t.Errorf("Fix() modified src: %q", src)
	}
	if string(first) != "Abcdef" || !bytes.Equal(first, second) {
		t.Errorf("Fix() = %q then %q, want \"Abcdef\" both times", first, second)
	}
	if &first[0] == &src[0] {
		t.Error("Fix() returned a slice aliasing src")
	}
	first[1] = '!'
	if string(src) != "abcdef" || string(second) != "Abcdef" {
		t.Errorf("results share memory: src %q, second %q", src, second)
	}
}

func TestFix_Order(t *testing.T) {
	src := []byte("abcdef")
	forward := []idsrule.Diagnostic{fixable("a", te(0, 1, "A")), fixable("b", te(2, 3, "C")), fixable("c", te(5, 6, "F"))}
	backward := []idsrule.Diagnostic{forward[2], forward[1], forward[0]}
	for _, ds := range [][]idsrule.Diagnostic{forward, backward} {
		got, applied, err := idsrule.Fix(src, ds)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "AbCdeF" || applied != 3 {
			t.Errorf("Fix() = %q, %d; want \"AbCdeF\", 3", got, applied)
		}
	}
}

// raceSlowdown is the factor time budgets are scaled by under the race
// detector.
const raceSlowdown = 8

// budget returns d, or d scaled by raceSlowdown under the race detector.
func budget(d time.Duration) time.Duration {
	if raceEnabled {
		return d * raceSlowdown
	}
	return d
}

// timeFix runs Fix three times, two under the race detector, and returns
// the shortest run with its result.
func timeFix(t *testing.T, src []byte, diags []idsrule.Diagnostic) (time.Duration, []byte, int) {
	t.Helper()
	runs := 3
	if raceEnabled {
		runs = 2
	}
	var best time.Duration
	var out []byte
	var applied int
	for i := range runs {
		start := time.Now()
		o, n, err := idsrule.Fix(src, diags)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 || elapsed < best {
			best, out, applied = elapsed, o, n
		}
	}
	return best, out, applied
}

// scaleDiags returns n disjoint single-edit diagnostics in position order
// over a source of 2n bytes: the i-th replaces the "a" at offset 2i with
// "A".
func scaleDiags(n int) ([]byte, []idsrule.Diagnostic) {
	src := bytes.Repeat([]byte("ab"), n)
	diags := make([]idsrule.Diagnostic, n)
	for i := range diags {
		diags[i] = fixable("scale", te(2*i, 2*i+1, "A"))
	}
	return src, diags
}

// overlaps applies the rule of fix.Validate to one pair of edits: ordered
// by (Start, End), the earlier one must end at or before the later one
// starts.
func overlaps(a, b idsrule.TextEdit) bool {
	if a.Span.Start > b.Span.Start || (a.Span.Start == b.Span.Start && a.Span.End > b.Span.End) {
		a, b = b, a
	}
	return a.Span.End > b.Span.Start
}

// naiveFix is Fix with the acceptance rule applied pairwise: a candidate
// is accepted when none of its edits overlaps any accepted edit, every
// pair compared directly. It is quadratic and serves as the reference.
func naiveFix(t *testing.T, src []byte, diags []idsrule.Diagnostic) ([]byte, int) {
	t.Helper()
	var accepted []idsrule.TextEdit
	applied := 0
	for _, d := range diags {
		if !d.HasFix() || fix.Validate(src, d.Edits) != nil {
			continue
		}
		ok := true
		for _, e := range d.Edits {
			for _, a := range accepted {
				if overlaps(a, e) {
					ok = false
				}
			}
		}
		if !ok {
			continue
		}
		accepted = append(accepted, d.Edits...)
		applied++
	}
	out, err := fix.Apply(src, accepted)
	if err != nil {
		t.Fatal(err)
	}
	return out, applied
}

// TestScaleFix checks that Fix scales with N log N over the number of
// diagnostics: a hundred thousand single-edit diagnostics apply well
// within two seconds and cost no more than forty times ten thousand of
// them, and that on ten thousand shuffled diagnostics, overlapping ones
// among them, the result matches a pairwise reference.
func TestScaleFix(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped in -short mode")
	}

	src10k, diags10k := scaleDiags(10_000)
	src100k, diags100k := scaleDiags(100_000)
	time10k, out10k, applied10k := timeFix(t, src10k, diags10k)
	time100k, out100k, applied100k := timeFix(t, src100k, diags100k)
	t.Logf("10k diagnostics: %v, 100k diagnostics: %v", time10k, time100k)
	if applied10k != 10_000 || applied100k != 100_000 {
		t.Errorf("applied %d and %d diagnostics, want 10000 and 100000", applied10k, applied100k)
	}
	if want := bytes.Repeat([]byte("Ab"), 100_000); !bytes.Equal(out100k, want) || !bytes.Equal(out10k, want[:20_000]) {
		t.Error("Fix produced the wrong text")
	}
	if limit := budget(2 * time.Second); time100k > limit {
		t.Errorf("100k diagnostics took %v, want at most %v", time100k, limit)
	}
	// A run of a few milliseconds is mostly noise; the ratio is taken
	// against at least that.
	if floor := budget(2 * time.Millisecond); time100k > 40*max(time10k, floor) {
		t.Errorf("100k diagnostics took %v, more than 40 times the %v of 10k", time100k, time10k)
	}

	// Correctness against the pairwise reference: the disjoint set, an
	// overlapping diagnostic every seventh one and an insertion that
	// fits before every fifth one, in a random order.
	rng := rand.New(rand.NewPCG(3, 4))
	src, diags := scaleDiags(10_000)
	for i := 0; i < 10_000; i += 7 {
		diags = append(diags, fixable("overlap", te(2*i, 2*i+2, "Z")))
	}
	for i := 0; i < 10_000; i += 5 {
		diags = append(diags, fixable("insert", te(2*i, 2*i, "+")))
	}
	rng.Shuffle(len(diags), func(i, j int) { diags[i], diags[j] = diags[j], diags[i] })
	got, applied, err := idsrule.Fix(src, diags)
	if err != nil {
		t.Fatal(err)
	}
	want, wantApplied := naiveFix(t, src, diags)
	if applied != wantApplied || !bytes.Equal(got, want) {
		t.Errorf("Fix applied %d diagnostics, the reference %d; outputs equal: %t", applied, wantApplied, bytes.Equal(got, want))
	}
}

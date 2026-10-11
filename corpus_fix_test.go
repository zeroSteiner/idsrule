package idsrule_test

import (
	"bytes"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/internal/corpus"
)

// indexFor returns the SID index of a dialect, creating it on first use.
func indexFor(indexes map[idsrule.Dialect]*idsrule.SIDIndex, d idsrule.Dialect) *idsrule.SIDIndex {
	if indexes[d] == nil {
		indexes[d] = idsrule.NewSIDIndex()
	}
	return indexes[d]
}

// logicalValue returns the logical value of a rule's first option named
// name, or "<none>" when the rule has none.
func logicalValue(r *cst.Rule, name string) string {
	o := r.Option(name)
	if o == nil {
		return "<none>"
	}
	v, _ := o.LogicalValue()
	return v
}

// TestCorpusFixRoundTrip lints every corpus file with the style checks on,
// fixes it and checks that the result is still the same rule set: it
// parses without syntax diagnostics into the same number of rules, every
// rule keeps its msg and sid, nothing fixable is left, and a second Fix
// pass changes nothing.
func TestCorpusFixRoundTrip(t *testing.T) {
	files := corpus.Files(t)
	if len(files) == 0 {
		t.Fatal("corpus directory contains no *.rule files")
	}

	base := idsrule.DefaultOptions()
	base.Policy = idsrule.Policy{SIDMin: 12_900_000, SIDMax: 12_999_999, PlaceholderBelow: 12_900_000, RequireRev: true}
	// The style checks run with the space after a semicolon required, so
	// that the Snort 3 rewrite is held to the semicolon check too.
	base.Policy.Style.SpaceAfterSemicolon = idsrule.SpacingRequire
	base.Checks.Style = true
	before := make(map[idsrule.Dialect]*idsrule.SIDIndex)
	after := make(map[idsrule.Dialect]*idsrule.SIDIndex)

	fixed := make(map[string]int)
	nfixed, nremaining, nsyntax, nchanged := 0, 0, 0, 0
	for _, f := range files {
		opts := base
		opts.SIDs = indexFor(before, f.Dialect)
		diags := idsrule.Lint(f.Name, f.Src, opts)
		out, applied, err := idsrule.Fix(f.Src, diags)
		if err != nil {
			t.Fatalf("%s: Fix: %v", f.Name, err)
		}
		nfixed += applied
		if applied == 0 && !bytes.Equal(out, f.Src) {
			t.Errorf("%s: Fix applied nothing but changed the file", f.Name)
		}
		// Fix takes diagnostics in order and accepts or skips each one,
		// so the one at index i was applied exactly when the count over
		// diags[:i+1] exceeds the count over diags[:i].
		prev := 0
		for i, d := range diags {
			if !d.HasFix() {
				continue
			}
			if _, n, _ := idsrule.Fix(f.Src, diags[:i+1]); n > prev {
				fixed[d.Rule]++
				prev = n
			}
		}

		opts.SIDs = indexFor(after, f.Dialect)
		again := idsrule.Lint(f.Name, out, opts)
		for _, d := range again {
			if strings.HasPrefix(d.Rule, "syntax-") {
				nsyntax++
				t.Errorf("%s: after the fix: %s", f.Name, d)
			}
			if d.HasFix() {
				nremaining++
				t.Errorf("%s: still fixable after the fix: %s", f.Name, d)
			}
		}

		src, _ := idsrule.Parse(f.Name, f.Src)
		res, _ := idsrule.Parse(f.Name, out)
		srcRules, resRules := src.Rules(), res.Rules()
		if len(srcRules) != len(resRules) {
			nchanged++
			t.Errorf("%s: %d rules before the fix, %d after", f.Name, len(srcRules), len(resRules))
			continue
		}
		for i := range srcRules {
			for _, name := range []string{"msg", "sid"} {
				if got, want := logicalValue(resRules[i], name), logicalValue(srcRules[i], name); got != want {
					t.Errorf("%s: rule %d: %s changed from %q to %q", f.Name, i+1, name, want, got)
				}
			}
		}

		twice, n, err := idsrule.Fix(out, again)
		if err != nil {
			t.Fatalf("%s: second Fix: %v", f.Name, err)
		}
		if n != 0 || !bytes.Equal(twice, out) {
			t.Errorf("%s: a second Fix pass applied %d diagnostics and changed the file", f.Name, n)
		}
	}

	for _, id := range slices.Sorted(maps.Keys(fixed)) {
		t.Logf("%-36s %d fixed", id, fixed[id])
	}
	counts := "unchanged"
	if nchanged > 0 {
		counts = "changed in " + strings.Repeat("!", nchanged)
	}
	t.Logf("%d diagnostics fixed, %d remaining fixable, re-parse: %d syntax diagnostics, rule counts %s", nfixed, nremaining, nsyntax, counts)
	if nfixed < 11 {
		t.Errorf("%d diagnostics fixed, want at least the corpus's 11 Snort 3 modifiers", nfixed)
	}
	if nremaining != 0 {
		t.Errorf("%d fixable diagnostics remain after one pass, want none", nremaining)
	}
}

package idsrule_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/internal/corpus"
)

// TestCorpusLint lints every corpus file with the policy the corpus is
// written to and pins what real rules produce: no syntax errors, no
// keyword from the wrong dialect, no duplicate sid within a dialect, and
// exactly the known counts of the findings the corpus does carry. The
// per-check histogram and every finding but the Snort 3 modifiers are
// logged.
func TestCorpusLint(t *testing.T) {
	files := corpus.Files(t)
	if len(files) == 0 {
		t.Fatal("corpus directory contains no *.rule files")
	}

	base := idsrule.DefaultOptions()
	base.Policy = idsrule.Policy{SIDMin: 12_900_000, SIDMax: 12_999_999, PlaceholderBelow: 12_900_000, RequireRev: true}
	indexes := make(map[idsrule.Dialect]*idsrule.SIDIndex)

	hist := make(map[string]int)
	nfiles, nrules := 0, 0
	for _, f := range files {
		opts := base
		if indexes[f.Dialect] == nil {
			indexes[f.Dialect] = idsrule.NewSIDIndex()
		}
		opts.SIDs = indexes[f.Dialect]
		diags := idsrule.Lint(f.Name, f.Src, opts)
		nfiles++
		nrules += corpus.CountRules(f.Src)
		for _, d := range diags {
			hist[d.Rule]++
			if d.Rule != "content-snort3-modifiers" {
				t.Logf("%s", d)
			}
		}
	}

	for _, id := range slices.Sorted(maps.Keys(hist)) {
		t.Logf("%-36s %d", id, hist[id])
	}
	t.Logf("%d files / %d rules linted, %d diagnostics", nfiles, nrules, total(hist))

	for id, n := range hist {
		if strings.HasPrefix(id, "syntax-") {
			t.Errorf("%d %s diagnostics, want none", n, id)
		}
	}
	for _, id := range []string{"keyword-wrong-dialect", "sid-duplicate", idsrule.RuleConfigInvalid, "dialect-unknown"} {
		if n := hist[id]; n != 0 {
			t.Errorf("%d %s diagnostics, want none", n, id)
		}
	}
	pinned := map[string]int{
		"content-snort3-modifiers": 11, // content:"x", nocase and the like
		"sticky-buffer-empty":      7,  // content:"x"; file_data; with nothing after file_data
		"value-unescaped-quote":    2,  // a pcre with a bare " inside the regex
	}
	for id, want := range pinned {
		if n := hist[id]; n != want {
			t.Errorf("%d %s diagnostics, want %d", n, id, want)
		}
	}
	for id := range hist {
		if _, ok := pinned[id]; !ok {
			t.Errorf("%d %s diagnostics, which the corpus did not produce before", hist[id], id)
		}
	}
}

// total sums a histogram.
func total(hist map[string]int) int {
	n := 0
	for _, v := range hist {
		n += v
	}
	return n
}

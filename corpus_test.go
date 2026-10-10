package idsrule_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/internal/corpus"
)

// TestCorpusInventory checks that the external corpus is where
// IDSRULE_CORPUS says it is, that every file's dialect can be told from its
// name, and reports how much of it there is.
func TestCorpusInventory(t *testing.T) {
	files := corpus.Files(t)
	if len(files) == 0 {
		t.Fatal("corpus directory contains no *.rule files")
	}

	type tally struct{ files, rules int }
	var total, snort2, suricata tally
	for _, f := range files {
		n := corpus.CountRules(f.Src)
		total.files++
		total.rules += n
		switch f.Dialect {
		case idsrule.DialectSnort2:
			snort2.files++
			snort2.rules += n
		case idsrule.DialectSuricata:
			suricata.files++
			suricata.rules += n
		case idsrule.DialectUnknown:
			t.Errorf("%s: dialect could not be told from the filename", f.Name)
		}
	}
	if total.rules == 0 {
		t.Fatal("corpus contains no rules")
	}

	t.Logf("corpus: %d files / %d rules (snort2 %d/%d, suricata %d/%d)",
		total.files, total.rules, snort2.files, snort2.rules, suricata.files, suricata.rules)
}

// TestCorpusParse parses every corpus file and checks that real rules
// produce no syntax diagnostics, that the tree is lossless and well-formed,
// and that every rule the corpus counts is found.
func TestCorpusParse(t *testing.T) {
	files := corpus.Files(t)
	if len(files) == 0 {
		t.Fatal("corpus directory contains no *.rule files")
	}

	nfiles, nrules, ndiags := 0, 0, 0
	lossless := true
	for _, f := range files {
		t.Run(f.Name, func(t *testing.T) {
			file, diags := idsrule.Parse(f.Path, f.Src)
			for _, d := range diags {
				t.Errorf("%s: %s", f.Name, d)
			}
			ndiags += len(diags)
			if file.Text() != string(f.Src) {
				lossless = false
				t.Errorf("%s: parsed text differs from the source", f.Name)
			}
			if err := cst.Verify(file); err != nil {
				lossless = false
				t.Errorf("%s: %v", f.Name, err)
			}
			want := corpus.CountRules(f.Src)
			if got := len(file.Rules()); got != want {
				t.Errorf("%s: parsed %d rules, the corpus counts %d", f.Name, got, want)
			}
			nfiles++
			nrules += len(file.Rules())
		})
	}

	state := "lossless"
	if !lossless {
		state = "NOT lossless"
	}
	t.Logf("%d files / %d rules parsed, %d syntax diagnostics, %s", nfiles, nrules, ndiags, state)
}

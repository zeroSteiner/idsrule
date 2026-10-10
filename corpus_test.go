package idsrule_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule"
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

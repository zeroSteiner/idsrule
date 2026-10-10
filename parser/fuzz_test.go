package parser

import (
	"bytes"
	"os"
	"testing"

	"github.com/zeroSteiner/idsrule/internal/corpus"
)

// FuzzParse throws arbitrary bytes at Parse and checks the invariants that
// hold for any input, and that parsing is deterministic. The fixtures and
// the recovery inputs are its seeds, as is every corpus file when
// IDSRULE_CORPUS is set.
func FuzzParse(f *testing.F) {
	for _, path := range fixtures(f) {
		src, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(src)
	}
	for _, row := range recoveryRows {
		f.Add([]byte(row.input))
	}
	if os.Getenv("IDSRULE_CORPUS") != "" {
		for _, cf := range corpus.Files(f) {
			f.Add(cf.Src)
		}
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		file, diags := Parse(src)
		if !checkFile(t, src, file, diags) {
			return
		}
		again, diags2 := Parse(src)
		if !bytes.Equal(render(file, diags), render(again, diags2)) {
			t.Errorf("parsing %q twice gave different results", src)
		}
	})
}

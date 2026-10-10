package lexer_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/internal/corpus"
	"github.com/zeroSteiner/idsrule/lexer"
	"github.com/zeroSteiner/idsrule/source"
)

// TestCorpusLexLossless lexes every corpus file and checks that the tokens
// reproduce it, that they satisfy the structural invariants, and that real
// rules produce no lexer diagnostics.
func TestCorpusLexLossless(t *testing.T) {
	files := corpus.Files(t)
	if len(files) == 0 {
		t.Fatal("corpus directory contains no *.rule files")
	}

	lossless, ndiags := 0, 0
	for _, f := range files {
		ok := t.Run(f.Name, func(t *testing.T) {
			toks, diags := lexer.Lex(f.Src)
			if !checkInvariants(t, f.Src, toks, diags) {
				return
			}
			b := diag.Builder{File: f.Name, Lines: source.NewLineTable(f.Src)}
			for _, d := range diags {
				b.Resolve(&d)
				t.Logf("lexer diagnostic: %s", d)
			}
			ndiags += len(diags)
		})
		if ok {
			lossless++
		}
	}

	t.Logf("%d files lexed losslessly, %d lexer diagnostics", lossless, ndiags)
	if lossless != len(files) {
		t.Errorf("%d of %d files failed to lex losslessly", len(files)-lossless, len(files))
	}
	if ndiags != 0 {
		t.Errorf("corpus produced %d lexer diagnostics, want 0", ndiags)
	}
}

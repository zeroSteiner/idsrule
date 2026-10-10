package lexer_test

import (
	"os"
	"testing"

	"github.com/zeroSteiner/idsrule/internal/corpus"
	"github.com/zeroSteiner/idsrule/lexer"
)

// FuzzLex throws arbitrary bytes at Lex and checks the invariants that hold
// for any input. The hazards are its seeds, as is every corpus file when
// IDSRULE_CORPUS is set.
func FuzzLex(f *testing.F) {
	for _, tt := range lexTests {
		f.Add([]byte(tt.src))
	}
	for _, tt := range moreLexTests {
		f.Add([]byte(tt.src))
	}
	if os.Getenv("IDSRULE_CORPUS") != "" {
		for _, cf := range corpus.Files(f) {
			f.Add(cf.Src)
		}
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		toks, diags := lexer.Lex(src)
		checkInvariants(t, src, toks, diags)
	})
}

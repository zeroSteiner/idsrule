package parser

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/diag"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// render produces the golden text of a parse: the dump of the tree, a blank
// line, and one line per diagnostic.
func render(f *cst.File, diags []diag.Diagnostic) []byte {
	var buf bytes.Buffer
	_ = cst.Dump(&buf, f)
	buf.WriteByte('\n')
	for _, d := range diags {
		fmt.Fprintf(&buf, "diag %s %d:%d %s\n", d.Rule, d.Span.Start, d.Span.End, d.Message)
	}
	return buf.Bytes()
}

// fixtures returns the paths of the testdata/*.rule fixtures.
func fixtures(t testing.TB) []string {
	t.Helper()
	paths, err := filepath.Glob("testdata/*.rule")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures in testdata")
	}
	return paths
}

// TestGolden parses every fixture and compares the rendered result with
// the .golden file beside it. Run with -update to rewrite the golden files.
func TestGolden(t *testing.T) {
	for _, path := range fixtures(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".rule")
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f, diags := Parse(src)
			checkFile(t, src, f, diags)
			got := render(f, diags)
			golden := strings.TrimSuffix(path, ".rule") + ".golden"
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from %s (run with -update to rewrite it):\n%s", name, golden, firstDiff(got, want))
			}
		})
	}
}

// firstDiff describes the first line on which got and want differ.
func firstDiff(got, want []byte) string {
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return fmt.Sprintf("line %d:\n got %q\nwant %q", i+1, gl, wl)
		}
	}
	return "no differing line"
}

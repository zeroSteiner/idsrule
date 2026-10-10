// Package corpus locates and loads the external corpus of real rule files
// that the module's integration tests run against.
//
// The corpus lives outside the repository. Tests find it through the
// IDSRULE_CORPUS environment variable and skip when it is unset.
package corpus

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/dialect"
)

const envVar = "IDSRULE_CORPUS"

// File is one rule file from the corpus.
type File struct {
	Path    string          // full path to the file
	Name    string          // base name of the file
	Dialect dialect.Dialect // detected from Name
	Src     []byte          // complete contents
}

// Dir returns the corpus directory named by IDSRULE_CORPUS. It skips the test
// when the variable is unset and fails it when the value is not a directory.
func Dir(t testing.TB) string {
	t.Helper()
	dir := os.Getenv(envVar)
	if dir == "" {
		t.Skip(envVar + " not set")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("%s=%q: %v", envVar, dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s=%q is not a directory", envVar, dir)
	}
	return dir
}

// Files reads every *.rule file directly inside Dir(t), sorted by Name.
// It fails the test if a file cannot be read.
func Files(t testing.TB) []File {
	t.Helper()
	dir := Dir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus directory: %v", err)
	}
	var files []File
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rule") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read corpus file: %v", err)
		}
		files = append(files, File{
			Path:    path,
			Name:    e.Name(),
			Dialect: dialect.FromFilename(e.Name()),
			Src:     src,
		})
	}
	slices.SortFunc(files, func(a, b File) int { return strings.Compare(a.Name, b.Name) })
	return files
}

// ruleLine matches the first line of a rule: a line that starts with a rule
// action followed by whitespace. Multiline mode makes ^ match at the start
// of every line, with or without a trailing newline on the last one.
var ruleLine = regexp.MustCompile(`(?m)^(alert|log|pass|drop|reject|sdrop|activate|dynamic|rejectsrc|rejectdst|rejectboth)\s`)

// CountRules returns the number of lines in src that begin a rule.
func CountRules(src []byte) int {
	return len(ruleLine.FindAllIndex(src, -1))
}

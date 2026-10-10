package idsrule_test

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/cst"
	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/internal/corpus"
	"github.com/zeroSteiner/idsrule/value"
)

// corpusOption is one option of one corpus rule with where it came from.
type corpusOption struct {
	file    string
	line    int
	dialect dialect.Dialect
	opt     *cst.Option
}

// corpusOptions parses every corpus file and returns every option of every
// rule, in file then source order, with its file's dialect.
func corpusOptions(t *testing.T) []corpusOption {
	t.Helper()
	files := corpus.Files(t)
	if len(files) == 0 {
		t.Fatal("corpus directory contains no *.rule files")
	}
	var out []corpusOption
	for _, f := range files {
		file, _ := idsrule.Parse(f.Path, f.Src)
		lines := file.Lines()
		for _, r := range file.Rules() {
			for _, o := range r.Options() {
				out = append(out, corpusOption{
					file:    f.Name,
					line:    lines.Position(o.Keyword.Start).Line,
					dialect: f.Dialect,
					opt:     o,
				})
			}
		}
	}
	return out
}

// corpusDialects are the dialects the corpus is written in, in report order.
var corpusDialects = []dialect.Dialect{dialect.Snort2, dialect.Suricata}

// keywordsByDialect groups the distinct option names of the corpus by the
// dialect of the file they appear in.
func keywordsByDialect(opts []corpusOption) map[dialect.Dialect]map[string]bool {
	by := make(map[dialect.Dialect]map[string]bool)
	for _, o := range opts {
		if by[o.dialect] == nil {
			by[o.dialect] = make(map[string]bool)
		}
		by[o.dialect][o.opt.Name()] = true
	}
	return by
}

// TestCorpusKeywordCoverage checks that every keyword the corpus uses is
// known to the dialect of the file it appears in, and reports how many
// distinct keywords each dialect's files use.
func TestCorpusKeywordCoverage(t *testing.T) {
	by := keywordsByDialect(corpusOptions(t))
	for _, d := range corpusDialects {
		names := slices.Sorted(maps.Keys(by[d]))
		t.Logf("%s: keywords: %s", d, strings.Join(names, " "))
		known := 0
		for _, name := range names {
			if _, ok := dialect.Lookup(d, name); ok {
				known++
			} else {
				t.Errorf("%s: unknown keyword %q", d, name)
			}
		}
		t.Logf("%s: %d/%d corpus keywords known", d, known, len(names))
	}
}

// TestCorpusDialectCrossCheck checks that no corpus keyword is known only
// to the other dialect, which would mean the tables assign it to the wrong
// dialect.
func TestCorpusDialectCrossCheck(t *testing.T) {
	by := keywordsByDialect(corpusOptions(t))
	for _, d := range corpusDialects {
		for _, name := range slices.Sorted(maps.Keys(by[d])) {
			if _, ok := dialect.Lookup(d, name); ok {
				continue
			}
			if _, known := dialect.LookupAny(name); known {
				t.Errorf("%s: keyword %q exists only in the other dialect", d, name)
			}
		}
	}
}

// TestCorpusValuesDecode checks that the value of every corpus option whose
// keyword is known and whose kind is decoded decodes without error.
func TestCorpusValuesDecode(t *testing.T) {
	opts := corpusOptions(t)
	checked, failed, trailing := 0, 0, 0
	kinds := make(map[dialect.ValueKind]int)
	for _, o := range opts {
		k, ok := dialect.Lookup(o.dialect, o.opt.Name())
		if !ok || k.Kind == dialect.KindRaw {
			continue
		}
		logical, _ := o.opt.LogicalValue()
		checked++
		kinds[k.Kind]++
		if err := value.Validate(k.Kind, logical); err != nil {
			failed++
			t.Errorf("%s:%d: %s: %v (value %q)", o.file, o.line, o.opt.Name(), err, logical)
			continue
		}
		if k.Kind == dialect.KindContent {
			if c, err := value.ParseContent(logical); err == nil && c.Trailing != "" {
				trailing++
			}
		}
	}
	type kindCount struct {
		kind dialect.ValueKind
		n    int
	}
	counts := make([]kindCount, 0, len(kinds))
	for k, n := range kinds {
		counts = append(counts, kindCount{k, n})
	}
	slices.SortFunc(counts, func(a, b kindCount) int { return cmp.Compare(a.kind, b.kind) })
	for _, c := range counts {
		t.Logf("%s: %d values", c.kind, c.n)
	}
	t.Logf("%d content values carry trailing text after the closing quote", trailing)
	t.Logf("%d values decoded, %d failed", checked, failed)
}

package check_test

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/check"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
)

// The fixtures under testdata are rule files annotated with comment lines:
//
//	# lint: dialect=snort2 sid-min=1 sid-max=9 placeholder-below=1 require-rev=true
//	        msg-prefix="VC " checks=a,b style=on sid-index=key severity=id:sev
//	        space-after-colon=any space-after-semicolon=require
//	        continuation-indent="    " fixes=N
//	# expect: <id> [@+N | @N] [error | warning] ["message substring"] [fix]
//
// Every "# lint:" key is optional. The dialect defaults to snort2, require-rev
// to true and checks to the fixture's own id, the file name up to the first
// '_' or '.'. Fixtures that share a sid-index key share one SIDIndex and are
// run in file name order. An "# expect:" names a diagnostic on the line N
// after it (default 1), or on absolute line N with "@N"; the severity and the
// quoted substring, which runs from the first '"' to the last one, are
// checked when given, and "fix" says the diagnostic carries an autofix
// (without it the diagnostic must carry none). The diagnostics Lint returns
// must match the expectations exactly, syntax diagnostics included.
//
// A fixture whose diagnostics carry fixes also has a golden under
// testdata/fixed: the result of one Lint and Fix pass over it. The harness
// checks the result against the golden, that a second pass changes nothing
// and that none of the fixed ids is reported again; "fixes=N" pins how many
// diagnostics the first pass applies. Run the tests with -update to rewrite
// the goldens.

// update rewrites the goldens under testdata/fixed instead of checking them.
var update = flag.Bool("update", false, "rewrite the fixed goldens under testdata/fixed")

// expectation is one "# expect:" annotation.
type expectation struct {
	annot  int // line of the annotation
	id     string
	line   int
	sev    diag.Severity // empty when not given
	substr string
	hasSub bool
	fix    bool // the diagnostic must carry an autofix
}

func (e expectation) String() string {
	s := fmt.Sprintf("%s @%d", e.id, e.line)
	if e.sev != "" {
		s += " " + string(e.sev)
	}
	if e.hasSub {
		s += " " + strconv.Quote(e.substr)
	}
	if e.fix {
		s += " fix"
	}
	return s
}

// fixture is one annotated rules file.
type fixture struct {
	name    string // base file name
	primary string // the check id the file name starts with
	src     []byte
	opts    idsrule.Options
	checks  []string
	sidKey  string
	fixes   int // diagnostics the first Fix pass must apply; -1 when unpinned
	expects []expectation
}

// splitFields splits s on blanks outside double quotes and drops the
// quotes.
func splitFields(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, pending := false, false
	flush := func() {
		if pending {
			out = append(out, cur.String())
			cur.Reset()
			pending = false
		}
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			inQuote = !inQuote
			pending = true
		case !inQuote && (c == ' ' || c == '\t'):
			flush()
		default:
			cur.WriteByte(c)
			pending = true
		}
	}
	flush()
	return out
}

// parseUint parses a "# lint:" number.
func parseUint(t *testing.T, name, key, val string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		t.Fatalf("%s: # lint: %s=%q: %v", name, key, val, err)
	}
	return n
}

// parseSpacing parses a "# lint:" spacing value.
func parseSpacing(t *testing.T, name, key, val string) check.Spacing {
	t.Helper()
	switch val {
	case "any":
		return check.SpacingAny
	case "require":
		return check.SpacingRequire
	case "forbid":
		return check.SpacingForbid
	}
	t.Fatalf("%s: # lint: %s=%q is not any, require or forbid", name, key, val)
	return check.SpacingAny
}

// parseLint applies one "# lint:" line to f.
func parseLint(t *testing.T, f *fixture, rest string) {
	t.Helper()
	for _, field := range splitFields(rest) {
		key, val, ok := strings.Cut(field, "=")
		if !ok {
			t.Fatalf("%s: # lint: field %q is not key=value", f.name, field)
		}
		switch key {
		case "dialect":
			switch val {
			case "snort2":
				f.opts.Dialect = dialect.Snort2
			case "suricata":
				f.opts.Dialect = dialect.Suricata
			case "unknown":
				f.opts.Dialect = dialect.Unknown
			default:
				t.Fatalf("%s: # lint: unknown dialect %q", f.name, val)
			}
		case "sid-min":
			f.opts.Policy.SIDMin = parseUint(t, f.name, key, val)
		case "sid-max":
			f.opts.Policy.SIDMax = parseUint(t, f.name, key, val)
		case "placeholder-below":
			f.opts.Policy.PlaceholderBelow = parseUint(t, f.name, key, val)
		case "require-rev":
			b, err := strconv.ParseBool(val)
			if err != nil {
				t.Fatalf("%s: # lint: require-rev=%q: %v", f.name, val, err)
			}
			f.opts.Policy.RequireRev = b
		case "msg-prefix":
			f.opts.Policy.MsgPrefix = val
		case "checks":
			f.checks = strings.Split(val, ",")
		case "style":
			f.opts.Checks.Style = val == "on"
		case "sid-index":
			f.sidKey = val
		case "space-after-colon":
			f.opts.Policy.Style.SpaceAfterColon = parseSpacing(t, f.name, key, val)
		case "space-after-semicolon":
			f.opts.Policy.Style.SpaceAfterSemicolon = parseSpacing(t, f.name, key, val)
		case "continuation-indent":
			f.opts.Policy.Style.ContinuationIndent = val
		case "fixes":
			f.fixes = int(parseUint(t, f.name, key, val))
		case "severity":
			id, sev, ok := strings.Cut(val, ":")
			if !ok {
				t.Fatalf("%s: # lint: severity=%q is not id:severity", f.name, val)
			}
			if f.opts.Checks.Severity == nil {
				f.opts.Checks.Severity = make(map[string]diag.Severity)
			}
			f.opts.Checks.Severity[id] = diag.Severity(sev)
		default:
			t.Fatalf("%s: # lint: unknown key %q", f.name, key)
		}
	}
}

// parseExpect parses one "# expect:" line found on line annot.
func parseExpect(t *testing.T, name string, annot int, rest string) expectation {
	t.Helper()
	e := expectation{annot: annot, line: annot + 1}
	if i := strings.IndexByte(rest, '"'); i >= 0 {
		j := strings.LastIndexByte(rest, '"')
		if j == i {
			t.Fatalf("%s:%d: # expect: unterminated substring", name, annot)
		}
		e.substr, e.hasSub = rest[i+1:j], true
		rest = rest[:i] + " " + rest[j+1:]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		t.Fatalf("%s:%d: # expect: missing check id", name, annot)
	}
	e.id = fields[0]
	for _, field := range fields[1:] {
		switch {
		case strings.HasPrefix(field, "@+") || strings.HasPrefix(field, "@-"):
			n, err := strconv.Atoi(field[1:])
			if err != nil {
				t.Fatalf("%s:%d: # expect: bad offset %q", name, annot, field)
			}
			e.line = annot + n
		case strings.HasPrefix(field, "@"):
			n, err := strconv.Atoi(field[1:])
			if err != nil {
				t.Fatalf("%s:%d: # expect: bad line %q", name, annot, field)
			}
			e.line = n
		case field == "error" || field == "warning":
			e.sev = diag.Severity(field)
		case field == "fix":
			e.fix = true
		default:
			t.Fatalf("%s:%d: # expect: unknown field %q", name, annot, field)
		}
	}
	return e
}

// loadFixture reads and parses the annotations of one fixture.
func loadFixture(t *testing.T, path string) *fixture {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(path)
	f := &fixture{name: name, src: src, fixes: -1}
	f.primary = strings.FieldsFunc(name, func(r rune) bool { return r == '_' || r == '.' })[0]
	f.opts = idsrule.Options{Dialect: dialect.Snort2, Policy: idsrule.Policy{RequireRev: true}}
	for i, line := range strings.Split(string(src), "\n") {
		switch {
		case strings.HasPrefix(line, "# lint:"):
			parseLint(t, f, strings.TrimPrefix(line, "# lint:"))
		case strings.HasPrefix(line, "# expect:"):
			f.expects = append(f.expects, parseExpect(t, name, i+1, strings.TrimPrefix(line, "# expect:")))
		}
	}
	// Run only the listed checks, or the fixture's own: enable them and
	// disable every other registered one.
	checks := f.checks
	if checks == nil {
		checks = []string{f.primary}
	}
	listed := make(map[string]bool)
	for _, id := range checks {
		if !check.Known(id) {
			t.Fatalf("%s: # lint: checks names unknown check %q", name, id)
		}
		listed[id] = true
	}
	f.opts.Checks.Enable = checks
	for _, id := range check.IDs() {
		if !listed[id] {
			f.opts.Checks.Disable = append(f.opts.Checks.Disable, id)
		}
	}
	return f
}

// describe renders diagnostics for a failure message.
func describe(ds []diag.Diagnostic) string {
	if len(ds) == 0 {
		return "  (none)"
	}
	lines := make([]string, len(ds))
	for i, d := range ds {
		lines[i] = "  " + d.String()
	}
	return strings.Join(lines, "\n")
}

// runFixture lints f and matches the diagnostics against its expectations
// in both directions.
func runFixture(t *testing.T, f *fixture) {
	t.Helper()
	got := idsrule.Lint(f.name, f.src, f.opts)
	matched := make([]bool, len(got))
	for _, e := range f.expects {
		found := false
		for i, d := range got {
			if matched[i] || d.Rule != e.id || d.Line != e.line {
				continue
			}
			if e.sev != "" && d.Severity != e.sev {
				continue
			}
			if e.hasSub && !strings.Contains(d.Message, e.substr) {
				continue
			}
			matched[i], found = true, true
			if d.HasFix() != e.fix {
				t.Errorf("%s:%d: %s: diagnostic %s carries a fix: %t, want %t", f.name, e.annot, e, d, d.HasFix(), e.fix)
			}
			break
		}
		if !found {
			t.Errorf("%s:%d: expected %s, not found among:\n%s", f.name, e.annot, e, describe(got))
		}
	}
	for i, d := range got {
		if !matched[i] {
			t.Errorf("%s: unexpected diagnostic %s", f.name, d)
		}
		if d.File != f.name || d.Line < 1 || d.Column < 1 || d.Message == "" {
			t.Errorf("%s: malformed diagnostic %+v", f.name, d)
		}
		for _, r := range d.Related {
			if r.File == "" || r.Line < 1 || r.Column < 1 {
				t.Errorf("%s: malformed Related %+v on %s", f.name, r, d)
			}
		}
	}
}

// goldenPath returns the path of f's fixed golden.
func goldenPath(f *fixture) string {
	return filepath.Join("testdata", "fixed", f.name+".golden")
}

// fixable reports whether any of ds carries a fix.
func fixable(ds []diag.Diagnostic) bool {
	for _, d := range ds {
		if d.HasFix() {
			return true
		}
	}
	return false
}

// runFixed lints f, fixes it and compares the result with the golden
// (or rewrites the golden with -update); then it lints and fixes the
// result again and checks that the second pass changes nothing and that no
// fixed id is reported again.
func runFixed(t *testing.T, f *fixture) {
	t.Helper()
	diags := idsrule.Lint(f.name, f.src, f.opts)
	fixed, applied, err := idsrule.Fix(f.src, diags)
	if err != nil {
		t.Fatalf("%s: Fix: %v", f.name, err)
	}
	if applied == 0 {
		t.Errorf("%s: Fix applied nothing", f.name)
	}
	if f.fixes >= 0 && applied != f.fixes {
		t.Errorf("%s: Fix applied %d diagnostics, want %d", f.name, applied, f.fixes)
	}
	fixedIDs := make(map[string]bool)
	for _, d := range diags {
		if d.HasFix() {
			fixedIDs[d.Rule] = true
		}
	}

	path := goldenPath(f)
	if *update {
		if err := os.WriteFile(path, fixed, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixed, want) {
		t.Errorf("%s: fixed output differs from %s:\n--- got\n%s\n--- want\n%s", f.name, path, fixed, want)
	}

	again := idsrule.Lint(f.name, fixed, f.opts)
	for _, d := range again {
		if fixedIDs[d.Rule] {
			t.Errorf("%s: after the fix, still reported: %s", f.name, d)
		}
	}
	twice, applied, err := idsrule.Fix(fixed, again)
	if err != nil {
		t.Fatalf("%s: second Fix: %v", f.name, err)
	}
	if applied != 0 || !bytes.Equal(twice, fixed) {
		t.Errorf("%s: a second Fix pass applied %d diagnostics and changed the output:\n%s", f.name, applied, twice)
	}
}

// TestFixtures runs every fixture under testdata through idsrule.Lint,
// runs the fixable ones through Fix against their goldens, and checks that
// every registered check has a fixture of its own.
func TestFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.rule"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures under testdata")
	}
	sort.Strings(paths)

	indexes := make(map[string]*check.SIDIndex)
	covered := make(map[string]bool)
	for _, path := range paths {
		f := loadFixture(t, path)
		if check.Known(f.primary) {
			covered[f.primary] = true
		} else if f.checks == nil {
			t.Errorf("%s: file name does not start with a check id and # lint: names no checks", f.name)
		}
		if f.sidKey != "" {
			if indexes[f.sidKey] == nil {
				indexes[f.sidKey] = check.NewSIDIndex()
			}
			f.opts.SIDs = indexes[f.sidKey]
		}
		t.Run(f.name, func(t *testing.T) { runFixture(t, f) })

		// Every fixture with a fixable diagnostic has a golden, and
		// only those do.
		_, err := os.Stat(goldenPath(f))
		hasGolden := err == nil
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		switch canFix := fixable(idsrule.Lint(f.name, f.src, f.opts)); {
		case canFix && !hasGolden && !*update:
			t.Errorf("%s: has fixable diagnostics but no %s; run go test ./check -update", f.name, goldenPath(f))
		case !canFix && hasGolden:
			t.Errorf("%s: has no fixable diagnostic, yet %s exists", f.name, goldenPath(f))
		case canFix:
			t.Run(f.name+"/fixed", func(t *testing.T) { runFixed(t, f) })
		}
	}

	for _, c := range check.All() {
		if c.ID == check.DialectUnknownID {
			continue
		}
		if !covered[c.ID] {
			t.Errorf("check %q has no fixture named testdata/%s[_variant].rule", c.ID, c.ID)
		}
	}
}

// TestSplitFields pins the "# lint:" tokenizer.
func TestSplitFields(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  a=1   b=2 ", []string{"a=1", "b=2"}},
		{`msg-prefix="VC " checks=a,b`, []string{"msg-prefix=VC ", "checks=a,b"}},
		{`x=""`, []string{"x="}},
		{"\tkey=v\t", []string{"key=v"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := splitFields(tt.in)
			if strings.Join(got, "|") != strings.Join(tt.want, "|") || len(got) != len(tt.want) {
				t.Errorf("splitFields(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

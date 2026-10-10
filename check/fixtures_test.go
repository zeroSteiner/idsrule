package check_test

import (
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
//	# expect: <id> [@+N | @N] [error | warning] ["message substring"]
//
// Every "# lint:" key is optional. The dialect defaults to snort2, require-rev
// to true and checks to the fixture's own id, the file name up to the first
// '_' or '.'. Fixtures that share a sid-index key share one SIDIndex and are
// run in file name order. An "# expect:" names a diagnostic on the line N
// after it (default 1), or on absolute line N with "@N"; the severity and the
// quoted substring, which runs from the first '"' to the last one, are
// checked when given. The diagnostics Lint returns must match the
// expectations exactly, syntax diagnostics included.

// expectation is one "# expect:" annotation.
type expectation struct {
	annot  int // line of the annotation
	id     string
	line   int
	sev    diag.Severity // empty when not given
	substr string
	hasSub bool
}

func (e expectation) String() string {
	s := fmt.Sprintf("%s @%d", e.id, e.line)
	if e.sev != "" {
		s += " " + string(e.sev)
	}
	if e.hasSub {
		s += " " + strconv.Quote(e.substr)
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
		rest = rest[:i]
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
	f := &fixture{name: name, src: src}
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
	if f.checks == nil {
		f.checks = []string{f.primary}
	}
	// Run only the listed checks: enable them and disable every other
	// registered one.
	listed := make(map[string]bool)
	for _, id := range f.checks {
		if !check.Known(id) {
			t.Fatalf("%s: # lint: checks names unknown check %q", name, id)
		}
		listed[id] = true
	}
	f.opts.Checks.Enable = f.checks
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

// TestFixtures runs every fixture under testdata through idsrule.Lint and
// checks that every registered non-style check has a fixture of its own.
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
		if !check.Known(f.primary) {
			t.Errorf("%s: file name does not start with a check id", f.name)
		}
		covered[f.primary] = true
		if f.sidKey != "" {
			if indexes[f.sidKey] == nil {
				indexes[f.sidKey] = check.NewSIDIndex()
			}
			f.opts.SIDs = indexes[f.sidKey]
		}
		t.Run(f.name, func(t *testing.T) { runFixture(t, f) })
	}

	for _, c := range check.All() {
		if c.Style || c.ID == check.DialectUnknownID {
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

package idsrule_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/check"
)

// rulesOf returns the Rule ids of ds in order.
func rulesOf(ds []idsrule.Diagnostic) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Rule
	}
	return out
}

// withRule returns the diagnostics of ds whose Rule is id.
func withRule(ds []idsrule.Diagnostic, id string) []idsrule.Diagnostic {
	var out []idsrule.Diagnostic
	for _, d := range ds {
		if d.Rule == id {
			out = append(out, d)
		}
	}
	return out
}

func TestLint_DialectFromFilename(t *testing.T) {
	src := []byte("alert http any any -> any any (msg:\"x\"; http.method; content:\"GET\"; sid:1; rev:1;)\n")
	tests := []struct {
		file    string
		dialect idsrule.Dialect // Options.Dialect; Unknown detects from the name
		want    []string
	}{
		{"a.suricata.rule", idsrule.DialectUnknown, nil},
		{"a.snort.rule", idsrule.DialectUnknown, []string{"header-invalid-protocol", "keyword-wrong-dialect"}},
		{"a.rule", idsrule.DialectUnknown, []string{"dialect-unknown"}},
		{"a.snort.rule", idsrule.DialectSuricata, nil},
		{"a.rule", idsrule.DialectSnort2, []string{"header-invalid-protocol", "keyword-wrong-dialect"}},
	}
	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.dialect.String(), func(t *testing.T) {
			opts := idsrule.DefaultOptions()
			opts.Dialect = tt.dialect
			got := idsrule.Lint(tt.file, src, opts)
			if rules := rulesOf(got); !slices.Equal(rules, tt.want) {
				t.Errorf("Lint(%s) = %v, want %v", tt.file, got, tt.want)
			}
			for _, d := range got {
				if d.File != tt.file {
					t.Errorf("diagnostic file = %q, want %q", d.File, tt.file)
				}
			}
		})
	}

	t.Run("dialect-unknown is at 1:1 and reported once", func(t *testing.T) {
		got := idsrule.Lint("a.rule", src, idsrule.DefaultOptions())
		if len(got) != 1 || got[0].Rule != "dialect-unknown" || got[0].Line != 1 || got[0].Column != 1 || got[0].Severity != idsrule.SeverityWarning {
			t.Errorf("Lint(a.rule) = %v", got)
		}
	})
}

func TestLint_ConfigInvalid(t *testing.T) {
	src := []byte("alert tcp any any -> any any (msg:\"x\"; rev:1;)\n") // sid-missing if it got that far
	tests := []struct {
		name string
		opts idsrule.Options
		want string // message substring
	}{
		{name: "bad sid range", opts: idsrule.Options{Policy: idsrule.Policy{SIDMin: 5, SIDMax: 1}}, want: "policy: sid range"},
		{name: "unknown check", opts: idsrule.Options{Checks: idsrule.Selection{Enable: []string{"nope"}}}, want: `unknown check id "nope"`},
		{name: "bad dialect", opts: idsrule.Options{Dialect: idsrule.Dialect(7)}, want: "invalid dialect"},
		{name: "bad severity", opts: idsrule.Options{Checks: idsrule.Selection{Severity: map[string]idsrule.Severity{"sid-missing": "loud"}}}, want: `invalid severity "loud"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := idsrule.Lint("x.snort.rule", src, tt.opts)
			if len(got) != 1 {
				t.Fatalf("Lint() = %v, want exactly one config-invalid diagnostic", got)
			}
			d := got[0]
			if d.Rule != idsrule.RuleConfigInvalid || d.Severity != idsrule.SeverityError || d.File != "x.snort.rule" ||
				d.Line != 1 || d.Column != 1 || d.End != (idsrule.Position{Line: 1, Column: 1}) || !strings.Contains(d.Message, tt.want) {
				t.Errorf("Lint() = %+v, want config-invalid at 1:1 containing %q", d, tt.want)
			}
			f, _ := idsrule.Parse("x.snort.rule", src)
			if cd := idsrule.Check(f, tt.opts); len(cd) != 1 || cd[0].Rule != idsrule.RuleConfigInvalid {
				t.Errorf("Check() = %v, want one config-invalid diagnostic", cd)
			}
		})
	}
	if slices.Contains(idsrule.CheckIDs(), idsrule.RuleConfigInvalid) {
		t.Errorf("CheckIDs() lists %q", idsrule.RuleConfigInvalid)
	}
}

func TestLint_CrossFile(t *testing.T) {
	// a declares sid 100 twice (an in-file duplicate), a placeholder and
	// sid 101; b declares sid 100 once and the placeholder.
	a := []byte("alert tcp any any -> any any (msg:\"a1\"; sid:100; rev:1;)\n" +
		"alert tcp any any -> any any (msg:\"a1 again\"; sid:100; rev:1;)\n" +
		"alert tcp any any -> any any (msg:\"a2\"; sid:1; rev:1;)\n" +
		"alert tcp any any -> any any (msg:\"a3\"; sid:101; rev:1;)\n")
	b := []byte("# b\nalert tcp any any -> any any (msg:\"b1\"; sid:100; rev:1;)\n" +
		"alert tcp any any -> any any (msg:\"b2\"; sid:1; rev:1;)\n")
	opts := idsrule.DefaultOptions()
	opts.Policy.PlaceholderBelow = 10
	opts.SIDs = idsrule.NewSIDIndex()

	// Re-linting a is idempotent: the in-file duplicate, nothing else.
	for i := 0; i < 3; i++ {
		got := idsrule.Lint("a.snort.rule", a, opts)
		if len(got) != 1 || got[0].Rule != "sid-duplicate" || got[0].Line != 2 || strings.Contains(got[0].Message, "declared in") {
			t.Fatalf("Lint(a) #%d = %v, want only the in-file duplicate", i+1, got)
		}
	}
	if n := opts.SIDs.Len(); n != 2 {
		t.Errorf("index holds %d sids after linting a, want 2 (placeholders are not indexed)", n)
	}
	if refs := opts.SIDs.Lookup(100); len(refs) != 1 || refs[0] != (idsrule.SIDRef{File: "a.snort.rule", Line: 1, Column: 41}) {
		t.Errorf("Lookup(100) = %v, want the first declaration in a only", refs)
	}

	// b reports sid 100 exactly once, although a declares it twice.
	got := idsrule.Lint("b.snort.rule", b, opts)
	if len(got) != 1 {
		t.Fatalf("Lint(b) = %v, want one sid-duplicate", got)
	}
	d := got[0]
	if d.Rule != "sid-duplicate" || d.Line != 2 || d.Column != 41 || !strings.Contains(d.Message, "also declared in a.snort.rule") {
		t.Errorf("Lint(b) = %+v", d)
	}
	want := idsrule.Related{File: "a.snort.rule", Line: 1, Column: 41, Message: "also declared here"}
	if len(d.Related) != 1 || d.Related[0] != want {
		t.Errorf("Related = %+v, want %+v", d.Related, want)
	}

	// Linting b again reports the same thing once, not twice.
	if again := idsrule.Lint("b.snort.rule", b, opts); len(again) != 1 || len(again[0].Related) != 1 {
		t.Errorf("second Lint(b) = %v", again)
	}
	// And a now sees b's declaration, on its first sid 100, besides its
	// in-file duplicate.
	got = idsrule.Lint("a.snort.rule", a, opts)
	if cross := withRule(got, "sid-duplicate"); len(got) != 2 || len(cross) != 2 ||
		cross[0].Line != 1 || !strings.Contains(cross[0].Message, "b.snort.rule") || cross[1].Line != 2 {
		t.Errorf("Lint(a) after b = %v, want the duplicate from b and the in-file one", got)
	}

	// The index is maintained even when the check is disabled.
	t.Run("disabled check still indexes", func(t *testing.T) {
		opts := opts
		opts.SIDs = idsrule.NewSIDIndex()
		opts.Checks.Disable = []string{"sid-duplicate"}
		if got := idsrule.Lint("a.snort.rule", a, opts); len(got) != 0 {
			t.Fatalf("Lint(a) with sid-duplicate disabled = %v, want nothing", got)
		}
		opts.Checks.Disable = nil
		if got := idsrule.Lint("b.snort.rule", b, opts); len(got) != 1 || got[0].Rule != "sid-duplicate" || len(got[0].Related) != 1 {
			t.Errorf("Lint(b) after a disabled lint = %v, want the duplicate from a", got)
		}
	})

	// Without an index there is nothing to find across files.
	opts.SIDs = nil
	if got := idsrule.Lint("b.snort.rule", b, opts); len(got) != 0 {
		t.Errorf("Lint(b) without an index = %v", got)
	}
}

func TestLint_SeverityOverride(t *testing.T) {
	src := []byte("alert tcp any any -> any any (msg:\"x\"; rev:1;)\n")
	opts := idsrule.DefaultOptions()
	opts.Checks.Severity = map[string]idsrule.Severity{"sid-missing": idsrule.SeverityWarning}
	got := idsrule.Lint("x.snort.rule", src, opts)
	if len(got) != 1 || got[0].Rule != "sid-missing" || got[0].Severity != idsrule.SeverityWarning {
		t.Errorf("Lint() = %v, want one sid-missing warning", got)
	}
	// The override applies to the Run-emitted dialect-unknown too.
	opts.Checks.Severity = map[string]idsrule.Severity{"dialect-unknown": idsrule.SeverityError}
	got = idsrule.Lint("x.rule", src, opts)
	if d := withRule(got, "dialect-unknown"); len(d) != 1 || d[0].Severity != idsrule.SeverityError {
		t.Errorf("Lint(x.rule) = %v, want a dialect-unknown error", got)
	}
}

func TestLint_DisableSuppresses(t *testing.T) {
	src := []byte("alert tcp any any -> any any (msg:\"x\"; rev:1;)\n")
	opts := idsrule.DefaultOptions()
	if got := idsrule.Lint("x.snort.rule", src, opts); len(withRule(got, "sid-missing")) != 1 {
		t.Fatalf("Lint() = %v, want sid-missing", got)
	}
	opts.Checks.Disable = []string{"sid-missing"}
	if got := idsrule.Lint("x.snort.rule", src, opts); len(got) != 0 {
		t.Errorf("Lint() with sid-missing disabled = %v, want nothing", got)
	}
	// Disable wins over Style and over a dialect-unknown emission.
	opts.Checks.Disable = []string{"sid-missing", "dialect-unknown"}
	if got := idsrule.Lint("x.rule", src, opts); len(got) != 0 {
		t.Errorf("Lint(x.rule) with dialect-unknown disabled = %v, want nothing", got)
	}
}

func TestCheckIDs_Sorted(t *testing.T) {
	ids := idsrule.CheckIDs()
	if len(ids) == 0 {
		t.Fatal("CheckIDs() is empty")
	}
	if !slices.IsSorted(ids) {
		t.Errorf("CheckIDs() is not sorted: %v", ids)
	}
	if len(slices.Compact(slices.Clone(ids))) != len(ids) {
		t.Errorf("CheckIDs() has duplicates: %v", ids)
	}
	if !slices.Equal(ids, check.IDs()) {
		t.Errorf("CheckIDs() = %v, check.IDs() = %v", ids, check.IDs())
	}
	for _, id := range []string{"sid-duplicate", "msg-missing", "dialect-unknown", "value-invalid"} {
		if !slices.Contains(ids, id) {
			t.Errorf("CheckIDs() lacks %q", id)
		}
	}
	// The slice is the caller's.
	ids[0] = "x"
	if idsrule.CheckIDs()[0] == "x" {
		t.Error("CheckIDs() returned a shared slice")
	}
}

func TestLint_NeverPanics(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("parser", "testdata", "*.rule"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no parser fixtures")
	}
	dialects := []idsrule.Dialect{idsrule.DialectUnknown, idsrule.DialectSnort2, idsrule.DialectSuricata}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range dialects {
			t.Run(filepath.Base(path)+"/"+d.String(), func(t *testing.T) {
				opts := idsrule.Options{
					Dialect: d,
					Policy:  idsrule.Policy{SIDMin: 10, SIDMax: 1000, PlaceholderBelow: 10, RequireRev: true, MsgPrefix: "X "},
					Checks:  idsrule.Selection{Style: true, Enable: idsrule.CheckIDs()},
					SIDs:    idsrule.NewSIDIndex(),
				}
				got := idsrule.Lint(path, src, opts)
				for _, dg := range got {
					if dg.Rule == idsrule.RuleConfigInvalid {
						t.Fatalf("options rejected: %s", dg.Message)
					}
					if dg.Line < 1 || dg.Column < 1 || dg.Rule == "" || dg.Message == "" || dg.File != path ||
						dg.Span.Start < 0 || dg.Span.End > len(src) || dg.Span.Start > dg.Span.End {
						t.Errorf("malformed diagnostic %+v", dg)
					}
				}
				if !slices.IsSortedFunc(got, func(a, b idsrule.Diagnostic) int {
					if a.Line != b.Line {
						return a.Line - b.Line
					}
					return a.Column - b.Column
				}) {
					t.Errorf("diagnostics are not sorted: %v", got)
				}
			})
		}
	}
	// And on inputs with no rules at all.
	for _, src := range []string{"", "\n", "# only a comment", "garbage\n", "alert", "alert tcp (", "\\\n"} {
		for _, d := range dialects {
			idsrule.Lint("x.rule", []byte(src), idsrule.Options{Dialect: d, Checks: idsrule.Selection{Style: true}})
		}
	}
	if idsrule.Check(nil, idsrule.DefaultOptions()) != nil {
		t.Error("Check(nil) returned diagnostics")
	}
}

// TestLint_VersionFollowsDialect checks that a version is applied to the
// files whose detected dialect has it and ignored for the others.
func TestLint_VersionFollowsDialect(t *testing.T) {
	opts := idsrule.DefaultOptions()
	opts.Version = idsrule.VersionSuricata7
	opts.Checks.Enable = []string{"keyword-version"}
	rule := []byte(`alert ftp any any -> any any (msg:"a"; ftp.command; content:"PASS"; sid:1; rev:1;)` + "\n")
	has := func(ds []idsrule.Diagnostic) bool {
		for _, d := range ds {
			if d.Rule == "keyword-version" {
				return true
			}
		}
		return false
	}
	if !has(idsrule.Lint("x.suricata.rules", rule, opts)) {
		t.Error("a Suricata file linted for 7.0 does not report ftp.command, which needs 8.0")
	}
	if ds := idsrule.Lint("x.snort.rules", rule, opts); has(ds) {
		t.Errorf("a Snort file reports keyword-version: %v", ds)
	}
	opts.Version = idsrule.VersionAny
	if ds := idsrule.Lint("x.suricata.rules", rule, opts); has(ds) {
		t.Errorf("with no version, ftp.command is reported: %v", ds)
	}
}

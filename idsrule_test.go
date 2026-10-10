package idsrule_test

import (
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule"
	"github.com/zeroSteiner/idsrule/check"
	"github.com/zeroSteiner/idsrule/diag"
	"github.com/zeroSteiner/idsrule/dialect"
)

func TestDefaultOptions(t *testing.T) {
	o := idsrule.DefaultOptions()
	if err := o.Validate(); err != nil {
		t.Fatalf("DefaultOptions().Validate() = %v, want nil", err)
	}
	if o.Dialect != idsrule.DialectUnknown {
		t.Errorf("DefaultOptions().Dialect = %v, want unknown", o.Dialect)
	}
	if !o.Policy.RequireRev || o.Policy.Style.SpaceAfterSemicolon != idsrule.SpacingRequire {
		t.Errorf("DefaultOptions().Policy = %+v, want check.DefaultPolicy()", o.Policy)
	}
	if o.SIDs != nil {
		t.Errorf("DefaultOptions().SIDs = %v, want nil", o.SIDs)
	}
}

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    idsrule.Options
		wantErr string // substring; empty means no error
	}{
		{name: "zero options", opts: idsrule.Options{}},
		{name: "snort2", opts: idsrule.Options{Dialect: idsrule.DialectSnort2}},
		{name: "suricata", opts: idsrule.Options{Dialect: idsrule.DialectSuricata}},
		{name: "invalid dialect", opts: idsrule.Options{Dialect: idsrule.Dialect(99)}, wantErr: "invalid dialect Dialect(99)"},
		{name: "invalid policy", opts: idsrule.Options{Policy: idsrule.Policy{SIDMin: 5, SIDMax: 1}}, wantErr: "policy: sid range"},
		{name: "invalid checks", opts: idsrule.Options{Checks: idsrule.Selection{Enable: []string{"x"}, Disable: []string{"x"}}}, wantErr: `checks: check "x" is both enabled and disabled`},
		{name: "unknown check ids pass until the registry exists", opts: idsrule.Options{Checks: idsrule.Selection{Enable: []string{"not-a-check"}}}},
		{name: "bad severity", opts: idsrule.Options{Checks: idsrule.Selection{Severity: map[string]idsrule.Severity{"x": "loud"}}}, wantErr: `checks: invalid severity "loud"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDialectFromFilename(t *testing.T) {
	names := []string{
		"x.snort.rule", "x.snort.rules", "x.suricata.rule", "x.suricata.rules",
		"/a/b/c.snort.rule", "x.rule", "X.SNORT.RULE", "",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if got, want := idsrule.DialectFromFilename(name), dialect.FromFilename(name); got != want {
				t.Errorf("DialectFromFilename(%q) = %v, want %v", name, got, want)
			}
		})
	}
	if got := idsrule.DialectFromFilename("local.snort.rule"); got != idsrule.DialectSnort2 {
		t.Errorf("DialectFromFilename(local.snort.rule) = %v, want snort2", got)
	}
}

func TestNewSIDIndex(t *testing.T) {
	x := idsrule.NewSIDIndex()
	if x == nil {
		t.Fatal("NewSIDIndex() = nil")
	}
	x.Add(1, idsrule.SIDRef{File: "a.rule", Line: 1, Column: 1})
	if got := x.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1", got)
	}
}

func TestAliases(t *testing.T) {
	// The re-exported constants must be the same values as the originals so
	// that callers can mix the root package with the sub-packages freely.
	if idsrule.SeverityError != diag.SeverityError || idsrule.SeverityWarning != diag.SeverityWarning {
		t.Error("severity constants differ from diag's")
	}
	if idsrule.DialectUnknown != dialect.Unknown || idsrule.DialectSnort2 != dialect.Snort2 || idsrule.DialectSuricata != dialect.Suricata {
		t.Error("dialect constants differ from dialect's")
	}
	if idsrule.SpacingAny != check.SpacingAny || idsrule.SpacingRequire != check.SpacingRequire || idsrule.SpacingForbid != check.SpacingForbid {
		t.Error("spacing constants differ from check's")
	}
	if got := ruleOf(diag.Diagnostic{Rule: "x"}); got != "x" {
		t.Errorf("Diagnostic alias is not interchangeable with diag.Diagnostic: got %q", got)
	}
}

// ruleOf takes the root alias so that passing a diag.Diagnostic to it proves
// the two types are identical.
func ruleOf(d idsrule.Diagnostic) string { return d.Rule }

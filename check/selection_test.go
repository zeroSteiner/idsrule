package check_test

import (
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/check"
	"github.com/zeroSteiner/idsrule/diag"
)

func TestSelectionValidate(t *testing.T) {
	knownIDs := map[string]bool{"sid-duplicate": true, "rev-missing": true, "msg-prefix": true}
	known := func(id string) bool { return knownIDs[id] }
	allKnown := func(string) bool { return true }

	tests := []struct {
		name    string
		sel     check.Selection
		known   func(string) bool
		wantErr []string // substrings that must each appear in the error; empty means no error
	}{
		{name: "zero selection, nil known", sel: check.Selection{}},
		{name: "zero selection, known", sel: check.Selection{}, known: known},
		{
			name:  "valid selection",
			sel:   check.Selection{Enable: []string{"sid-duplicate"}, Disable: []string{"rev-missing"}, Style: true, Severity: map[string]diag.Severity{"msg-prefix": diag.SeverityError}},
			known: known,
		},
		{
			name:    "overlap",
			sel:     check.Selection{Enable: []string{"a", "b"}, Disable: []string{"b", "c"}},
			known:   allKnown,
			wantErr: []string{`check "b" is both enabled and disabled`},
		},
		{
			name:    "overlap is reported with nil known",
			sel:     check.Selection{Enable: []string{"b"}, Disable: []string{"b"}},
			wantErr: []string{`check "b" is both enabled and disabled`},
		},
		{
			name:    "bad severity",
			sel:     check.Selection{Severity: map[string]diag.Severity{"sid-duplicate": "fatal"}},
			known:   known,
			wantErr: []string{`invalid severity "fatal" for check "sid-duplicate"`},
		},
		{
			name:    "empty severity",
			sel:     check.Selection{Severity: map[string]diag.Severity{"sid-duplicate": ""}},
			wantErr: []string{`invalid severity "" for check "sid-duplicate"`},
		},
		{
			name:    "unknown id in enable",
			sel:     check.Selection{Enable: []string{"sid-duplicate", "nope"}},
			known:   known,
			wantErr: []string{`unknown check id "nope"`},
		},
		{
			name:    "unknown id in disable",
			sel:     check.Selection{Disable: []string{"nope"}},
			known:   known,
			wantErr: []string{`unknown check id "nope"`},
		},
		{
			name:    "unknown id in severity",
			sel:     check.Selection{Severity: map[string]diag.Severity{"nope": diag.SeverityWarning}},
			known:   known,
			wantErr: []string{`unknown check id "nope"`},
		},
		{
			name: "nil known skips id validation",
			sel:  check.Selection{Enable: []string{"nope"}, Disable: []string{"also-nope"}, Severity: map[string]diag.Severity{"still-nope": diag.SeverityWarning}},
		},
		{
			name:    "several errors are joined",
			sel:     check.Selection{Enable: []string{"x"}, Disable: []string{"x"}, Severity: map[string]diag.Severity{"y": "bogus"}},
			known:   known,
			wantErr: []string{`check "x" is both enabled and disabled`, `invalid severity "bogus" for check "y"`, `unknown check id "x"`, `unknown check id "y"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sel.Validate(tt.known)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Validate() = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestSelectionValidateReportsUnknownIDOnce(t *testing.T) {
	sel := check.Selection{
		Enable:   []string{"nope", "nope"},
		Severity: map[string]diag.Severity{"nope": diag.SeverityError},
	}
	err := sel.Validate(func(string) bool { return false })
	if err == nil {
		t.Fatal("Validate() = nil, want error")
	}
	if n := strings.Count(err.Error(), `unknown check id "nope"`); n != 1 {
		t.Errorf("unknown id reported %d times, want 1: %q", n, err)
	}
}

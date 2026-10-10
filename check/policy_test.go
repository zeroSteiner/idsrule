package check_test

import (
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/check"
)

func TestDefaultPolicy(t *testing.T) {
	p := check.DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("DefaultPolicy().Validate() = %v, want nil", err)
	}
	if !p.RequireRev {
		t.Error("DefaultPolicy().RequireRev = false, want true")
	}
	if p.Style.SpaceAfterSemicolon != check.SpacingRequire {
		t.Errorf("DefaultPolicy().Style.SpaceAfterSemicolon = %v, want require", p.Style.SpaceAfterSemicolon)
	}
	if p.Style.SpaceAfterColon != check.SpacingAny {
		t.Errorf("DefaultPolicy().Style.SpaceAfterColon = %v, want any", p.Style.SpaceAfterColon)
	}
	if p.SIDMin != 0 || p.SIDMax != 0 || p.PlaceholderBelow != 0 || p.MsgPrefix != "" || p.NormalizeMsg != nil {
		t.Errorf("DefaultPolicy() has unexpected non-zero fields: %+v", p)
	}
}

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name    string
		policy  check.Policy
		wantErr []string // substrings that must each appear in the error; empty means no error
	}{
		{name: "zero policy", policy: check.Policy{}},
		{name: "sid range ok", policy: check.Policy{SIDMin: 10, SIDMax: 20}},
		{name: "sid range equal", policy: check.Policy{SIDMin: 10, SIDMax: 10}},
		{name: "sid min only", policy: check.Policy{SIDMin: 10}},
		{name: "sid max only", policy: check.Policy{SIDMax: 5}},
		{name: "sid min above max", policy: check.Policy{SIDMin: 10, SIDMax: 5}, wantErr: []string{"SIDMin (10) exceeds SIDMax (5)"}},
		{name: "placeholder below min", policy: check.Policy{PlaceholderBelow: 50, SIDMin: 100}},
		{name: "placeholder equal min", policy: check.Policy{PlaceholderBelow: 100, SIDMin: 100}},
		{name: "placeholder without min", policy: check.Policy{PlaceholderBelow: 100}},
		{name: "placeholder above min", policy: check.Policy{PlaceholderBelow: 100, SIDMin: 50}, wantErr: []string{"PlaceholderBelow (100) exceeds SIDMin (50)"}},
		{name: "space after colon out of range", policy: check.Policy{Style: check.StylePolicy{SpaceAfterColon: check.Spacing(3)}}, wantErr: []string{"Style.SpaceAfterColon"}},
		{name: "space after semicolon out of range", policy: check.Policy{Style: check.StylePolicy{SpaceAfterSemicolon: check.Spacing(250)}}, wantErr: []string{"Style.SpaceAfterSemicolon"}},
		{name: "all spacings valid", policy: check.Policy{Style: check.StylePolicy{SpaceAfterColon: check.SpacingForbid, SpaceAfterSemicolon: check.SpacingRequire}}},
		{
			name:    "multiple errors are joined",
			policy:  check.Policy{SIDMin: 10, SIDMax: 5, PlaceholderBelow: 20, Style: check.StylePolicy{SpaceAfterColon: 9}},
			wantErr: []string{"SIDMin (10) exceeds SIDMax (5)", "PlaceholderBelow (20) exceeds SIDMin (10)", "Style.SpaceAfterColon"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
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

func TestSpacingString(t *testing.T) {
	tests := []struct {
		s    check.Spacing
		want string
	}{
		{check.SpacingAny, "any"},
		{check.SpacingRequire, "require"},
		{check.SpacingForbid, "forbid"},
		{check.Spacing(3), "Spacing(3)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.s.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if got, want := tt.s.Valid(), tt.s <= check.SpacingForbid; got != want {
				t.Errorf("Valid() = %v, want %v", got, want)
			}
		})
	}
}

func TestDefaultNormalizeMsg(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"already clean", "already clean"},
		{"  Hello   World ", "hello world"},
		{"A\t\n  B\r\nC", "a b c"},
		{"MiXeD CaSe", "mixed case"},
		{"À É", "à é"},
		{"VULNCHECK CVE-2021-21315   Command Injection", "vulncheck cve-2021-21315 command injection"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := check.DefaultNormalizeMsg(tt.in); got != tt.want {
				t.Errorf("DefaultNormalizeMsg(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

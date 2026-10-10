package dialect_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule/dialect"
)

func TestFromFilename(t *testing.T) {
	tests := []struct {
		name string
		want dialect.Dialect
	}{
		{"x.snort.rule", dialect.Snort2},
		{"x.snort.rules", dialect.Snort2},
		{"x.suricata.rule", dialect.Suricata},
		{"x.suricata.rules", dialect.Suricata},
		{"/abs/path/to/cve-2021-21315.snort.rule", dialect.Snort2},
		{"rel/dir/local.suricata.rules", dialect.Suricata},
		{".snort.rule", dialect.Snort2},
		{"snort.rule", dialect.Unknown},
		{"X.SNORT.RULE", dialect.Unknown},
		{"x.Snort.rule", dialect.Unknown},
		{"x.suricata.RULES", dialect.Unknown},
		{"x.rule", dialect.Unknown},
		{"x.rules", dialect.Unknown},
		{"x.snort.rule.bak", dialect.Unknown},
		{"dir.snort.rule/x", dialect.Unknown},
		{"", dialect.Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dialect.FromFilename(tt.name); got != tt.want {
				t.Errorf("FromFilename(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestDialectString(t *testing.T) {
	tests := []struct {
		d    dialect.Dialect
		want string
	}{
		{dialect.Unknown, "unknown"},
		{dialect.Snort2, "snort2"},
		{dialect.Suricata, "suricata"},
		{dialect.Dialect(7), "Dialect(7)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.d.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDialectValid(t *testing.T) {
	tests := []struct {
		d    dialect.Dialect
		want bool
	}{
		{dialect.Unknown, true},
		{dialect.Snort2, true},
		{dialect.Suricata, true},
		{dialect.Dialect(3), false},
		{dialect.Dialect(255), false},
	}
	for _, tt := range tests {
		t.Run(tt.d.String(), func(t *testing.T) {
			if got := tt.d.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDialectSet(t *testing.T) {
	tests := []struct {
		d    dialect.Dialect
		want dialect.Set
	}{
		{dialect.Unknown, 0},
		{dialect.Snort2, dialect.SetSnort2},
		{dialect.Suricata, dialect.SetSuricata},
		{dialect.Dialect(9), 0},
	}
	for _, tt := range tests {
		t.Run(tt.d.String(), func(t *testing.T) {
			if got := tt.d.Set(); got != tt.want {
				t.Errorf("Set() = %b, want %b", got, tt.want)
			}
		})
	}
}

func TestSetHas(t *testing.T) {
	tests := []struct {
		name string
		set  dialect.Set
		d    dialect.Dialect
		want bool
	}{
		{"both has snort2", dialect.Both, dialect.Snort2, true},
		{"both has suricata", dialect.Both, dialect.Suricata, true},
		{"both lacks unknown", dialect.Both, dialect.Unknown, false},
		{"snort2 has snort2", dialect.SetSnort2, dialect.Snort2, true},
		{"snort2 lacks suricata", dialect.SetSnort2, dialect.Suricata, false},
		{"suricata has suricata", dialect.SetSuricata, dialect.Suricata, true},
		{"suricata lacks snort2", dialect.SetSuricata, dialect.Snort2, false},
		{"empty lacks snort2", 0, dialect.Snort2, false},
		{"empty lacks unknown", 0, dialect.Unknown, false},
		{"undefined dialect", dialect.Both, dialect.Dialect(9), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.set.Has(tt.d); got != tt.want {
				t.Errorf("Set(%b).Has(%v) = %v, want %v", tt.set, tt.d, got, tt.want)
			}
		})
	}
}

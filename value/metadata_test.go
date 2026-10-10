package value_test

import (
	"slices"
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParseMetadata(t *testing.T) {
	entry := func(k, v string) value.MetadataEntry { return value.MetadataEntry{Key: k, Value: v} }
	tests := []struct {
		in   string
		want []value.MetadataEntry
		err  int
	}{
		{"deployment Datacenter, deployment SSLDecrypt", []value.MetadataEntry{entry("deployment", "Datacenter"), entry("deployment", "SSLDecrypt")}, noErr},
		{"created_at 2026_01_01", []value.MetadataEntry{entry("created_at", "2026_01_01")}, noErr},
		{"deployment Datacenter,impact successful-exploitation", []value.MetadataEntry{entry("deployment", "Datacenter"), entry("impact", "successful-exploitation")}, noErr},
		{"a b c", []value.MetadataEntry{entry("a", "b c")}, noErr},
		{"a  b", []value.MetadataEntry{entry("a", "b")}, noErr},
		{"a\tb", []value.MetadataEntry{entry("a", "b")}, noErr},
		{"key", []value.MetadataEntry{entry("key", "")}, noErr},
		{"a , b", []value.MetadataEntry{entry("a", ""), entry("b", "")}, noErr},
		{"a,,b", nil, 2},
		{"a, ,b", nil, 3},
		{"a,", nil, 2},
		{"a, ", nil, 3},
		{",a", nil, 0},
		{"", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseMetadata(tt.in)
			checkErr(t, err, tt.err)
			if !slices.Equal(got.Entries, tt.want) {
				t.Errorf("ParseMetadata(%q) = %+v, want %+v", tt.in, got.Entries, tt.want)
			}
		})
	}
}

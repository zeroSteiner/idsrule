package value_test

import (
	"slices"
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParseFlowbits(t *testing.T) {
	tests := []struct {
		in   string
		want value.Flowbits
		err  int
	}{
		{"set,a", value.Flowbits{Verb: "set", Names: []string{"a"}}, noErr},
		{"set,a|b", value.Flowbits{Verb: "set", Names: []string{"a", "b"}}, noErr},
		{"isset, a", value.Flowbits{Verb: "isset", Names: []string{"a"}}, noErr},
		{"isset, a | b", value.Flowbits{Verb: "isset", Names: []string{"a", "b"}}, noErr},
		{"noalert", value.Flowbits{Verb: "noalert"}, noErr},
		{"set,vc-cve-2026-20253-restore", value.Flowbits{Verb: "set", Names: []string{"vc-cve-2026-20253-restore"}}, noErr},
		{"unset,a", value.Flowbits{Verb: "unset", Names: []string{"a"}}, noErr},
		{"toggle,a", value.Flowbits{Verb: "toggle", Names: []string{"a"}}, noErr},
		{"isnotset,a", value.Flowbits{Verb: "isnotset", Names: []string{"a"}}, noErr},
		{"setx,a", value.Flowbits{Verb: "setx", Names: []string{"a"}}, noErr},
		{"reset", value.Flowbits{Verb: "reset"}, noErr},
		{"reset,a", value.Flowbits{Verb: "reset", Names: []string{"a"}}, noErr},
		{"set,a,grp", value.Flowbits{Verb: "set", Names: []string{"a"}, Group: "grp"}, noErr},
		{"set, a , grp ", value.Flowbits{Verb: "set", Names: []string{"a"}, Group: "grp"}, noErr},
		{"isset,a&b", value.Flowbits{Verb: "isset", Names: []string{"a&b"}}, noErr},
		{"set", value.Flowbits{}, 3},
		{"isset", value.Flowbits{}, 5},
		{"set,", value.Flowbits{}, 4},
		{"set, ", value.Flowbits{}, 5},
		{"set,,g", value.Flowbits{}, 4},
		{"set,a|", value.Flowbits{}, 6},
		{"set, |b", value.Flowbits{}, 5},
		{"set,a,", value.Flowbits{}, 6},
		{"set,a,b,c", value.Flowbits{}, 7},
		{"noalert,a", value.Flowbits{}, 7},
		{"frob,a", value.Flowbits{}, 0},
		{"Set,a", value.Flowbits{}, 0},
		{"", value.Flowbits{}, 0},
		{",a", value.Flowbits{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseFlowbits(tt.in)
			checkErr(t, err, tt.err)
			if got.Verb != tt.want.Verb || !slices.Equal(got.Names, tt.want.Names) || got.Group != tt.want.Group {
				t.Errorf("ParseFlowbits(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

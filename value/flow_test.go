package value_test

import (
	"slices"
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParseFlow(t *testing.T) {
	tests := []struct {
		in   string
		want []string
		err  int
	}{
		{"established,to_server", []string{"established", "to_server"}, noErr},
		{"established, to_server", []string{"established", "to_server"}, noErr},
		{"to_server,established", []string{"to_server", "established"}, noErr},
		{"established,from_server", []string{"established", "from_server"}, noErr},
		{"established", []string{"established"}, noErr},
		{"not_established", []string{"not_established"}, noErr},
		{"stateless,to_client", []string{"stateless", "to_client"}, noErr},
		{"established,to_server,only_stream,no_frag", []string{"established", "to_server", "only_stream", "no_frag"}, noErr},
		{"established\t,\tto_server", []string{"established", "to_server"}, noErr},
		{"ESTABLISHED,To_Server", []string{"ESTABLISHED", "To_Server"}, noErr},
		{"Established", []string{"Established"}, noErr},
		{"Established,established", nil, 12},
		{"to_client,TO_SERVER", nil, 10},
		{"to_client,to_server", nil, 10},
		{"to_client,from_server", nil, 10},
		{"from_client, to_server", nil, 13},
		{"established,established", nil, 12},
		{"established,stateless", nil, 12},
		{"established,not_established", nil, 12},
		{"only_stream,no_stream", nil, 12},
		{"no_frag, only_frag", nil, 9},
		{"established,x", nil, 12},
		{"established,", nil, 12},
		{",established", nil, 0},
		{"", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseFlow(tt.in)
			checkErr(t, err, tt.err)
			if !slices.Equal(got.Tokens, tt.want) {
				t.Errorf("ParseFlow(%q) = %q, want %q", tt.in, got.Tokens, tt.want)
			}
		})
	}
}

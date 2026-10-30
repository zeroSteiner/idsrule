package value_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParseThreshold(t *testing.T) {
	tests := []struct {
		in   string
		want value.Threshold
		err  int
	}{
		{"type limit, track by_src, count 1, seconds 60", value.Threshold{Type: "limit", Track: "by_src", Count: 1, Seconds: 60, HasType: true}, noErr},
		// Suricata 8's backoff.
		{"type backoff, track by_flow, count 1, multiplier 10", value.Threshold{Type: "backoff", Track: "by_flow", Count: 1, Multiplier: 10, HasType: true, HasMultiplier: true}, noErr},
		{"type backoff, track by_flow, count 65535, multiplier 65535", value.Threshold{Type: "backoff", Track: "by_flow", Count: 65535, Multiplier: 65535, HasType: true, HasMultiplier: true}, noErr},
		{"type limit, track by_src, count 1, seconds 60, multiplier 3", value.Threshold{Type: "limit", Track: "by_src", Count: 1, Seconds: 60, Multiplier: 3, HasType: true, HasMultiplier: true}, noErr},
		{"type backoff, track by_flow, count 1", value.Threshold{}, 36},
		{"type backoff, track by_flow, count 1, multiplier 10, seconds 5", value.Threshold{}, 0},
		{"type backoff, track by_src, count 1, multiplier 10", value.Threshold{}, 0},
		{"type backoff, track by_flow, count 0, multiplier 10", value.Threshold{}, 0},
		{"type backoff, track by_flow, count 1, multiplier 1", value.Threshold{}, 0},
		{"type backoff, track by_flow, count 1, multiplier 65536", value.Threshold{}, 0},
		{"track by_src, count 1, seconds 60, multiplier 2", value.Threshold{}, 0},
		{"track by_src, count 1, seconds 60", value.Threshold{Track: "by_src", Count: 1, Seconds: 60}, noErr},
		{"type both,track by_src,count 0,seconds 0", value.Threshold{Type: "both", Track: "by_src", HasType: true}, noErr},
		{"seconds 60, count 1, track by_dst, type threshold", value.Threshold{Type: "threshold", Track: "by_dst", Count: 1, Seconds: 60, HasType: true}, noErr},
		{"type limit, track by_rule, count 1, seconds 1", value.Threshold{Type: "limit", Track: "by_rule", Count: 1, Seconds: 1, HasType: true}, noErr},
		{"type limit, track by_both, count 1, seconds 1", value.Threshold{Type: "limit", Track: "by_both", Count: 1, Seconds: 1, HasType: true}, noErr},
		{"type limit, track by_flow, count 1, seconds 1", value.Threshold{Type: "limit", Track: "by_flow", Count: 1, Seconds: 1, HasType: true}, noErr},
		{"type  limit ,  track\tby_src , count 1 , seconds 60", value.Threshold{Type: "limit", Track: "by_src", Count: 1, Seconds: 60, HasType: true}, noErr},
		{"type limit, track by_src, seconds 60", value.Threshold{}, 36},
		{"type limit, track by_src, count 1", value.Threshold{}, 33},
		{"type limit, count 1, seconds 60", value.Threshold{}, 31},
		{"type limit, track by_src, count 1, count 2, seconds 60", value.Threshold{}, 35},
		{"type limit, type limit, track by_src, count 1, seconds 60", value.Threshold{}, 12},
		{"type x, track by_src, count 1, seconds 1", value.Threshold{}, 5},
		{"type, track by_src, count 1, seconds 1", value.Threshold{}, 4},
		{"track by_x, count 1, seconds 1", value.Threshold{}, 6},
		{"count x, track by_src, seconds 1", value.Threshold{}, 6},
		{"count, track by_src, seconds 1", value.Threshold{}, 5},
		{"count -1, track by_src, seconds 1", value.Threshold{}, 6},
		{"count 18446744073709551615, track by_src, seconds 1", value.Threshold{}, 6},
		{"foo 1, track by_src, count 1, seconds 1", value.Threshold{}, 0},
		{"type limit, , track by_src, count 1, seconds 1", value.Threshold{}, 12},
		{"type limit, track by_src, count 1, seconds 1,", value.Threshold{}, 45},
		{"", value.Threshold{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseThreshold(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseThreshold(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

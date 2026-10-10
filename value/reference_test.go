package value_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParseReference(t *testing.T) {
	tests := []struct {
		in   string
		want value.Reference
		err  int
	}{
		{"cve,2026-1234", value.Reference{Scheme: "cve", ID: "2026-1234"}, noErr},
		{"cve,CVE-2026-63077", value.Reference{Scheme: "cve", ID: "CVE-2026-63077"}, noErr},
		{"url,example.com/x?a=1,b", value.Reference{Scheme: "url", ID: "example.com/x?a=1,b"}, noErr},
		{"url,https://github.com/x/y", value.Reference{Scheme: "url", ID: "https://github.com/x/y"}, noErr},
		{"cve, 2026-1234", value.Reference{Scheme: "cve", ID: "2026-1234"}, noErr},
		{"cve ,2026-1234", value.Reference{Scheme: "cve", ID: "2026-1234"}, noErr},
		{"bugtraq,1", value.Reference{Scheme: "bugtraq", ID: "1"}, noErr},
		{"md5_sum,abc", value.Reference{Scheme: "md5_sum", ID: "abc"}, noErr},
		{"cve", value.Reference{}, 3},
		{"", value.Reference{}, 0},
		{",x", value.Reference{}, 0},
		{" ,x", value.Reference{}, 1},
		{"cve,", value.Reference{}, 4},
		{"cve, ", value.Reference{}, 5},
		{"c-ve,x", value.Reference{}, 1},
		{"c ve,x", value.Reference{}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseReference(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseReference(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

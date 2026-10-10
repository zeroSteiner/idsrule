package value_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParsePCRE(t *testing.T) {
	tests := []struct {
		in   string
		want value.PCRE
		err  int
	}{
		{`"/abc/i"`, value.PCRE{Pattern: "abc", Flags: "i"}, noErr},
		{`"/abc/"`, value.PCRE{Pattern: "abc"}, noErr},
		{`"/a(?:\;|%3b)/i"`, value.PCRE{Pattern: `a(?:\;|%3b)`, Flags: "i"}, noErr},
		{`!"/x/"`, value.PCRE{Negated: true, Pattern: "x"}, noErr},
		{`! "/x/"`, value.PCRE{Negated: true, Pattern: "x"}, noErr},
		{`"/a\/b/"`, value.PCRE{Pattern: `a\/b`}, noErr},
		{`"/a/b/Pis"`, value.PCRE{Pattern: "a/b", Flags: "Pis"}, noErr},
		{`"/content"\S*?:.*(x)/"`, value.PCRE{Pattern: `content"\S*?:.*(x)`}, noErr},
		{`"/\x22user-id\x22\s*:/P"`, value.PCRE{Pattern: `\x22user-id\x22\s*:`, Flags: "P"}, noErr},
		{`"//"`, value.PCRE{}, noErr},
		{`"/x/Ui"`, value.PCRE{Pattern: "x", Flags: "Ui"}, noErr},
		{`"m|a|i"`, value.PCRE{Pattern: "a", Flags: "i"}, noErr},
		{`"m#a/b#"`, value.PCRE{Pattern: "a/b"}, noErr},
		{`"m/a/i"`, value.PCRE{Pattern: "a", Flags: "i"}, noErr},
		{`!"m!a!b!"`, value.PCRE{Negated: true, Pattern: "a!b"}, noErr},
		{`"m,,"`, value.PCRE{}, noErr},
		{`"m"`, value.PCRE{}, 2},
		{`"mabc"`, value.PCRE{}, 2},
		{`"m1a1"`, value.PCRE{}, 2},
		{`"m a "`, value.PCRE{}, 2},
		{`"m|a"`, value.PCRE{}, 4},
		{`"m|a|Z!"`, value.PCRE{}, 6},
		{`"/a/Z!"`, value.PCRE{}, 5},
		{`"/a/i1"`, value.PCRE{}, 5},
		{`/a/i`, value.PCRE{}, 0},
		{`"abc"`, value.PCRE{}, 1},
		{`"/abc"`, value.PCRE{}, 5},
		{`"/x/`, value.PCRE{}, 4},
		{`"/x/" i`, value.PCRE{}, 5},
		{`"/x/"i`, value.PCRE{}, 5},
		{`""`, value.PCRE{}, 1},
		{``, value.PCRE{}, 0},
		{`!`, value.PCRE{}, 1},
		{`"`, value.PCRE{}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParsePCRE(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParsePCRE(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

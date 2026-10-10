package value_test

import (
	"bytes"
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParseContent(t *testing.T) {
	tests := []struct {
		in   string
		want value.Content
		err  int
	}{
		{`"abc"`, value.Content{Pattern: []byte("abc")}, noErr},
		{`!"abc"`, value.Content{Negated: true, Pattern: []byte("abc")}, noErr},
		{`! "abc"`, value.Content{Negated: true, Pattern: []byte("abc")}, noErr},
		{`"a\"b"`, value.Content{Pattern: []byte(`a"b`)}, noErr},
		{`"a\\b"`, value.Content{Pattern: []byte(`a\b`)}, noErr},
		{`"a\;b"`, value.Content{Pattern: []byte(`a;b`)}, noErr},
		{`"a\:b"`, value.Content{Pattern: []byte(`a:b`)}, noErr},
		{`"a\|b"`, value.Content{Pattern: []byte(`a|b`)}, noErr},
		{`"\"backupFile\""`, value.Content{Pattern: []byte(`"backupFile"`)}, noErr},
		{`"\\n-if\\n"`, value.Content{Pattern: []byte(`\n-if\n`)}, noErr},
		{`"|89|HDF|0d 0a 1a 0a|"`, value.Content{Pattern: []byte{0x89, 'H', 'D', 'F', 0x0d, 0x0a, 0x1a, 0x0a}}, noErr},
		{`"|00 0F|x"`, value.Content{Pattern: []byte{0x00, 0x0f, 'x'}}, noErr},
		{`"|7f|ELF"`, value.Content{Pattern: []byte{0x7f, 'E', 'L', 'F'}}, noErr},
		{`"|3b| --'|0d 0a|"`, value.Content{Pattern: []byte{';', ' ', '-', '-', '\'', 0x0d, 0x0a}}, noErr},
		{`"|dc 07 00 00|"`, value.Content{Pattern: []byte{0xdc, 0x07, 0, 0}}, noErr},
		{`"|0 1|"`, value.Content{Pattern: []byte{0x01}}, noErr},
		{`"| 00 |"`, value.Content{Pattern: []byte{0x00}}, noErr},
		{`"x", nocase`, value.Content{Pattern: []byte("x"), Trailing: ", nocase"}, noErr},
		{`!"Cookie", nocase`, value.Content{Negated: true, Pattern: []byte("Cookie"), Trailing: ", nocase"}, noErr},
		{`"/api/plugin", depth 11`, value.Content{Pattern: []byte("/api/plugin"), Trailing: ", depth 11"}, noErr},
		{`"x"  , fast_pattern  `, value.Content{Pattern: []byte("x"), Trailing: ", fast_pattern"}, noErr},
		{`"x"y`, value.Content{Pattern: []byte("x"), Trailing: "y"}, noErr},
		{`"|0|"`, value.Content{}, 3},
		{`"|abc|"`, value.Content{}, 5},
		{`"|zz|"`, value.Content{}, 2},
		{`"|0g|"`, value.Content{}, 3},
		{`"|00"|"`, value.Content{}, 4},
		{`"|00`, value.Content{}, 4},
		{`""`, value.Content{}, 1},
		{`!""`, value.Content{}, 2},
		{`abc`, value.Content{}, 0},
		{``, value.Content{}, 0},
		{`!`, value.Content{}, 1},
		{`! x`, value.Content{}, 2},
		{`"abc`, value.Content{}, 4},
		{`"a\"`, value.Content{}, 4},
		{`"a\`, value.Content{}, 2},
		{`"a\nb"`, value.Content{}, 2},
		{`"ab\x"`, value.Content{}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseContent(tt.in)
			checkErr(t, err, tt.err)
			if got.Negated != tt.want.Negated || !bytes.Equal(got.Pattern, tt.want.Pattern) || got.Trailing != tt.want.Trailing {
				t.Errorf("ParseContent(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

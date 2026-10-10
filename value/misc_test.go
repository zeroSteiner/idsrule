package value_test

import (
	"slices"
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParseIsDataAt(t *testing.T) {
	tests := []struct {
		in   string
		want value.IsDataAt
		err  int
	}{
		{"10", value.IsDataAt{Offset: 10}, noErr},
		{"!10,relative", value.IsDataAt{Negated: true, Offset: 10, Relative: true}, noErr},
		{"$v", value.IsDataAt{Var: "$v"}, noErr},
		{"10,rawbytes", value.IsDataAt{Offset: 10, Rawbytes: true}, noErr},
		{"10,relative,rawbytes", value.IsDataAt{Offset: 10, Relative: true, Rawbytes: true}, noErr},
		{"10, rawbytes , relative", value.IsDataAt{Offset: 10, Relative: true, Rawbytes: true}, noErr},
		{"len,relative", value.IsDataAt{Var: "len", Relative: true}, noErr},
		{"! 10", value.IsDataAt{Negated: true, Offset: 10}, noErr},
		{"!$v,relative", value.IsDataAt{Negated: true, Var: "$v", Relative: true}, noErr},
		{"0", value.IsDataAt{}, noErr},
		{"10,relative,relative", value.IsDataAt{}, 12},
		{"10,rawbytes,rawbytes", value.IsDataAt{}, 12},
		{"10,x", value.IsDataAt{}, 3},
		{"10,", value.IsDataAt{}, 3},
		{"10, ", value.IsDataAt{}, 4},
		{"-1", value.IsDataAt{}, 0},
		{"1x", value.IsDataAt{}, 1},
		{"x-y", value.IsDataAt{}, 1},
		{"!", value.IsDataAt{}, 1},
		{"! x-y", value.IsDataAt{}, 3},
		{"", value.IsDataAt{}, 0},
		{",relative", value.IsDataAt{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseIsDataAt(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseIsDataAt(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseFastPattern(t *testing.T) {
	tests := []struct {
		in   string
		want value.FastPattern
		err  int
	}{
		{"", value.FastPattern{}, noErr},
		{"only", value.FastPattern{Only: true}, noErr},
		{"3,4", value.FastPattern{Offset: 3, Length: 4, Chunk: true}, noErr},
		{"0,20", value.FastPattern{Length: 20, Chunk: true}, noErr},
		{"3, 4", value.FastPattern{Offset: 3, Length: 4, Chunk: true}, noErr},
		{" 3 , 4 ", value.FastPattern{Offset: 3, Length: 4, Chunk: true}, noErr},
		{"x", value.FastPattern{}, 0},
		{"Only", value.FastPattern{}, 0},
		{"3", value.FastPattern{}, 0},
		{"3,4,5", value.FastPattern{}, 0},
		{"3,x", value.FastPattern{}, 2},
		{"x,4", value.FastPattern{}, 0},
		{"3,", value.FastPattern{}, 2},
		{",4", value.FastPattern{}, 0},
		{"only,1", value.FastPattern{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseFastPattern(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseFastPattern(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseBase64Decode(t *testing.T) {
	tests := []struct {
		in   string
		want value.Base64Decode
		err  int
	}{
		{"", value.Base64Decode{}, noErr},
		{"bytes 10, offset 2, relative", value.Base64Decode{Bytes: 10, Offset: 2, Relative: true}, noErr},
		{"bytes 4096, offset 0, relative", value.Base64Decode{Bytes: 4096, Relative: true}, noErr},
		{"relative", value.Base64Decode{Relative: true}, noErr},
		{"offset 5", value.Base64Decode{Offset: 5}, noErr},
		{"relative, bytes 1", value.Base64Decode{Bytes: 1, Relative: true}, noErr},
		{"bytes\t10", value.Base64Decode{Bytes: 10}, noErr},
		{"bytes 10, bytes 5", value.Base64Decode{}, 10},
		{"relative,relative", value.Base64Decode{}, 9},
		{"bytes", value.Base64Decode{}, 5},
		{"bytes x", value.Base64Decode{}, 6},
		{"bytes 1x", value.Base64Decode{}, 7},
		{"relative 1", value.Base64Decode{}, 9},
		{"foo", value.Base64Decode{}, 0},
		{"bytes 1,,relative", value.Base64Decode{}, 8},
		{", relative", value.Base64Decode{}, 0},
		{"relative,", value.Base64Decode{}, 9},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseBase64Decode(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseBase64Decode(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseQuoted(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  int
	}{
		{`"abc"`, "abc", noErr},
		{`""`, "", noErr},
		{`"a\"b"`, `a"b`, noErr},
		{`"a\\b"`, `a\b`, noErr},
		{`"a\;b"`, `a;b`, noErr},
		{`"a\:b"`, `a:b`, noErr},
		{`"\"\\;\:"`, `"\;:`, noErr},
		{`"x (y)"`, "x (y)", noErr},
		{`"a|00|b"`, "a|00|b", noErr},
		{`"it\'s"`, "it's", noErr},
		{`"\w\x\y"`, "wxy", noErr},
		{`"\\"`, `\`, noErr},
		{`"a\nb"`, "anb", noErr},
		{`"a\|b"`, "a|b", noErr},
		{`"msg escape tests \w\x\y\'\"\\;\:"`, `msg escape tests wxy'"\;:`, noErr},
		{`abc`, "", 0},
		{`"abc`, "", 4},
		{`"abc\`, "", 4},
		{`"a\`, "", 2},
		{`"a\"`, "", 4},
		{`"\`, "", 1},
		{`"a" x`, "", 4},
		{`"a"x`, "", 3},
		{`"a""`, "", 3},
		{``, "", 0},
		{`'a'`, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseQuoted(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseQuoted(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseIdent(t *testing.T) {
	tests := []struct {
		in  string
		err int
	}{
		{"web-application-attack", noErr},
		{"a.b_c-1", noErr},
		{"A", noErr},
		{"0", noErr},
		{"http.host_header_ambiguous", noErr},
		{"", 0},
		{"a b", 1},
		{"a!", 1},
		{"!a", 0},
		{"a,b", 1},
		{"a/b", 1},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseIdent(tt.in)
			checkErr(t, err, tt.err)
			if tt.err == noErr && got != tt.in {
				t.Errorf("ParseIdent(%q) = %q", tt.in, got)
			}
			if tt.err != noErr && got != "" {
				t.Errorf("ParseIdent(%q) = %q with an error", tt.in, got)
			}
		})
	}
}

func TestParseCSV(t *testing.T) {
	tests := []struct {
		in   string
		want []string
		err  int
	}{
		{"a,b", []string{"a", "b"}, noErr},
		{"a, b ,c", []string{"a", "b", "c"}, noErr},
		{"a", []string{"a"}, noErr},
		{"username,password", []string{"username", "password"}, noErr},
		{"a b,c", []string{"a b", "c"}, noErr},
		{"", nil, 0},
		{" ", nil, 1},
		{"a,,b", nil, 2},
		{"a, ,b", nil, 3},
		{"a,", nil, 2},
		{",a", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseCSV(tt.in)
			checkErr(t, err, tt.err)
			if !slices.Equal(got, tt.want) {
				t.Errorf("ParseCSV(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

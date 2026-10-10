package value_test

import (
	"testing"

	"github.com/zeroSteiner/idsrule/value"
)

func TestParseUint(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		err  int
	}{
		{"0", 0, noErr},
		{"1", 1, noErr},
		{"007", 7, noErr},
		{"12900118", 12900118, noErr},
		{"18446744073709551615", 18446744073709551615, noErr},
		{"18446744073709551616", 0, 0},
		{"99999999999999999999999", 0, 0},
		{"-1", 0, 0},
		{"+1", 0, 0},
		{" 1", 0, 0},
		{"1 ", 0, 1},
		{"1a", 0, 1},
		{"0x10", 0, 1},
		{"", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseUint(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseUint(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseIntOrVar(t *testing.T) {
	tests := []struct {
		in   string
		want value.IntOrVar
		err  int
	}{
		{"10", value.IntOrVar{Value: 10}, noErr},
		{"0", value.IntOrVar{}, noErr},
		{"-10", value.IntOrVar{Value: -10}, noErr},
		{"+5", value.IntOrVar{Value: 5}, noErr},
		{"9223372036854775807", value.IntOrVar{Value: 9223372036854775807}, noErr},
		{"-9223372036854775808", value.IntOrVar{Value: -9223372036854775808}, noErr},
		{"$v", value.IntOrVar{Var: "$v"}, noErr},
		{"$HOME_NET", value.IntOrVar{Var: "$HOME_NET"}, noErr},
		{"len", value.IntOrVar{Var: "len"}, noErr},
		{"_x1", value.IntOrVar{Var: "_x1"}, noErr},
		{"9223372036854775808", value.IntOrVar{}, 0},
		{"$", value.IntOrVar{}, 1},
		{"$a-b", value.IntOrVar{}, 2},
		{"a b", value.IntOrVar{}, 1},
		{"-", value.IntOrVar{}, 1},
		{"+", value.IntOrVar{}, 1},
		{"1x", value.IntOrVar{}, 1},
		{"-1x", value.IntOrVar{}, 2},
		{" 1", value.IntOrVar{}, 0},
		{"", value.IntOrVar{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseIntOrVar(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseIntOrVar(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseRelInt(t *testing.T) {
	tests := []struct {
		in   string
		want value.RelInt
		err  int
	}{
		{"100", value.RelInt{A: 100}, noErr},
		{"0", value.RelInt{}, noErr},
		{"<100", value.RelInt{Op: "<", A: 100}, noErr},
		{">100", value.RelInt{Op: ">", A: 100}, noErr},
		{"<=5", value.RelInt{Op: "<=", A: 5}, noErr},
		{">=5", value.RelInt{Op: ">=", A: 5}, noErr},
		{"=5", value.RelInt{Op: "=", A: 5}, noErr},
		{"!5", value.RelInt{Op: "!", A: 5}, noErr},
		{"!=5", value.RelInt{Op: "!", A: 5}, noErr},
		{"> 100", value.RelInt{Op: ">", A: 100}, noErr},
		{"100<>200", value.RelInt{Op: "<>", A: 100, B: 200}, noErr},
		{"100 <> 200", value.RelInt{Op: "<>", A: 100, B: 200}, noErr},
		{"100-200", value.RelInt{Op: "-", A: 100, B: 200}, noErr},
		{"3 - 5", value.RelInt{Op: "-", A: 3, B: 5}, noErr},
		{"100<>50", value.RelInt{}, 5},
		{"5<>5", value.RelInt{}, 3},
		{"5-5", value.RelInt{}, 2},
		{"<>", value.RelInt{}, 1},
		{"<>5", value.RelInt{}, 1},
		{"", value.RelInt{}, 0},
		{"abc", value.RelInt{}, 0},
		{">", value.RelInt{}, 1},
		{"<<5", value.RelInt{}, 1},
		{"100<>", value.RelInt{}, 5},
		{"100-", value.RelInt{}, 4},
		{">5<>6", value.RelInt{}, 2},
		{"5 x", value.RelInt{}, 2},
		{"5<>6 x", value.RelInt{}, 5},
		{"5<>6<>7", value.RelInt{}, 4},
		{"-5", value.RelInt{}, 0},
		{"99999999999999999999", value.RelInt{}, 0},
		{"1<>99999999999999999999", value.RelInt{}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseRelInt(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseRelInt(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseUrilen(t *testing.T) {
	tests := []struct {
		in   string
		want value.Urilen
		err  int
	}{
		{"<10", value.Urilen{RelInt: value.RelInt{Op: "<", A: 10}}, noErr},
		{"10", value.Urilen{RelInt: value.RelInt{A: 10}}, noErr},
		{">20,raw", value.Urilen{RelInt: value.RelInt{Op: ">", A: 20}, Buffer: "raw"}, noErr},
		{"10<>20,norm", value.Urilen{RelInt: value.RelInt{Op: "<>", A: 10, B: 20}, Buffer: "norm"}, noErr},
		{"5, norm", value.Urilen{RelInt: value.RelInt{A: 5}, Buffer: "norm"}, noErr},
		{"5 ,norm", value.Urilen{RelInt: value.RelInt{A: 5}, Buffer: "norm"}, noErr},
		{"5\t,\traw", value.Urilen{RelInt: value.RelInt{A: 5}, Buffer: "raw"}, noErr},
		{"5,x", value.Urilen{}, 2},
		{"5,norm,raw", value.Urilen{}, 2},
		{"5,", value.Urilen{}, 2},
		{"5, ", value.Urilen{}, 3},
		{"5,NORM", value.Urilen{}, 2},
		{",norm", value.Urilen{}, 0},
		{"<>,norm", value.Urilen{}, 1},
		{"10<>5,norm", value.Urilen{}, 4},
		{"x,raw", value.Urilen{}, 0},
		{"", value.Urilen{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseUrilen(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseUrilen(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

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
		// Suricata 8: hex numbers and size units.
		{"0x10", value.RelInt{A: 16, Forms: value.FormHex}, noErr},
		{"0xfF", value.RelInt{A: 255, Forms: value.FormHex}, noErr},
		{">=0x10", value.RelInt{Op: ">=", A: 16, Forms: value.FormHex}, noErr},
		{"0x10-0x20", value.RelInt{Op: "-", A: 16, B: 32, Forms: value.FormHex}, noErr},
		{"0x7fffffffffffffff", value.RelInt{A: 1<<63 - 1, Forms: value.FormHex}, noErr},
		{"0x8000000000000000", value.RelInt{}, 0},
		{"0X10", value.RelInt{}, 1},
		{"0x", value.RelInt{}, 1},
		{"0xg", value.RelInt{}, 1},
		{"10kb", value.RelInt{A: 10 << 10, Forms: value.FormUnit}, noErr},
		{"1KiB", value.RelInt{A: 1 << 10, Forms: value.FormIECUnit}, noErr},
		{">10MB", value.RelInt{Op: ">", A: 10 << 20, Forms: value.FormUnit}, noErr},
		{"2mib", value.RelInt{A: 2 << 20, Forms: value.FormIECUnit}, noErr},
		{"1Gb", value.RelInt{A: 1 << 30, Forms: value.FormUnit}, noErr},
		{"3GiB", value.RelInt{A: 3 << 30, Forms: value.FormIECUnit}, noErr},
		{"0kb", value.RelInt{Forms: value.FormUnit}, noErr},
		{"1kb<>2kb", value.RelInt{Op: "<>", A: 1 << 10, B: 2 << 10, Forms: value.FormUnit}, noErr},
		{"9999999999gb", value.RelInt{}, 0},
		{"10 kb", value.RelInt{}, 3},
		{"10k", value.RelInt{}, 2},
		{"10kbx", value.RelInt{}, 4},
		{"0x10kb", value.RelInt{}, 4},
		// Suricata 8: negated ranges.
		{"!5-10", value.RelInt{Op: "!-", A: 5, B: 10, Forms: value.FormNegatedRange}, noErr},
		{"!5<>10", value.RelInt{Op: "!<>", A: 5, B: 10, Forms: value.FormNegatedRange}, noErr},
		{"! 5 - 10", value.RelInt{Op: "!-", A: 5, B: 10, Forms: value.FormNegatedRange}, noErr},
		{"!10-5", value.RelInt{}, 4},
		{"!=5-10", value.RelInt{}, 3},
		{"<5-10", value.RelInt{}, 2},
		// Suricata 8: bitmask tests.
		{"&0xc0=0x80", value.RelInt{Op: "&=", A: 0xc0, B: 0x80, Forms: value.FormBitmask | value.FormHex}, noErr},
		{"&0x40!=0", value.RelInt{Op: "&!=", A: 0x40, Forms: value.FormBitmask | value.FormHex}, noErr},
		{" & 0xc0 = 0x80 ", value.RelInt{Op: "&=", A: 0xc0, B: 0x80, Forms: value.FormBitmask | value.FormHex}, noErr},
		{"&12!=4", value.RelInt{Op: "&!=", A: 12, B: 4, Forms: value.FormBitmask}, noErr},
		{"&0xc0=12", value.RelInt{}, 6},
		{"&0xc0", value.RelInt{}, 5},
		{"&0xc0<0x80", value.RelInt{}, 5},
		{"&0xc0=", value.RelInt{}, 6},
		{"&=1", value.RelInt{}, 1},
		{"&", value.RelInt{}, 1},
		{"&0xc0=0x80 x", value.RelInt{}, 11},
		{"!&1=1", value.RelInt{}, 1},
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

// TestParseRelIntSuricataVectors runs the inputs of Suricata 8.0.8's own
// unit tests for its integer parser (rust/src/detect/uint.rs and the
// DetectU*Parse tests in src/detect-*.c), leaving out the ones that fail
// only for overflowing a u8, which ParseRelInt does not know the width of.
func TestParseRelIntSuricataVectors(t *testing.T) {
	accept := []string{
		"&0x40!=0", "&0xc0=0x80", "0x100", "0xFF", "0xff", "!1-6", " 2kb",
		"> 3MB", "3", "5", ">3", "<44",
		"   12 ", "   8 ", "  8  <>  20 ", "  8  <> 20  ", "  8 ", "  >  8  ",
		"  >  8 ", " 1 <> 3 ", " 5 <> 10 ", " < 10  ", " > 10 ", "! 1", "!1",
		"1", "10", "1<>3", "5<>10", "8", "8<>20", "<   12 ", "<100", "<8",
		"> 2 ", ">10", ">8",
	}
	reject := []string{"&0xc0=12", "", "8<<20", "> 8 <> 20"}
	for _, s := range accept {
		if _, err := value.ParseRelInt(s); err != nil {
			t.Errorf("ParseRelInt(%q): %v; Suricata accepts it", s, err)
		}
	}
	for _, s := range reject {
		if _, err := value.ParseRelInt(s); err == nil {
			t.Errorf("ParseRelInt(%q) succeeded; Suricata rejects it", s)
		}
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

func TestRelIntSuricata7(t *testing.T) {
	tests := map[string]bool{
		"10": true, ">10": true, "1-5": true, "!5": true, "10kb": true, "=10mb": true,
		">10kb": false, "1kb-2kb": false, "10kib": false, "0x10": false, "!1-5": false, "&3=1": false,
	}
	for in, want := range tests {
		r, err := value.ParseRelInt(in)
		if err != nil {
			t.Fatalf("ParseRelInt(%q): %v", in, err)
		}
		if got := r.Suricata7(); got != want {
			t.Errorf("ParseRelInt(%q).Suricata7() = %v, want %v (forms %b)", in, got, want, r.Forms)
		}
	}
}

func TestParseTos(t *testing.T) {
	tests := []struct {
		in   string
		want value.Tos
		err  int
	}{
		{"8", value.Tos{Value: 8}, noErr},
		{"255", value.Tos{Value: 255}, noErr},
		{"!8", value.Tos{Negated: true, Value: 8}, noErr},
		{"! 8", value.Tos{Negated: true, Value: 8}, noErr},
		{"x10", value.Tos{Value: 16}, noErr},
		{"Xff", value.Tos{Value: 255}, noErr},
		{"!x1", value.Tos{Negated: true, Value: 1}, noErr},
		{"256", value.Tos{}, 0},
		{"!256", value.Tos{}, 1},
		{"x", value.Tos{}, 1},
		{"x100", value.Tos{}, 1},
		{"xg", value.Tos{}, 1},
		{"0x10", value.Tos{}, 1},
		{"", value.Tos{}, 0},
		{"<8", value.Tos{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseTos(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseTos(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseQuotedUint(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		err  int
	}{
		{"123", 123, noErr},
		{`"123"`, 123, noErr},
		{`" 123 "`, 123, noErr},
		{`"123`, 123, noErr},
		{`123"`, 123, noErr},
		{`""`, 0, 1},
		{`"1 2"`, 0, 2},
		{`"x"`, 0, 1},
		{"", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseQuotedUint(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseQuotedUint(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseUintEnum(t *testing.T) {
	tests := []struct {
		in   string
		want value.UintEnum
		err  int
	}{
		{"3", value.UintEnum{RelInt: value.RelInt{A: 3}}, noErr},
		{">3", value.UintEnum{RelInt: value.RelInt{Op: ">", A: 3}}, noErr},
		{"fail", value.UintEnum{Name: "fail"}, noErr},
		{"!fail", value.UintEnum{Name: "fail", Negated: true}, noErr},
		{"symmetric_active", value.UintEnum{Name: "symmetric_active"}, noErr},
		{"!", value.UintEnum{}, 0},
		{"", value.UintEnum{}, 0},
		{"3x", value.UintEnum{}, 0},
		{"a b", value.UintEnum{}, 1},
		{"!a!", value.UintEnum{}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := value.ParseUintEnum(tt.in)
			checkErr(t, err, tt.err)
			if got != tt.want {
				t.Errorf("ParseUintEnum(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

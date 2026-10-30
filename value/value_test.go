package value_test

import (
	"errors"
	"testing"

	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/value"
)

// noErr marks a test case that must decode without error.
const noErr = -1

// checkErr checks that err is nil when wantOff is noErr, and otherwise an
// *value.Error at wantOff.
func checkErr(t *testing.T, err error, wantOff int) {
	t.Helper()
	if wantOff == noErr {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	var e *value.Error
	if !errors.As(err, &e) {
		t.Fatalf("error = %v, want a *value.Error at offset %d", err, wantOff)
	}
	if e.Off != wantOff {
		t.Fatalf("error %q at offset %d, want offset %d", e.Msg, e.Off, wantOff)
	}
	if e.Msg == "" {
		t.Error("error has no message")
	}
}

func TestErrorString(t *testing.T) {
	err := &value.Error{Off: 3, Msg: "expected a digit"}
	if got, want := err.Error(), "expected a digit at offset 3"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		kind dialect.ValueKind
		ok   []string
		bad  []string
	}{
		{dialect.KindNone, []string{""}, []string{"x", " "}},
		{dialect.KindUint, []string{"1", "0"}, []string{"x", "-1", ""}},
		{dialect.KindIntOrVar, []string{"-1", "$v", "len"}, []string{"", "1x"}},
		{dialect.KindRelInt, []string{">5", "1<>2"}, []string{"<>", ""}},
		{dialect.KindUrilen, []string{"<10", "5,norm", "10<>20, raw"}, []string{"5,x", "<>", ""}},
		{dialect.KindQuoted, []string{`"a"`, `""`}, []string{"a", `"a`}},
		{dialect.KindIdent, []string{"a", "a.b-c_1"}, []string{"a b", ""}},
		{dialect.KindContent, []string{`"a"`, `!"|00|"`}, []string{`""`, "a"}},
		{dialect.KindPCRE, []string{`"/a/"`, `!"/a/i"`}, []string{"/a/", `"a"`}},
		{dialect.KindFlow, []string{"established", "to_server, established"}, []string{"x", ""}},
		{dialect.KindFlowbits, []string{"noalert", "set,a"}, []string{"set", ""}},
		{dialect.KindReference, []string{"cve,1"}, []string{"cve", ""}},
		{dialect.KindMetadata, []string{"a b", "a"}, []string{"", "a,,b"}},
		{dialect.KindThreshold, []string{"track by_src, count 1, seconds 1"}, []string{"", "count 1"}},
		{dialect.KindBase64Decode, []string{"", "relative"}, []string{"x", "bytes"}},
		{dialect.KindFastPattern, []string{"", "only", "1,2"}, []string{"x", "1"}},
		{dialect.KindIsDataAt, []string{"1", "!1,relative"}, []string{"", "1,x"}},
		{dialect.KindCSV, []string{"a", "a, b"}, []string{"", "a,,b"}},
		{dialect.KindDirection, []string{"", "to_client", "to_server"}, []string{"to_both", "TO_CLIENT", "to_client,x"}},
		{dialect.KindRaw, []string{"", "anything at all", ",,"}, nil},
	}
	covered := make(map[dialect.ValueKind]bool)
	for _, tt := range tests {
		covered[tt.kind] = true
		for _, s := range tt.ok {
			if err := value.Validate(tt.kind, s); err != nil {
				t.Errorf("Validate(%v, %q) = %v, want nil", tt.kind, s, err)
			}
		}
		for _, s := range tt.bad {
			if err := value.Validate(tt.kind, s); err == nil {
				t.Errorf("Validate(%v, %q) = nil, want an error", tt.kind, s)
			} else {
				var e *value.Error
				if !errors.As(err, &e) {
					t.Errorf("Validate(%v, %q) = %T, want *value.Error", tt.kind, s, err)
				}
			}
		}
	}
	for k := dialect.KindNone; k <= dialect.KindRaw; k++ {
		if !covered[k] {
			t.Errorf("kind %v is not covered", k)
		}
	}
	if err := value.Validate(dialect.ValueKind(99), ""); err == nil {
		t.Error("Validate(ValueKind(99)) = nil, want an error")
	}
}

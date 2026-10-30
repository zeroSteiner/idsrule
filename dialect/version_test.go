package dialect_test

import (
	"slices"
	"testing"

	"github.com/zeroSteiner/idsrule/dialect"
)

func TestVersion(t *testing.T) {
	v := dialect.NewVersion(8, 1)
	if v.Major() != 8 || v.Minor() != 1 || v.String() != "8.1" {
		t.Errorf("NewVersion(8, 1) = %v (major %d, minor %d)", v, v.Major(), v.Minor())
	}
	if dialect.Suricata8 != dialect.NewVersion(8, 0) || dialect.Suricata7 != dialect.NewVersion(7, 0) {
		t.Error("Suricata7 or Suricata8 is not the release it names")
	}
	if dialect.AnyVersion.String() != "any" {
		t.Errorf("AnyVersion.String() = %q", dialect.AnyVersion.String())
	}
	if dialect.Suricata7 >= dialect.Suricata8 || dialect.Suricata8 >= dialect.NewVersion(8, 1) || dialect.NewVersion(8, 255) >= dialect.NewVersion(9, 0) {
		t.Error("versions do not order as their numbers do")
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want dialect.Version
		ok   bool
	}{
		{"8", dialect.Suricata8, true},
		{"8.0", dialect.Suricata8, true},
		{"7", dialect.Suricata7, true},
		{"8.1", dialect.NewVersion(8, 1), true},
		{"", dialect.AnyVersion, true},
		{"any", dialect.AnyVersion, true},
		{"ANY", dialect.AnyVersion, true},
		{"0", dialect.AnyVersion, false},
		{"8.", dialect.AnyVersion, false},
		{".1", dialect.AnyVersion, false},
		{"8.0.1", dialect.AnyVersion, false},
		{"256", dialect.AnyVersion, false},
		{"v8", dialect.AnyVersion, false},
		{"-1", dialect.AnyVersion, false},
	}
	for _, tt := range tests {
		got, err := dialect.ParseVersion(tt.in)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("ParseVersion(%q) = %v, %v; want %v, ok %v", tt.in, got, err, tt.want, tt.ok)
		}
	}
}

func TestDialectVersions(t *testing.T) {
	if got := dialect.Suricata.Versions(); !slices.Equal(got, []dialect.Version{dialect.Suricata7, dialect.Suricata8}) {
		t.Errorf("Suricata.Versions() = %v", got)
	}
	for _, d := range []dialect.Dialect{dialect.Snort2, dialect.Unknown, dialect.Dialect(9)} {
		if vs := d.Versions(); len(vs) != 0 {
			t.Errorf("%v.Versions() = %v, want none", d, vs)
		}
		if !d.HasVersion(dialect.AnyVersion) || d.HasVersion(dialect.Suricata8) {
			t.Errorf("%v.HasVersion is wrong", d)
		}
	}
	if !dialect.Suricata.HasVersion(dialect.Suricata7) || dialect.Suricata.HasVersion(dialect.NewVersion(6, 0)) {
		t.Error("Suricata.HasVersion is wrong")
	}
	vs := dialect.Suricata.Versions()
	vs[0] = 0
	if dialect.Suricata.Versions()[0] != dialect.Suricata7 {
		t.Error("Versions returned a slice that aliases the table")
	}
}

func TestKeywordIn(t *testing.T) {
	get := func(name string) dialect.Keyword {
		k, ok := dialect.LookupAny(name)
		if !ok {
			t.Fatalf("%q is not in the tables", name)
		}
		return k
	}
	tests := []struct {
		name string
		d    dialect.Dialect
		v    dialect.Version
		want bool
	}{
		{"ftp.command", dialect.Suricata, dialect.AnyVersion, true},
		{"ftp.command", dialect.Suricata, dialect.Suricata8, true},
		{"ftp.command", dialect.Suricata, dialect.Suricata7, false},
		{"ftp.command", dialect.Snort2, dialect.AnyVersion, false},
		{"ssh.protoversion", dialect.Suricata, dialect.Suricata7, true},
		{"ssh.protoversion", dialect.Suricata, dialect.Suricata8, false},
		{"ssh.protoversion", dialect.Suricata, dialect.AnyVersion, true},
		{"http2.header", dialect.Suricata, dialect.AnyVersion, false},
		{"http2.header", dialect.Suricata, dialect.Suricata7, false},
		{"content", dialect.Snort2, dialect.AnyVersion, true},
		{"content", dialect.Suricata, dialect.Suricata7, true},
		{"content", dialect.Suricata, dialect.NewVersion(9, 0), true},
	}
	for _, tt := range tests {
		if got := get(tt.name).In(tt.d, tt.v); got != tt.want {
			t.Errorf("%q.In(%v, %v) = %v, want %v", tt.name, tt.d, tt.v, got, tt.want)
		}
	}
}

package dialect_test

import (
	"slices"
	"testing"

	"github.com/zeroSteiner/idsrule/dialect"
)

func TestPresenceString(t *testing.T) {
	tests := []struct {
		p     dialect.Presence
		want  string
		valid bool
	}{
		{dialect.NoValue, "no_value", true},
		{dialect.Required, "required", true},
		{dialect.Optional, "optional", true},
		{dialect.Presence(3), "Presence(3)", false},
		{dialect.Presence(255), "Presence(255)", false},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if got := tt.p.Valid(); got != tt.valid {
				t.Errorf("Valid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestValueKindString(t *testing.T) {
	tests := []struct {
		k     dialect.ValueKind
		want  string
		valid bool
	}{
		{dialect.KindNone, "none", true},
		{dialect.KindUint, "uint", true},
		{dialect.KindIntOrVar, "int_or_var", true},
		{dialect.KindRelInt, "rel_int", true},
		{dialect.KindUrilen, "urilen", true},
		{dialect.KindQuoted, "quoted", true},
		{dialect.KindIdent, "ident", true},
		{dialect.KindContent, "content", true},
		{dialect.KindPCRE, "pcre", true},
		{dialect.KindFlow, "flow", true},
		{dialect.KindFlowbits, "flowbits", true},
		{dialect.KindReference, "reference", true},
		{dialect.KindMetadata, "metadata", true},
		{dialect.KindThreshold, "threshold", true},
		{dialect.KindBase64Decode, "base64_decode", true},
		{dialect.KindFastPattern, "fast_pattern", true},
		{dialect.KindIsDataAt, "isdataat", true},
		{dialect.KindCSV, "csv", true},
		{dialect.KindDirection, "direction", true},
		{dialect.KindRaw, "raw", true},
		{dialect.KindRaw + 1, "ValueKind(20)", false},
		{dialect.ValueKind(255), "ValueKind(255)", false},
	}
	seen := make(map[string]bool)
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.k.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if got := tt.k.Valid(); got != tt.valid {
				t.Errorf("Valid() = %v, want %v", got, tt.valid)
			}
			if seen[tt.want] {
				t.Errorf("name %q used twice", tt.want)
			}
			seen[tt.want] = true
		})
	}
	// Every kind up to KindRaw is in the table above.
	for k := dialect.KindNone; k <= dialect.KindRaw; k++ {
		if !seen[k.String()] {
			t.Errorf("kind %d is not covered", k)
		}
	}
}

func TestRoleString(t *testing.T) {
	tests := []struct {
		r     dialect.Role
		want  string
		valid bool
	}{
		{dialect.RoleMeta, "meta", true},
		{dialect.RolePayload, "payload", true},
		{dialect.RoleModifier, "modifier", true},
		{dialect.RoleStickyBuffer, "sticky_buffer", true},
		{dialect.RoleTransform, "transform", true},
		{dialect.RoleBufferTest, "buffer_test", true},
		{dialect.RoleFlow, "flow", true},
		{dialect.RoleNonPayload, "non_payload", true},
		{dialect.RolePostDetect, "post_detect", true},
		{dialect.RoleAppLayer, "app_layer", true},
		{dialect.RoleOther, "other", true},
		{dialect.RoleOther + 1, "Role(11)", false},
		{dialect.Role(255), "Role(255)", false},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.r.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if got := tt.r.Valid(); got != tt.valid {
				t.Errorf("Valid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	tests := []struct {
		d    dialect.Dialect
		name string
		want bool
	}{
		{dialect.Snort2, "content", true},
		{dialect.Suricata, "content", true},
		{dialect.Unknown, "content", false},
		{dialect.Snort2, "http_uri", true},
		{dialect.Suricata, "http_uri", true},
		{dialect.Snort2, "http.uri", false},
		{dialect.Suricata, "http.uri", true},
		{dialect.Snort2, "logto", true},
		{dialect.Suricata, "logto", false},
		{dialect.Snort2, "startswith", false},
		{dialect.Suricata, "startswith", true},
		{dialect.Snort2, "nope", false},
		{dialect.Suricata, "nope", false},
		{dialect.Snort2, "Content", false},
		{dialect.Snort2, "", false},
		{dialect.Dialect(9), "content", false},
	}
	for _, tt := range tests {
		t.Run(tt.d.String()+"/"+tt.name, func(t *testing.T) {
			k, ok := dialect.Lookup(tt.d, tt.name)
			if ok != tt.want {
				t.Fatalf("Lookup(%v, %q) ok = %v, want %v", tt.d, tt.name, ok, tt.want)
			}
			if ok && k.Name != tt.name {
				t.Errorf("Lookup(%v, %q).Name = %q", tt.d, tt.name, k.Name)
			}
			if !ok && k != (dialect.Keyword{}) {
				t.Errorf("Lookup(%v, %q) returned %+v with ok false", tt.d, tt.name, k)
			}
		})
	}
}

func TestLookupAny(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"content", true},
		{"http.uri", true},
		{"logto", true},
		{"http_uri", true},
		{"nope", false},
		{"", false},
		{"CONTENT", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, ok := dialect.LookupAny(tt.name)
			if ok != tt.want {
				t.Fatalf("LookupAny(%q) ok = %v, want %v", tt.name, ok, tt.want)
			}
			if ok && k.Name != tt.name {
				t.Errorf("LookupAny(%q).Name = %q", tt.name, k.Name)
			}
		})
	}
}

func TestKeywords(t *testing.T) {
	names := func(ks []dialect.Keyword) []string {
		out := make([]string, len(ks))
		for i, k := range ks {
			out[i] = k.Name
		}
		return out
	}
	all := dialect.Keywords(dialect.Unknown)
	if len(all) == 0 {
		t.Fatal("Keywords(Unknown) is empty")
	}
	if !slices.IsSorted(names(all)) {
		t.Error("Keywords(Unknown) is not sorted by name")
	}
	union := make(map[string]bool)
	for _, d := range []dialect.Dialect{dialect.Snort2, dialect.Suricata} {
		ks := dialect.Keywords(d)
		if len(ks) == 0 {
			t.Fatalf("Keywords(%v) is empty", d)
		}
		if !slices.IsSorted(names(ks)) {
			t.Errorf("Keywords(%v) is not sorted by name", d)
		}
		for _, k := range ks {
			if !k.Dialects.Has(d) {
				t.Errorf("Keywords(%v) includes %q, which is not in that dialect", d, k.Name)
			}
			union[k.Name] = true
		}
		if len(ks) >= len(all) {
			t.Errorf("Keywords(%v) has %d keywords, not fewer than Keywords(Unknown)'s %d", d, len(ks), len(all))
		}
	}
	if len(union) != len(all) {
		t.Errorf("the union of the dialects has %d keywords, Keywords(Unknown) %d", len(union), len(all))
	}
	snort2, suricata := len(dialect.Keywords(dialect.Snort2)), len(dialect.Keywords(dialect.Suricata))
	t.Logf("%d keywords: %d in snort2, %d in suricata, %d in both", len(all), snort2, suricata, snort2+suricata-len(all))
	for _, k := range all {
		if !union[k.Name] {
			t.Errorf("Keywords(Unknown) includes %q, which is in no dialect", k.Name)
		}
	}
	// An undefined dialect is treated like Unknown.
	if ks := dialect.Keywords(dialect.Dialect(9)); !slices.Equal(names(ks), names(all)) {
		t.Errorf("Keywords(Dialect(9)) returned %d keywords, want the %d of Keywords(Unknown)", len(ks), len(all))
	}
	// The slice is the caller's: changing it does not change the tables.
	all[0].Name = "changed"
	if again := dialect.Keywords(dialect.Unknown); again[0].Name == "changed" {
		t.Error("Keywords returned a slice that aliases the tables")
	}
}

func TestActions(t *testing.T) {
	tests := []struct {
		d    dialect.Dialect
		want []string
	}{
		{dialect.Snort2, []string{"alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop"}},
		{dialect.Suricata, []string{"alert", "pass", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth", "config", "accept"}},
		{dialect.Unknown, []string{"accept", "activate", "alert", "config", "drop", "dynamic", "log", "pass", "reject", "rejectboth", "rejectdst", "rejectsrc", "sdrop"}},
		{dialect.Dialect(9), []string{"accept", "activate", "alert", "config", "drop", "dynamic", "log", "pass", "reject", "rejectboth", "rejectdst", "rejectsrc", "sdrop"}},
	}
	for _, tt := range tests {
		t.Run(tt.d.String(), func(t *testing.T) {
			got := tt.d.Actions()
			if !slices.Equal(got, tt.want) {
				t.Errorf("Actions() = %q, want %q", got, tt.want)
			}
			got[0] = "changed"
			if again := tt.d.Actions(); again[0] == "changed" {
				t.Error("Actions returned a slice that aliases the table")
			}
		})
	}
}

func TestIsAction(t *testing.T) {
	tests := []struct {
		s                         string
		snort2, suricata, unknown bool
	}{
		{"alert", true, true, true},
		{"drop", true, true, true},
		{"sdrop", true, false, true},
		{"activate", true, false, true},
		{"rejectboth", false, true, true},
		{"rejectsrc", false, true, true},
		{"nope", false, false, false},
		{"", false, false, false},
		{"Alert", true, true, true},
		{"ALERT", true, true, true},
		{"SDROP", true, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := dialect.Snort2.IsAction(tt.s); got != tt.snort2 {
				t.Errorf("Snort2.IsAction(%q) = %v, want %v", tt.s, got, tt.snort2)
			}
			if got := dialect.Suricata.IsAction(tt.s); got != tt.suricata {
				t.Errorf("Suricata.IsAction(%q) = %v, want %v", tt.s, got, tt.suricata)
			}
			if got := dialect.Unknown.IsAction(tt.s); got != tt.unknown {
				t.Errorf("Unknown.IsAction(%q) = %v, want %v", tt.s, got, tt.unknown)
			}
		})
	}
}

func TestProtocols(t *testing.T) {
	snort2 := dialect.Snort2.Protocols()
	if want := []string{"ip", "tcp", "udp", "icmp"}; !slices.Equal(snort2, want) {
		t.Errorf("Snort2.Protocols() = %q, want %q", snort2, want)
	}
	suricata := dialect.Suricata.Protocols()
	for _, p := range []string{
		"ip", "tcp", "udp", "icmp",
		"http", "http2", "ftp", "ftp-data", "tls", "ssh", "smb", "dns", "dcerpc", "smtp", "imap",
		"modbus", "dnp3", "enip", "nfs", "ntp", "dhcp", "krb5", "ikev2", "ike", "snmp", "sip", "rfb",
		"mqtt", "tftp", "rdp", "pgsql", "quic", "bittorrent-dht", "websocket", "ldap", "pop3", "doh2", "mdns",
	} {
		if !slices.Contains(suricata, p) {
			t.Errorf("Suricata.Protocols() lacks %q", p)
		}
	}
	if slices.Contains(suricata, "nope") {
		t.Error("Suricata.Protocols() contains \"nope\"")
	}
	for _, d := range []dialect.Dialect{dialect.Unknown, dialect.Dialect(9)} {
		all := d.Protocols()
		if !slices.IsSorted(all) {
			t.Errorf("%v.Protocols() is not sorted", d)
		}
		if len(slices.Compact(slices.Clone(all))) != len(all) {
			t.Errorf("%v.Protocols() has duplicates", d)
		}
		for _, p := range slices.Concat(snort2, suricata) {
			if !slices.Contains(all, p) {
				t.Errorf("%v.Protocols() lacks %q", d, p)
			}
		}
	}
	snort2[0] = "changed"
	if again := dialect.Snort2.Protocols(); again[0] == "changed" {
		t.Error("Protocols returned a slice that aliases the table")
	}
}

func TestIsProtocol(t *testing.T) {
	tests := []struct {
		s                         string
		snort2, suricata, unknown bool
	}{
		{"tcp", true, true, true},
		{"ip", true, true, true},
		{"http", false, true, true},
		{"tls", false, true, true},
		{"nope", false, false, false},
		{"", false, false, false},
		{"TCP", true, true, true},
		{"Http", false, true, true},
		{"47", false, false, false},
		{"6", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := dialect.Snort2.IsProtocol(tt.s); got != tt.snort2 {
				t.Errorf("Snort2.IsProtocol(%q) = %v, want %v", tt.s, got, tt.snort2)
			}
			if got := dialect.Suricata.IsProtocol(tt.s); got != tt.suricata {
				t.Errorf("Suricata.IsProtocol(%q) = %v, want %v", tt.s, got, tt.suricata)
			}
			if got := dialect.Unknown.IsProtocol(tt.s); got != tt.unknown {
				t.Errorf("Unknown.IsProtocol(%q) = %v, want %v", tt.s, got, tt.unknown)
			}
		})
	}
}

func TestAddedAndPacketProtocols(t *testing.T) {
	if got := dialect.Suricata.ActionAdded("ACCEPT"); got != dialect.Suricata8 {
		t.Errorf("Suricata.ActionAdded(ACCEPT) = %v", got)
	}
	for _, a := range []string{"alert", "config", "nope"} {
		if got := dialect.Suricata.ActionAdded(a); got != dialect.AnyVersion {
			t.Errorf("Suricata.ActionAdded(%q) = %v", a, got)
		}
	}
	if got := dialect.Snort2.ActionAdded("accept"); got != dialect.AnyVersion {
		t.Errorf("Snort2.ActionAdded(accept) = %v", got)
	}
	for _, p := range []string{"doh2", "LDAP", "mdns", "pop3", "websocket"} {
		if got := dialect.Suricata.ProtocolAdded(p); got != dialect.Suricata8 {
			t.Errorf("Suricata.ProtocolAdded(%q) = %v", p, got)
		}
	}
	if got := dialect.Suricata.ProtocolAdded("http"); got != dialect.AnyVersion {
		t.Errorf("Suricata.ProtocolAdded(http) = %v", got)
	}
	for p, want := range map[string]bool{"tcp": true, "PKTHDR": true, "tcp-stream": true, "igmp": true, "http": false, "ftp-data": false, "nope": false} {
		if got := dialect.Suricata.IsPacketProtocol(p); got != want {
			t.Errorf("Suricata.IsPacketProtocol(%q) = %v", p, got)
		}
	}
	if dialect.Snort2.IsPacketProtocol("pkthdr") || !dialect.Snort2.IsPacketProtocol("ip") || !dialect.Unknown.IsPacketProtocol("sctp") {
		t.Error("IsPacketProtocol is wrong for Snort2 or Unknown")
	}
	for _, p := range dialect.Suricata.Protocols() {
		if dialect.Suricata.IsPacketProtocol(p) == slices.Contains([]string{"http", "dns", "tls"}, p) && slices.Contains([]string{"http", "dns", "tls", "tcp", "udp"}, p) {
			t.Errorf("IsPacketProtocol(%q) misclassifies it", p)
		}
	}
}

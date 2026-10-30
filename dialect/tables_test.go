package dialect_test

import (
	"strings"
	"testing"

	"github.com/zeroSteiner/idsrule/dialect"
	"github.com/zeroSteiner/idsrule/value"
)

// TestTableInvariants checks what must hold of every keyword in the tables.
func TestTableInvariants(t *testing.T) {
	seen := make(map[string]bool)
	for _, k := range dialect.Keywords(dialect.Unknown) {
		t.Run(k.Name, func(t *testing.T) {
			if k.Name == "" {
				t.Fatal("empty name")
			}
			if k.Name != strings.ToLower(k.Name) || strings.ContainsAny(k.Name, " \t:;,()\"'") {
				t.Errorf("name %q is not a lower-case keyword", k.Name)
			}
			if seen[k.Name] {
				t.Errorf("name %q appears twice", k.Name)
			}
			seen[k.Name] = true
			if k.Dialects == 0 {
				t.Error("Dialects is empty")
			}
			if k.Dialects&^dialect.Both != 0 {
				t.Errorf("Dialects %b has bits outside Both", k.Dialects)
			}
			if k.Deprecated&^k.Dialects != 0 {
				t.Errorf("Deprecated %b is not a subset of Dialects %b", k.Deprecated, k.Dialects)
			}
			if !k.Value.Valid() {
				t.Errorf("Value %v is out of range", k.Value)
			}
			if !k.Kind.Valid() {
				t.Errorf("Kind %v is out of range", k.Kind)
			}
			if !k.Role.Valid() {
				t.Errorf("Role %v is out of range", k.Role)
			}
			if (k.Value == dialect.NoValue) != (k.Kind == dialect.KindNone) {
				t.Errorf("Value %v does not agree with Kind %v", k.Value, k.Kind)
			}
			if k.Value == dialect.Optional {
				if err := value.Validate(k.Kind, ""); err != nil {
					t.Errorf("Value is Optional but Kind %v rejects an empty value: %v", k.Kind, err)
				}
			}
			if k.Role == dialect.RoleStickyBuffer && !k.Repeatable {
				t.Error("sticky buffer is not Repeatable")
			}
			if k.Kind == dialect.KindDirection && (k.Role != dialect.RoleStickyBuffer || k.Value != dialect.Optional || k.Dialects != dialect.SetSuricata) {
				t.Errorf("KindDirection on a %v keyword with Value %v and Dialects %b; it is for the optional value of a Suricata sticky buffer", k.Role, k.Value, k.Dialects)
			}
			if k.Directional && (k.Value != dialect.Required || k.Dialects != dialect.SetSuricata || k.Kind == dialect.KindDirection) {
				t.Errorf("Directional on a keyword with Value %v, Kind %v and Dialects %b; it is for a Suricata keyword whose required value may start with a direction", k.Value, k.Kind, k.Dialects)
			}
			if k.Role == dialect.RoleTransform || k.Role == dialect.RoleBufferTest {
				if k.Dialects != dialect.SetSuricata {
					t.Errorf("%v keyword exists outside Suricata (%b)", k.Role, k.Dialects)
				}
				if !k.Repeatable {
					t.Errorf("%v keyword is not Repeatable", k.Role)
				}
			}
			if k.Role == dialect.RoleBufferTest && k.Value == dialect.NoValue {
				t.Error("buffer test takes no value")
			}
			if k.Replaces != "" {
				checkReplaces(t, k)
			}
			if k.Successor != "" {
				checkSuccessor(t, k)
			}
			checkVersions(t, k)
			if k.Bits != 0 {
				if k.Bits != 8 && k.Bits != 16 && k.Bits != 32 && k.Bits != 64 {
					t.Errorf("Bits %d is not 8, 16, 32 or 64", k.Bits)
				}
				if k.Kind != dialect.KindRelInt && k.Kind != dialect.KindUrilen && k.Kind != dialect.KindUintEnum {
					t.Errorf("Bits on a %v value; it is for the integers Suricata's integer parser reads", k.Kind)
				}
				if !k.Dialects.Has(dialect.Suricata) {
					t.Error("Bits on a keyword Suricata does not have")
				}
			}
			for _, d := range []dialect.Dialect{dialect.Snort2, dialect.Suricata} {
				_, ok := dialect.Lookup(d, k.Name)
				if want := k.Dialects.Has(d); ok != want {
					t.Errorf("Lookup(%v, %q) = %v, want %v", d, k.Name, ok, want)
				}
			}
		})
	}
}

// checkReplaces checks that k.Replaces is set only on a single-dialect
// keyword and names a keyword other than k that exists in the other
// dialect.
func checkReplaces(t *testing.T, k dialect.Keyword) {
	t.Helper()
	if k.Replaces == k.Name {
		t.Error("Replaces names the keyword itself")
		return
	}
	var other dialect.Dialect
	switch k.Dialects {
	case dialect.SetSnort2:
		other = dialect.Suricata
	case dialect.SetSuricata:
		other = dialect.Snort2
	case dialect.Both:
		t.Errorf("Replaces %q on a keyword of both dialects", k.Replaces)
		return
	default:
		t.Errorf("Replaces %q on a keyword with Dialects %b", k.Replaces, k.Dialects)
		return
	}
	if _, ok := dialect.Lookup(other, k.Replaces); !ok {
		t.Errorf("Replaces %q, which is not a %v keyword", k.Replaces, other)
	}
}

// checkSuccessor checks that k.Successor is set only on a deprecated or
// removed keyword and names a keyword other than k that exists,
// undeprecated, in every dialect k is deprecated in, and in the release
// that removed k.
func checkSuccessor(t *testing.T, k dialect.Keyword) {
	t.Helper()
	if k.Successor == k.Name {
		t.Error("Successor names the keyword itself")
		return
	}
	if k.Deprecated == 0 && k.Removed == dialect.AnyVersion {
		t.Errorf("Successor %q on a keyword that is neither deprecated nor removed", k.Successor)
		return
	}
	s, ok := dialect.LookupAny(k.Successor)
	if !ok {
		t.Errorf("Successor %q, which does not exist", k.Successor)
		return
	}
	if k.Deprecated&^s.Dialects != 0 {
		t.Errorf("Successor %q covers %b, not all of Deprecated %b", k.Successor, s.Dialects, k.Deprecated)
	}
	if s.Deprecated&k.Deprecated != 0 {
		t.Errorf("Successor %q is itself deprecated in %b", k.Successor, s.Deprecated&k.Deprecated)
	}
	if k.Removed != dialect.AnyVersion && !s.In(dialect.Suricata, k.Removed) {
		t.Errorf("Successor %q does not exist in %v, which removed %q", k.Successor, k.Removed, k.Name)
	}
}

// checkVersions checks that a keyword with Added or Removed belongs to one
// dialect that has Versions, that both name releases of it, and that Added
// comes before Removed.
func checkVersions(t *testing.T, k dialect.Keyword) {
	t.Helper()
	if k.Added == dialect.AnyVersion && k.Removed == dialect.AnyVersion {
		return
	}
	if k.Dialects != dialect.SetSuricata {
		t.Errorf("Added %v / Removed %v on a keyword with Dialects %b; only a Suricata-only keyword has versions", k.Added, k.Removed, k.Dialects)
		return
	}
	for _, v := range []dialect.Version{k.Added, k.Removed} {
		if !dialect.Suricata.HasVersion(v) {
			t.Errorf("version %v is not a Suricata release the tables describe", v)
		}
	}
	if k.Added == dialect.Suricata.Versions()[0] {
		t.Errorf("Added %v is the oldest release the tables describe; leave it unset", k.Added)
	}
	if k.Added != dialect.AnyVersion && k.Removed != dialect.AnyVersion && k.Added >= k.Removed {
		t.Errorf("Added %v is not before Removed %v", k.Added, k.Removed)
	}
}

// TestTableContents spot-checks entries the rest of the module relies on.
func TestTableContents(t *testing.T) {
	type want struct {
		dialects, deprecated dialect.Set
		value                dialect.Presence
		kind                 dialect.ValueKind
		role                 dialect.Role
		repeatable           bool
		replaces, successor  string
	}
	tests := map[string]want{
		"msg":               {dialect.Both, 0, dialect.Required, dialect.KindQuoted, dialect.RoleMeta, false, "", ""},
		"sid":               {dialect.Both, 0, dialect.Required, dialect.KindUint, dialect.RoleMeta, false, "", ""},
		"reference":         {dialect.Both, 0, dialect.Required, dialect.KindReference, dialect.RoleMeta, true, "", ""},
		"metadata":          {dialect.Both, 0, dialect.Required, dialect.KindMetadata, dialect.RoleMeta, true, "", ""},
		"content":           {dialect.Both, 0, dialect.Required, dialect.KindContent, dialect.RolePayload, true, "", ""},
		"pcre":              {dialect.Both, 0, dialect.Required, dialect.KindPCRE, dialect.RolePayload, true, "", ""},
		"nocase":            {dialect.Both, 0, dialect.NoValue, dialect.KindNone, dialect.RoleModifier, true, "", ""},
		"depth":             {dialect.Both, 0, dialect.Required, dialect.KindIntOrVar, dialect.RoleModifier, true, "", ""},
		"fast_pattern":      {dialect.Both, 0, dialect.Optional, dialect.KindFastPattern, dialect.RoleModifier, false, "", ""},
		"isdataat":          {dialect.Both, 0, dialect.Required, dialect.KindIsDataAt, dialect.RolePayload, true, "", ""},
		"byte_test":         {dialect.Both, 0, dialect.Required, dialect.KindRaw, dialect.RolePayload, true, "", ""},
		"base64_decode":     {dialect.Both, 0, dialect.Optional, dialect.KindBase64Decode, dialect.RolePayload, true, "", ""},
		"file_data":         {dialect.Both, 0, dialect.Optional, dialect.KindRaw, dialect.RoleStickyBuffer, true, "", ""},
		"file.data":         {dialect.SetSuricata, 0, dialect.Optional, dialect.KindDirection, dialect.RoleStickyBuffer, true, "file_data", ""},
		"frame":             {dialect.SetSuricata, 0, dialect.Required, dialect.KindIdent, dialect.RoleStickyBuffer, true, "", ""},
		"quic.version":      {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleStickyBuffer, true, "", ""},
		"urilen":            {dialect.Both, 0, dialect.Required, dialect.KindUrilen, dialect.RolePayload, false, "", ""},
		"dsize":             {dialect.Both, 0, dialect.Required, dialect.KindRelInt, dialect.RoleNonPayload, false, "", ""},
		"flow":              {dialect.Both, 0, dialect.Required, dialect.KindFlow, dialect.RoleFlow, false, "", ""},
		"flowbits":          {dialect.Both, 0, dialect.Required, dialect.KindFlowbits, dialect.RoleFlow, true, "", ""},
		"threshold":         {dialect.Both, 0, dialect.Required, dialect.KindThreshold, dialect.RolePostDetect, false, "", ""},
		"detection_filter":  {dialect.Both, 0, dialect.Required, dialect.KindThreshold, dialect.RolePostDetect, false, "", ""},
		"http_uri":          {dialect.Both, dialect.SetSuricata, dialect.NoValue, dialect.KindNone, dialect.RoleModifier, true, "", "http.uri"},
		"http_raw_cookie":   {dialect.SetSnort2, 0, dialect.NoValue, dialect.KindNone, dialect.RoleModifier, true, "", ""},
		"http_user_agent":   {dialect.SetSuricata, dialect.SetSuricata, dialect.NoValue, dialect.KindNone, dialect.RoleModifier, true, "", "http.user_agent"},
		"http_server_body":  {dialect.SetSuricata, dialect.SetSuricata, dialect.NoValue, dialect.KindNone, dialect.RoleModifier, true, "", "http.response_body"},
		"http.uri":          {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleStickyBuffer, true, "http_uri", ""},
		"http.request_body": {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleStickyBuffer, true, "http_client_body", ""},
		"http.user_agent":   {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleStickyBuffer, true, "", ""},
		"http_accept":       {dialect.SetSuricata, dialect.SetSuricata, dialect.Optional, dialect.KindDirection, dialect.RoleStickyBuffer, true, "", "http.accept"},
		"dce_iface":         {dialect.Both, dialect.SetSuricata, dialect.Required, dialect.KindRaw, dialect.RoleAppLayer, false, "", "dcerpc.iface"},
		"dcerpc.iface":      {dialect.SetSuricata, 0, dialect.Required, dialect.KindRaw, dialect.RoleAppLayer, false, "dce_iface", ""},
		"dcerpc.stub_data":  {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleStickyBuffer, true, "dce_stub_data", ""},
		"krb5_msg_type":     {dialect.SetSuricata, 0, dialect.Required, dialect.KindRaw, dialect.RoleAppLayer, false, "", ""},
		"pcrexform":         {dialect.SetSuricata, 0, dialect.Required, dialect.KindRaw, dialect.RoleTransform, true, "", ""},
		"xor":               {dialect.SetSuricata, 0, dialect.Required, dialect.KindQuoted, dialect.RoleTransform, true, "", ""},
		"from_base64":       {dialect.SetSuricata, 0, dialect.Optional, dialect.KindRaw, dialect.RoleTransform, true, "", ""},
		"url_decode":        {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleTransform, true, "", ""},
		"to_lowercase":      {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleTransform, true, "", ""},
		"startswith":        {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleModifier, true, "", ""},
		"endswith":          {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleModifier, true, "", ""},
		"bsize":             {dialect.SetSuricata, 0, dialect.Required, dialect.KindRelInt, dialect.RoleBufferTest, true, "", ""},
		"absent":            {dialect.SetSuricata, 0, dialect.Optional, dialect.KindRaw, dialect.RoleBufferTest, true, "", ""},
		"noalert":           {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RolePostDetect, false, "", ""},
		"mqtt.qos":          {dialect.SetSuricata, 0, dialect.Required, dialect.KindRaw, dialect.RoleAppLayer, false, "", ""},
		"ftp.command":       {dialect.SetSuricata, 0, dialect.NoValue, dialect.KindNone, dialect.RoleStickyBuffer, true, "", ""},
		"ftp.dynamic_port":  {dialect.SetSuricata, 0, dialect.Required, dialect.KindRelInt, dialect.RoleAppLayer, true, "", ""},
		"luajit":            {dialect.SetSuricata, dialect.SetSuricata, dialect.Required, dialect.KindRaw, dialect.RoleOther, true, "", "lua"},
		"uricontent":        {dialect.Both, dialect.SetSuricata, dialect.Required, dialect.KindContent, dialect.RolePayload, true, "", ""},
		"logto":             {dialect.SetSnort2, 0, dialect.Required, dialect.KindQuoted, dialect.RolePostDetect, false, "", ""},
		"activates":         {dialect.SetSnort2, 0, dialect.Required, dialect.KindUint, dialect.RolePostDetect, false, "", ""},
	}
	for name, w := range tests {
		t.Run(name, func(t *testing.T) {
			k, ok := dialect.LookupAny(name)
			if !ok {
				t.Fatalf("%q is not in the tables", name)
			}
			got := want{k.Dialects, k.Deprecated, k.Value, k.Kind, k.Role, k.Repeatable, k.Replaces, k.Successor}
			if got != w {
				t.Errorf("%q = %+v, want %+v", name, got, w)
			}
		})
	}
	for _, name := range []string{"krb5.msg_type", "krb5.err_code"} {
		if _, ok := dialect.LookupAny(name); ok {
			t.Errorf("%q is in the tables; Suricata 7 spells it with an underscore", name)
		}
	}
}

// TestLegacyHTTPModifiers checks the http_* modifiers against their http.*
// sticky buffers: the ten Snort 2.9 has exist in both dialects and are
// what their successor replaces; the four Suricata added are Suricata's
// own and their successors replace nothing.
func TestLegacyHTTPModifiers(t *testing.T) {
	tests := []struct {
		name, successor string
		snort2          bool
		replaces        string // what the successor replaces
	}{
		{"http_uri", "http.uri", true, "http_uri"},
		{"http_raw_uri", "http.uri.raw", true, "http_raw_uri"},
		{"http_header", "http.header", true, "http_header"},
		{"http_raw_header", "http.header.raw", true, "http_raw_header"},
		{"http_cookie", "http.cookie", true, "http_cookie"},
		{"http_method", "http.method", true, "http_method"},
		{"http_client_body", "http.request_body", true, "http_client_body"},
		{"http_stat_code", "http.stat_code", true, "http_stat_code"},
		{"http_stat_msg", "http.stat_msg", true, "http_stat_msg"},
		{"http_server_body", "http.response_body", false, ""},
		{"http_user_agent", "http.user_agent", false, ""},
		{"http_host", "http.host", false, ""},
		{"http_raw_host", "http.host.raw", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, ok := dialect.LookupAny(tt.name)
			if !ok {
				t.Fatalf("%q is not in the tables", tt.name)
			}
			wantDialects := dialect.SetSuricata
			if tt.snort2 {
				wantDialects = dialect.Both
			}
			if k.Dialects != wantDialects || k.Deprecated != dialect.SetSuricata {
				t.Errorf("Dialects %b, Deprecated %b; want %b, %b", k.Dialects, k.Deprecated, wantDialects, dialect.SetSuricata)
			}
			if k.Role != dialect.RoleModifier || k.Value != dialect.NoValue || !k.Repeatable {
				t.Errorf("not a valueless repeatable modifier: %+v", k)
			}
			if k.Replaces != "" {
				t.Errorf("Replaces %q, want none", k.Replaces)
			}
			if k.Successor != tt.successor {
				t.Fatalf("Successor %q, want %q", k.Successor, tt.successor)
			}
			s, ok := dialect.Lookup(dialect.Suricata, tt.successor)
			if !ok {
				t.Fatalf("successor %q is not a Suricata keyword", tt.successor)
			}
			if s.Dialects != dialect.SetSuricata || s.Role != dialect.RoleStickyBuffer || s.Deprecated != 0 {
				t.Errorf("successor %q = %+v, want an undeprecated Suricata-only sticky buffer", tt.successor, s)
			}
			if s.Replaces != tt.replaces {
				t.Errorf("successor %q replaces %q, want %q", tt.successor, s.Replaces, tt.replaces)
			}
		})
	}
}

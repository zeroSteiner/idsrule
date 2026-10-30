package dialect

import "fmt"

// Presence says whether a keyword takes a value: "nocase;" takes none,
// "sid:1;" requires one and "fast_pattern;" or "fast_pattern:only;" may
// take one.
type Presence uint8

const (
	// NoValue means the keyword is written without ':' and a value.
	NoValue Presence = iota
	// Required means the keyword must be followed by ':' and a value.
	Required
	// Optional means the keyword may be written either way.
	Optional
)

// String returns "no_value", "required" or "optional", or "Presence(n)" for
// a value outside the defined range.
func (p Presence) String() string {
	switch p {
	case NoValue:
		return "no_value"
	case Required:
		return "required"
	case Optional:
		return "optional"
	}
	return fmt.Sprintf("Presence(%d)", uint8(p))
}

// Valid reports whether p is one of the defined presences.
func (p Presence) Valid() bool { return p <= Optional }

// ValueKind names the grammar of a keyword's value. The value package has
// a decoder for every kind but KindNone and KindRaw.
type ValueKind uint8

const (
	// KindNone is the kind of a keyword that takes no value.
	KindNone ValueKind = iota
	// KindUint is an unsigned decimal integer: sid, rev, priority.
	KindUint
	// KindIntOrVar is a signed decimal integer or a byte_extract variable:
	// depth, offset, distance, within.
	KindIntOrVar
	// KindRelInt is an integer with an optional relational operator, a
	// range or, from Suricata 8, a bitmask test, its numbers decimal or
	// in Suricata hex or with a size unit: dsize, bsize.
	KindRelInt
	// KindUrilen is a KindRelInt value followed by an optional ",norm" or
	// ",raw": urilen.
	KindUrilen
	// KindQuoted is a double-quoted string with backslash escapes: msg.
	KindQuoted
	// KindIdent is a bare identifier of letters, digits, '_', '.' and '-':
	// classtype, app-layer-event.
	KindIdent
	// KindContent is a content pattern: an optionally negated quoted string
	// with escapes and |hex| blocks.
	KindContent
	// KindPCRE is a pcre value: an optionally negated quoted "/regex/flags".
	KindPCRE
	// KindFlow is the comma-separated token list of flow.
	KindFlow
	// KindFlowbits is the "verb,names" value of flowbits.
	KindFlowbits
	// KindReference is the "scheme,id" value of reference.
	KindReference
	// KindMetadata is the comma-separated "key value" list of metadata.
	KindMetadata
	// KindThreshold is the "type, track, count, seconds" value of threshold
	// and detection_filter.
	KindThreshold
	// KindBase64Decode is the optional "bytes, offset, relative" value of
	// base64_decode.
	KindBase64Decode
	// KindFastPattern is the optional "only" or "offset,length" value of
	// fast_pattern.
	KindFastPattern
	// KindIsDataAt is the "[!]offset[,relative][,rawbytes]" value of isdataat.
	KindIsDataAt
	// KindCSV is a comma-separated list of non-empty items.
	KindCSV
	// KindDirection is the direction a Suricata 8 sticky buffer may name,
	// to_client or to_server: file.data:to_client.
	KindDirection
	// KindRaw is a value whose grammar is not decoded: anything is accepted.
	KindRaw
)

// String returns the kind's lower-case name, such as "content" or
// "fast_pattern", or "ValueKind(n)" for a value outside the defined range.
func (k ValueKind) String() string {
	switch k {
	case KindNone:
		return "none"
	case KindUint:
		return "uint"
	case KindIntOrVar:
		return "int_or_var"
	case KindRelInt:
		return "rel_int"
	case KindUrilen:
		return "urilen"
	case KindQuoted:
		return "quoted"
	case KindIdent:
		return "ident"
	case KindContent:
		return "content"
	case KindPCRE:
		return "pcre"
	case KindFlow:
		return "flow"
	case KindFlowbits:
		return "flowbits"
	case KindReference:
		return "reference"
	case KindMetadata:
		return "metadata"
	case KindThreshold:
		return "threshold"
	case KindBase64Decode:
		return "base64_decode"
	case KindFastPattern:
		return "fast_pattern"
	case KindIsDataAt:
		return "isdataat"
	case KindCSV:
		return "csv"
	case KindDirection:
		return "direction"
	case KindRaw:
		return "raw"
	}
	return fmt.Sprintf("ValueKind(%d)", uint8(k))
}

// Valid reports whether k is one of the defined kinds.
func (k ValueKind) Valid() bool { return k <= KindRaw }

// Role classifies what a keyword does in a rule, following the sections of
// the Snort manual and the Suricata keyword index.
type Role uint8

const (
	// RoleMeta is a keyword that describes the rule: msg, sid, reference.
	RoleMeta Role = iota
	// RolePayload is a payload match: content, pcre, isdataat.
	RolePayload
	// RoleModifier modifies the preceding content: nocase, depth, http_uri.
	RoleModifier
	// RoleStickyBuffer selects the buffer the following matches apply to:
	// file_data, http.uri. Most take no value; frame names the frame, and
	// in Suricata 8 some may name a direction (file.data:to_client).
	RoleStickyBuffer
	// RoleTransform rewrites the bytes of the active sticky buffer before
	// the matches that follow: url_decode, to_lowercase, xor. Suricata
	// only.
	RoleTransform
	// RoleBufferTest tests the active sticky buffer itself rather than
	// matching a content in it: bsize, absent. Suricata only.
	RoleBufferTest
	// RoleFlow is a flow or state keyword: flow, flowbits, xbits.
	RoleFlow
	// RoleNonPayload matches packet headers: ttl, dsize, flags.
	RoleNonPayload
	// RolePostDetect acts after a match: threshold, tag, noalert.
	RolePostDetect
	// RoleAppLayer is an application-layer match that takes a value:
	// dcerpc.opnum, ssl_version, mqtt.type.
	RoleAppLayer
	// RoleOther is anything else: lua, requires, config.
	RoleOther
)

// String returns the role's lower-case name, such as "meta" or
// "sticky_buffer", or "Role(n)" for a value outside the defined range.
func (r Role) String() string {
	switch r {
	case RoleMeta:
		return "meta"
	case RolePayload:
		return "payload"
	case RoleModifier:
		return "modifier"
	case RoleStickyBuffer:
		return "sticky_buffer"
	case RoleTransform:
		return "transform"
	case RoleBufferTest:
		return "buffer_test"
	case RoleFlow:
		return "flow"
	case RoleNonPayload:
		return "non_payload"
	case RolePostDetect:
		return "post_detect"
	case RoleAppLayer:
		return "app_layer"
	case RoleOther:
		return "other"
	}
	return fmt.Sprintf("Role(%d)", uint8(r))
}

// Valid reports whether r is one of the defined roles.
func (r Role) Valid() bool { return r <= RoleOther }

// Keyword describes one rule option keyword: where it exists, whether and
// what kind of value it takes, what it does and how it relates to the other
// dialect.
type Keyword struct {
	// Name is the keyword as written in a rule, lower-case.
	Name string
	// Dialects is the set of dialects the keyword exists in.
	Dialects Set
	// Deprecated is the subset of Dialects in which the keyword is accepted
	// but deprecated, such as the http_* modifiers in Suricata.
	Deprecated Set
	// Value says whether the keyword takes a value.
	Value Presence
	// Kind is the grammar of the value; KindNone when Value is NoValue.
	Kind ValueKind
	// Role is what the keyword does.
	Role Role
	// Repeatable reports whether the keyword may appear more than once in
	// one rule.
	Repeatable bool
	// Directional reports whether the value may begin with a direction,
	// to_client or to_server, and a ',' before the value proper:
	// filesize:to_server,>100. Suricata 8 reads it; the value after the
	// direction is of Kind.
	Directional bool
	// Replaces names the equivalent keyword in the other dialect, if there
	// is one. It is set only on a keyword that exists in one dialect:
	// "http.uri" (Suricata) replaces "http_uri" (Snort 2), while
	// "http.user_agent" replaces nothing because Snort 2 has no
	// http_user_agent.
	Replaces string
	// Successor names the keyword that supersedes this one in the dialects
	// where it is Deprecated: "http.uri" for "http_uri" in Suricata. It is
	// empty when the keyword is not deprecated or when nothing replaces it
	// one for one.
	Successor string
	// Added is the first release of the keyword's dialect that has it:
	// Suricata8 for "ftp.command". It is AnyVersion when every release
	// the tables describe has it. Like Removed, it is set only on a
	// keyword of one dialect, a dialect with Versions.
	Added Version
	// Removed is the first release of the keyword's dialect that no longer
	// accepts it: Suricata8 for "ssh.protoversion". It is AnyVersion when
	// no release the tables describe has removed it.
	Removed Version
}

// In reports whether the keyword exists in release v of dialect d: d is one
// of its Dialects and v is neither before Added nor at or after Removed.
// For AnyVersion it reports whether some release of d the tables describe
// has the keyword, which for a dialect without Versions is every keyword of
// the dialect.
func (k Keyword) In(d Dialect, v Version) bool {
	if !k.Dialects.Has(d) {
		return false
	}
	if v != AnyVersion {
		return k.inRelease(v)
	}
	vs := d.versions()
	if len(vs) == 0 {
		return true
	}
	for _, r := range vs {
		if k.inRelease(r) {
			return true
		}
	}
	return false
}

// inRelease reports whether release v lies within [Added, Removed).
func (k Keyword) inRelease(v Version) bool {
	return (k.Added == AnyVersion || v >= k.Added) && (k.Removed == AnyVersion || v < k.Removed)
}

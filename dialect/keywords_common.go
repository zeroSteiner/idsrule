package dialect

// commonKeywords are the keywords that exist in both dialects. The http_*
// modifiers are deprecated in Suricata in favour of the http.* sticky
// buffers, which the Successor field names.
//
// byte_test, byte_jump, byte_extract and byte_math are KindRaw: their
// values are small languages of their own (operators, endianness, string
// conversions, variables) whose decoding is out of scope here.
var commonKeywords = []Keyword{
	// Meta.
	{Name: "msg", Dialects: Both, Value: Required, Kind: KindQuoted, Role: RoleMeta},
	{Name: "sid", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleMeta},
	{Name: "rev", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleMeta},
	{Name: "gid", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleMeta},
	{Name: "classtype", Dialects: Both, Value: Required, Kind: KindIdent, Role: RoleMeta},
	{Name: "reference", Dialects: Both, Value: Required, Kind: KindReference, Role: RoleMeta, Repeatable: true},
	{Name: "priority", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleMeta},
	{Name: "metadata", Dialects: Both, Value: Required, Kind: KindMetadata, Role: RoleMeta, Repeatable: true},

	// Payload.
	{Name: "content", Dialects: Both, Value: Required, Kind: KindContent, Role: RolePayload, Repeatable: true},
	{Name: "pcre", Dialects: Both, Value: Required, Kind: KindPCRE, Role: RolePayload, Repeatable: true},
	{Name: "nocase", Dialects: Both, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true},
	{Name: "depth", Dialects: Both, Value: Required, Kind: KindIntOrVar, Role: RoleModifier, Repeatable: true},
	{Name: "offset", Dialects: Both, Value: Required, Kind: KindIntOrVar, Role: RoleModifier, Repeatable: true},
	{Name: "distance", Dialects: Both, Value: Required, Kind: KindIntOrVar, Role: RoleModifier, Repeatable: true},
	{Name: "within", Dialects: Both, Value: Required, Kind: KindIntOrVar, Role: RoleModifier, Repeatable: true},
	// fast_pattern may be set once per rule; both engines reject a second.
	{Name: "fast_pattern", Dialects: Both, Value: Optional, Kind: KindFastPattern, Role: RoleModifier},
	{Name: "rawbytes", Dialects: Both, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true},
	{Name: "isdataat", Dialects: Both, Value: Required, Kind: KindIsDataAt, Role: RolePayload, Repeatable: true},
	{Name: "byte_test", Dialects: Both, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "byte_jump", Dialects: Both, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "byte_extract", Dialects: Both, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "byte_math", Dialects: Both, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "base64_decode", Dialects: Both, Value: Optional, Kind: KindBase64Decode, Role: RolePayload, Repeatable: true},
	{Name: "base64_data", Dialects: Both, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true},
	{Name: "file_data", Dialects: Both, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true},
	{Name: "pkt_data", Dialects: Both, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true},
	{Name: "urilen", Dialects: Both, Value: Required, Kind: KindUrilen, Role: RolePayload},
	{Name: "dsize", Dialects: Both, Value: Required, Kind: KindRelInt, Role: RoleNonPayload},
	// replace is a content-like quoted pattern that overwrites the match.
	{Name: "replace", Dialects: Both, Value: Required, Kind: KindContent, Role: RoleModifier, Repeatable: true},
	// asn1 takes a comma-separated list of checks with arguments.
	{Name: "asn1", Dialects: Both, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "ftpbounce", Dialects: Both, Value: NoValue, Kind: KindNone, Role: RolePayload},
	// uricontent is Snort's pre-http_uri URI match; Suricata still parses
	// it as content with http_uri but documents it as deprecated.
	{Name: "uricontent", Dialects: Both, Deprecated: SetSuricata, Value: Required, Kind: KindContent, Role: RolePayload, Repeatable: true},

	// Flow.
	{Name: "flow", Dialects: Both, Value: Required, Kind: KindFlow, Role: RoleFlow},
	{Name: "flowbits", Dialects: Both, Value: Required, Kind: KindFlowbits, Role: RoleFlow, Repeatable: true},

	// Non-payload. ttl takes Snort's N-M and Suricata's richer range forms
	// and ip_proto takes protocol names, so both are KindRaw; fragbits,
	// flags, rpc and stream_size have grammars of their own.
	{Name: "ttl", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "tos", Dialects: Both, Value: Required, Kind: KindRelInt, Role: RoleNonPayload},
	{Name: "id", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleNonPayload},
	{Name: "ipopts", Dialects: Both, Value: Required, Kind: KindIdent, Role: RoleNonPayload},
	{Name: "fragbits", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "fragoffset", Dialects: Both, Value: Required, Kind: KindRelInt, Role: RoleNonPayload},
	{Name: "flags", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "seq", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleNonPayload},
	{Name: "ack", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleNonPayload},
	{Name: "window", Dialects: Both, Value: Required, Kind: KindRelInt, Role: RoleNonPayload},
	{Name: "itype", Dialects: Both, Value: Required, Kind: KindRelInt, Role: RoleNonPayload},
	{Name: "icode", Dialects: Both, Value: Required, Kind: KindRelInt, Role: RoleNonPayload},
	{Name: "icmp_id", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleNonPayload},
	{Name: "icmp_seq", Dialects: Both, Value: Required, Kind: KindUint, Role: RoleNonPayload},
	{Name: "rpc", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "ip_proto", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "sameip", Dialects: Both, Value: NoValue, Kind: KindNone, Role: RoleNonPayload},
	{Name: "stream_size", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleNonPayload},

	// Post-detection.
	{Name: "threshold", Dialects: Both, Value: Required, Kind: KindThreshold, Role: RolePostDetect},
	{Name: "detection_filter", Dialects: Both, Value: Required, Kind: KindThreshold, Role: RolePostDetect},
	{Name: "tag", Dialects: Both, Value: Required, Kind: KindRaw, Role: RolePostDetect},

	// Application layer: the DCE/RPC, SSL and DNP3 keywords share their
	// Snort names with Suricata, which keeps the dce_* names as aliases of
	// its dcerpc.* keywords.
	{Name: "dce_iface", Dialects: Both, Deprecated: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Successor: "dcerpc.iface"},
	{Name: "dce_opnum", Dialects: Both, Deprecated: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Successor: "dcerpc.opnum"},
	{Name: "dce_stub_data", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true, Successor: "dcerpc.stub_data"},
	{Name: "ssl_version", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "ssl_state", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "dnp3_func", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "dnp3_ind", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "dnp3_obj", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "dnp3_data", Dialects: Both, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true},
	{Name: "enip_command", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "cip_service", Dialects: Both, Value: Required, Kind: KindRaw, Role: RoleAppLayer},

	// Legacy HTTP content modifiers: nine of Snort 2.9's ten, which Suricata
	// accepts but deprecates. http_raw_cookie has no Suricata counterpart and
	// lives in the Snort table; http_server_body, http_user_agent, http_host
	// and http_raw_host are Suricata's own and live in its table.
	{Name: "http_uri", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.uri"},
	{Name: "http_raw_uri", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.uri.raw"},
	{Name: "http_header", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.header"},
	{Name: "http_raw_header", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.header.raw"},
	{Name: "http_cookie", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.cookie"},
	{Name: "http_method", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.method"},
	{Name: "http_client_body", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.request_body"},
	{Name: "http_stat_code", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.stat_code"},
	{Name: "http_stat_msg", Dialects: Both, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: "http.stat_msg"},
}

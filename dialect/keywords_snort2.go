package dialect

// snort2Keywords are the keywords that exist only in Snort 2.9: the
// preprocessor rule options and the post-detection actions Suricata never
// had. Most values are small grammars of their own and so KindRaw.
var snort2Keywords = []Keyword{
	// Payload.
	{Name: "protected_content", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "hash", Dialects: SetSnort2, Value: Required, Kind: KindIdent, Role: RoleModifier, Repeatable: true},
	{Name: "length", Dialects: SetSnort2, Value: Required, Kind: KindUint, Role: RoleModifier, Repeatable: true},
	{Name: "http_encode", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "cvs", Dialects: SetSnort2, Value: Required, Kind: KindIdent, Role: RolePayload},
	{Name: "sd_pattern", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	// Suricata has no raw cookie buffer ("use http_raw_header instead"), so
	// this legacy modifier is Snort's alone and has no successor.
	{Name: "http_raw_cookie", Dialects: SetSnort2, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true},

	// Application layer (preprocessor rule options).
	{Name: "sip_method", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "sip_stat_code", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "sip_header", Dialects: SetSnort2, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true},
	{Name: "sip_body", Dialects: SetSnort2, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true},
	{Name: "gtp_type", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "gtp_info", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "gtp_version", Dialects: SetSnort2, Value: Required, Kind: KindUint, Role: RoleAppLayer},
	{Name: "modbus_func", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "modbus_unit", Dialects: SetSnort2, Value: Required, Kind: KindUint, Role: RoleAppLayer},
	{Name: "modbus_data", Dialects: SetSnort2, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true},
	{Name: "cip_attribute", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "cip_class", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "cip_conn_path_class", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "cip_instance", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "cip_req", Dialects: SetSnort2, Value: NoValue, Kind: KindNone, Role: RoleAppLayer},
	{Name: "cip_rsp", Dialects: SetSnort2, Value: NoValue, Kind: KindNone, Role: RoleAppLayer},
	{Name: "cip_status", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "enip_req", Dialects: SetSnort2, Value: NoValue, Kind: KindNone, Role: RoleAppLayer},
	{Name: "enip_rsp", Dialects: SetSnort2, Value: NoValue, Kind: KindNone, Role: RoleAppLayer},
	{Name: "appid", Dialects: SetSnort2, Value: Required, Kind: KindCSV, Role: RoleAppLayer},

	// Non-payload.
	{Name: "stream_reassemble", Dialects: SetSnort2, Value: Required, Kind: KindRaw, Role: RoleNonPayload},

	// Post-detection.
	{Name: "logto", Dialects: SetSnort2, Value: Required, Kind: KindQuoted, Role: RolePostDetect},
	{Name: "session", Dialects: SetSnort2, Value: Required, Kind: KindIdent, Role: RolePostDetect},
	{Name: "resp", Dialects: SetSnort2, Value: Required, Kind: KindCSV, Role: RolePostDetect},
	{Name: "react", Dialects: SetSnort2, Value: Optional, Kind: KindRaw, Role: RolePostDetect},
	{Name: "activates", Dialects: SetSnort2, Value: Required, Kind: KindUint, Role: RolePostDetect},
	{Name: "activated_by", Dialects: SetSnort2, Value: Required, Kind: KindUint, Role: RolePostDetect},
	{Name: "count", Dialects: SetSnort2, Value: Required, Kind: KindUint, Role: RolePostDetect},
}

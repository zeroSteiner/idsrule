package dialect

// sticky returns a Suricata sticky-buffer keyword, replacing the Snort
// modifier snort when there is one.
func sticky(name, snort string) Keyword {
	return Keyword{Name: name, Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true, Replaces: snort}
}

// legacySticky returns a deprecated Suricata sticky buffer: the underscore
// spelling of a buffer that has since been renamed to successor.
func legacySticky(name, successor string) Keyword {
	return Keyword{Name: name, Dialects: SetSuricata, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true, Successor: successor}
}

// legacyModifier returns a deprecated Suricata content modifier that Snort
// 2.9 never had, superseded by the sticky buffer successor.
func legacyModifier(name, successor string) Keyword {
	return Keyword{Name: name, Dialects: SetSuricata, Deprecated: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true, Successor: successor}
}

// appLayer returns a Suricata application-layer keyword that takes a value
// of the given kind.
func appLayer(name string, kind ValueKind) Keyword {
	return Keyword{Name: name, Dialects: SetSuricata, Value: Required, Kind: kind, Role: RoleAppLayer}
}

// transform returns a Suricata buffer transform that takes no value.
func transform(name string) Keyword {
	return Keyword{Name: name, Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleTransform, Repeatable: true}
}

// directional returns the sticky buffer k as one that Suricata 8 lets name
// a direction: file.data:to_client.
func directional(k Keyword) Keyword {
	k.Value, k.Kind = Optional, KindDirection
	return k
}

// uintMatch returns a Suricata keyword that matches an n-bit unsigned
// integer read by Suricata's integer parser: enip.revision:>2.
func uintMatch(name string, n uint8) Keyword {
	return Keyword{Name: name, Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleAppLayer, Repeatable: true, Bits: n}
}

// enumMatch returns a Suricata keyword whose n-bit unsigned integer may
// also be given by name: ntp.mode:client.
func enumMatch(name string, n uint8) Keyword {
	k := uintMatch(name, n)
	k.Kind = KindUintEnum
	return k
}

// withRole returns k with role r.
func withRole(r Role, k Keyword) Keyword {
	k.Role = r
	return k
}

// addedIn returns k as a keyword that first appeared in Suricata release v.
func addedIn(v Version, k Keyword) Keyword {
	k.Added = v
	return k
}

// suricataKeywords are the keywords that exist only in Suricata: every
// keyword Suricata 7.0 and 8.0 register (from their sigmatch_table and Rust
// registrations), apart from internal and demo ones, with Added and Removed
// saying which of the two releases has each. A value read by Suricata's
// integer parser is KindRelInt or KindUintEnum with its Bits; a value with
// a grammar of its own is KindRaw.
var suricataKeywords = []Keyword{
	// Content modifiers, buffer tests and transforms. A buffer test
	// (bsize, absent) examines the active sticky buffer itself; a
	// transform rewrites it before the matches that follow.
	{Name: "startswith", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true},
	{Name: "endswith", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true},
	{Name: "bsize", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleBufferTest, Repeatable: true, Bits: 64},
	{Name: "absent", Dialects: SetSuricata, Value: Optional, Kind: KindRaw, Role: RoleBufferTest, Repeatable: true, Added: Suricata8},
	// pcrexform takes a quoted regular expression, whose escapes are
	// PCRE's rather than a quoted string's.
	{Name: "pcrexform", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleTransform, Repeatable: true},
	{Name: "xor", Dialects: SetSuricata, Value: Required, Kind: KindQuoted, Role: RoleTransform, Repeatable: true},
	{Name: "from_base64", Dialects: SetSuricata, Value: Optional, Kind: KindRaw, Role: RoleTransform, Repeatable: true, Added: Suricata8},
	transform("dotprefix"),
	transform("strip_whitespace"),
	transform("compress_whitespace"),
	transform("to_md5"),
	transform("to_sha1"),
	transform("to_sha256"),
	transform("to_lowercase"),
	transform("to_uppercase"),
	transform("url_decode"),
	transform("header_lowercase"),
	transform("strip_pseudo_headers"),
	addedIn(Suricata8, transform("domain")),
	addedIn(Suricata8, transform("tld")),
	// gunzip and zlib_deflate take an optional max-size.
	{Name: "gunzip", Dialects: SetSuricata, Value: Optional, Kind: KindRaw, Role: RoleTransform, Repeatable: true, Added: Suricata8},
	{Name: "zlib_deflate", Dialects: SetSuricata, Value: Optional, Kind: KindRaw, Role: RoleTransform, Repeatable: true, Added: Suricata8},
	{Name: "luaxform", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleTransform, Repeatable: true, Added: Suricata8},
	// entropy tests the active buffer, or the payload without one.
	{Name: "entropy", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true, Added: Suricata8},

	// HTTP sticky buffers.
	sticky("http.uri", "http_uri"),
	sticky("http.uri.raw", "http_raw_uri"),
	sticky("http.uri.normalized", ""),
	sticky("http.method", "http_method"),
	sticky("http.request_line", ""),
	sticky("http.request_body", "http_client_body"),
	sticky("http.header", "http_header"),
	sticky("http.header.raw", "http_raw_header"),
	sticky("http.header_names", ""),
	sticky("http.request_header", ""),
	sticky("http.response_header", ""),
	sticky("http.cookie", "http_cookie"),
	sticky("http.user_agent", ""),
	sticky("http.host", ""),
	sticky("http.host.raw", ""),
	directional(sticky("http.accept", "")),
	directional(sticky("http.accept_lang", "")),
	directional(sticky("http.accept_enc", "")),
	directional(sticky("http.referer", "")),
	directional(sticky("http.connection", "")),
	directional(sticky("http.content_type", "")),
	directional(sticky("http.content_len", "")),
	sticky("http.protocol", ""),
	sticky("http.start", ""),
	sticky("http.response_line", ""),
	sticky("http.response_body", ""),
	sticky("http.stat_code", "http_stat_code"),
	sticky("http.stat_msg", "http_stat_msg"),
	directional(sticky("http.server", "")),
	directional(sticky("http.location", "")),
	legacyModifier("http_server_body", "http.response_body"),
	legacyModifier("http_user_agent", "http.user_agent"),
	legacyModifier("http_host", "http.host"),
	legacyModifier("http_raw_host", "http.host.raw"),
	directional(legacySticky("http_accept", "http.accept")),
	directional(legacySticky("http_accept_lang", "http.accept_lang")),
	directional(legacySticky("http_accept_enc", "http.accept_enc")),
	directional(legacySticky("http_referer", "http.referer")),
	directional(legacySticky("http_connection", "http.connection")),
	directional(legacySticky("http_content_type", "http.content_type")),
	directional(legacySticky("http_content_len", "http.content_len")),
	legacySticky("http_protocol", "http.protocol"),
	legacySticky("http_start", "http.start"),
	legacySticky("http_request_line", "http.request_line"),
	legacySticky("http_response_line", "http.response_line"),
	legacySticky("http_header_names", "http.header_names"),

	// HTTP/2.
	appLayer("http2.frametype", KindRaw),
	appLayer("http2.errorcode", KindRaw),
	appLayer("http2.priority", KindRaw),
	appLayer("http2.window", KindRaw),
	appLayer("http2.size_update", KindRaw),
	appLayer("http2.settings", KindRaw),
	sticky("http2.header_name", ""),
	// http2.header was experimental in Suricata 6 and is gone since 7.0;
	// http.request_header and http.response_header took its place.
	{Name: "http2.header", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleStickyBuffer, Repeatable: true, Removed: Suricata7},

	// Files.
	directional(sticky("file.data", "file_data")),
	directional(sticky("file.name", "")),
	directional(sticky("file.magic", "")),
	{Name: "filename", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "fileext", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "filemagic", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "filestore", Dialects: SetSuricata, Value: Optional, Kind: KindRaw, Role: RolePostDetect},
	{Name: "filemd5", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload},
	{Name: "filesha1", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload},
	{Name: "filesha256", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload},
	{Name: "filesize", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RolePayload, Directional: true, Bits: 64},

	// DNS.
	sticky("dns.query", ""),
	legacySticky("dns_query", "dns.query"),
	addedIn(Suricata8, sticky("dns.answer.name", "")),
	uintMatch("dns.opcode", 8),
	addedIn(Suricata8, sticky("dns.query.name", "")),
	addedIn(Suricata8, sticky("dns.queries.rrname", "")),
	addedIn(Suricata8, sticky("dns.answers.rrname", "")),
	addedIn(Suricata8, sticky("dns.authorities.rrname", "")),
	addedIn(Suricata8, sticky("dns.additionals.rrname", "")),
	addedIn(Suricata8, sticky("dns.response.rrname", "")),
	addedIn(Suricata8, enumMatch("dns.rcode", 16)),
	addedIn(Suricata8, enumMatch("dns.rrtype", 16)),

	// mDNS.
	addedIn(Suricata8, sticky("mdns.queries.rrname", "")),
	addedIn(Suricata8, sticky("mdns.answers.rrname", "")),
	addedIn(Suricata8, sticky("mdns.authorities.rrname", "")),
	addedIn(Suricata8, sticky("mdns.additionals.rrname", "")),
	addedIn(Suricata8, sticky("mdns.response.rrname", "")),

	// FTP. The ftp.* keywords are new in Suricata 8.
	addedIn(Suricata8, sticky("ftp.command", "")),
	addedIn(Suricata8, sticky("ftp.command_data", "")),
	addedIn(Suricata8, sticky("ftp.reply", "")),
	addedIn(Suricata8, sticky("ftp.completion_code", "")),
	addedIn(Suricata8, uintMatch("ftp.dynamic_port", 16)),
	addedIn(Suricata8, appLayer("ftp.mode", KindIdent)),
	addedIn(Suricata8, appLayer("ftp.reply_received", KindIdent)),
	appLayer("ftpdata_command", KindIdent),

	// TLS.
	sticky("tls.sni", ""),
	sticky("tls.cert_subject", ""),
	sticky("tls.cert_issuer", ""),
	sticky("tls.cert_serial", ""),
	sticky("tls.cert_fingerprint", ""),
	sticky("tls.certs", ""),
	sticky("tls.random", ""),
	sticky("tls.random_time", ""),
	sticky("tls.random_bytes", ""),
	addedIn(Suricata8, sticky("tls.alpn", "")),
	addedIn(Suricata8, sticky("tls.subjectaltname", "")),
	legacySticky("tls_sni", "tls.sni"),
	legacySticky("tls_cert_subject", "tls.cert_subject"),
	legacySticky("tls_cert_issuer", "tls.cert_issuer"),
	legacySticky("tls_cert_serial", "tls.cert_serial"),
	legacySticky("tls_cert_fingerprint", "tls.cert_fingerprint"),
	appLayer("tls.version", KindRaw),
	appLayer("tls.subject", KindRaw),
	appLayer("tls.issuerdn", KindRaw),
	appLayer("tls.fingerprint", KindRaw),
	appLayer("tls.cert_chain_len", KindRaw),
	appLayer("tls_cert_notbefore", KindRaw),
	appLayer("tls_cert_notafter", KindRaw),
	{Name: "tls_cert_expired", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleAppLayer},
	{Name: "tls_cert_valid", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleAppLayer},
	{Name: "tls.store", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RolePostDetect},
	{Name: "tls_store", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RolePostDetect},

	// JA3, JA3S, JA4.
	sticky("ja3.hash", ""),
	sticky("ja3.string", ""),
	legacySticky("ja3_hash", "ja3.hash"),
	legacySticky("ja3_string", "ja3.string"),
	sticky("ja3s.hash", ""),
	sticky("ja3s.string", ""),
	sticky("ja4.hash", ""),
	legacySticky("ja4_hash", "ja4.hash"),

	// SSH.
	sticky("ssh.proto", ""),
	sticky("ssh.software", ""),
	legacySticky("ssh_proto", "ssh.proto"),
	legacySticky("ssh_software", "ssh.software"),
	sticky("ssh.hassh", ""),
	sticky("ssh.hassh.string", ""),
	sticky("ssh.hassh.server", ""),
	sticky("ssh.hassh.server.string", ""),
	legacySticky("ssh-hassh", "ssh.hassh"),
	legacySticky("ssh-hassh-string", "ssh.hassh.string"),
	legacySticky("ssh-hassh-server", "ssh.hassh.server"),
	legacySticky("ssh-hassh-server-string", "ssh.hassh.server.string"),
	// Deprecated in 7.0; 8.0 keeps the names only to refuse them.
	{Name: "ssh.protoversion", Dialects: SetSuricata, Deprecated: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Successor: "ssh.proto", Removed: Suricata8},
	{Name: "ssh.softwareversion", Dialects: SetSuricata, Deprecated: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Successor: "ssh.software", Removed: Suricata8},

	// SMB.
	sticky("smb.named_pipe", ""),
	sticky("smb.share", ""),
	sticky("smb.ntlmssp_user", ""),
	sticky("smb.ntlmssp_domain", ""),
	legacySticky("smb_named_pipe", "smb.named_pipe"),
	legacySticky("smb_share", "smb.share"),
	// smb.version takes a version, and in Suricata 8.0 an optional
	// ",max" or ",min".
	{Name: "smb.version", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Repeatable: true, Added: Suricata8},

	// Kerberos.
	sticky("krb5.cname", ""),
	sticky("krb5.sname", ""),
	legacySticky("krb5_cname", "krb5.cname"),
	legacySticky("krb5_sname", "krb5.sname"),
	appLayer("krb5_msg_type", KindRaw),
	appLayer("krb5_err_code", KindRaw),
	appLayer("krb5.ticket_encryption", KindRaw),

	// DCE/RPC.
	{Name: "dcerpc.iface", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Replaces: "dce_iface"},
	{Name: "dcerpc.opnum", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Replaces: "dce_opnum"},
	sticky("dcerpc.stub_data", "dce_stub_data"),

	// SNMP.
	sticky("snmp.community", ""),
	sticky("snmp.usm", ""),
	appLayer("snmp.version", KindRaw),
	appLayer("snmp.pdu_type", KindRaw),
	addedIn(Suricata8, enumMatch("snmp.trap_type", 8)),

	// SIP.
	sticky("sip.method", ""),
	sticky("sip.uri", ""),
	sticky("sip.protocol", ""),
	sticky("sip.stat_code", ""),
	sticky("sip.stat_msg", ""),
	sticky("sip.request_line", ""),
	sticky("sip.response_line", ""),
	addedIn(Suricata8, sticky("sip.from", "")),
	addedIn(Suricata8, sticky("sip.to", "")),
	addedIn(Suricata8, sticky("sip.via", "")),
	addedIn(Suricata8, sticky("sip.user_agent", "")),
	addedIn(Suricata8, sticky("sip.content_type", "")),
	addedIn(Suricata8, sticky("sip.content_length", "")),

	// SDP, carried by SIP.
	addedIn(Suricata8, sticky("sdp.origin", "")),
	addedIn(Suricata8, sticky("sdp.session_name", "")),
	addedIn(Suricata8, sticky("sdp.session_info", "")),
	addedIn(Suricata8, sticky("sdp.uri", "")),
	addedIn(Suricata8, sticky("sdp.email", "")),
	addedIn(Suricata8, sticky("sdp.phone_number", "")),
	addedIn(Suricata8, sticky("sdp.connection_data", "")),
	addedIn(Suricata8, sticky("sdp.bandwidth", "")),
	addedIn(Suricata8, sticky("sdp.time", "")),
	addedIn(Suricata8, sticky("sdp.repeat_time", "")),
	addedIn(Suricata8, sticky("sdp.timezone", "")),
	addedIn(Suricata8, sticky("sdp.encryption_key", "")),
	addedIn(Suricata8, sticky("sdp.attribute", "")),
	addedIn(Suricata8, sticky("sdp.media.media", "")),
	addedIn(Suricata8, sticky("sdp.media.media_info", "")),
	addedIn(Suricata8, sticky("sdp.media.connection_data", "")),
	addedIn(Suricata8, sticky("sdp.media.encryption_key", "")),

	// RFB.
	sticky("rfb.name", ""),
	appLayer("rfb.sectype", KindRaw),
	enumMatch("rfb.secresult", 32),

	// IKE.
	sticky("ike.init_spi", ""),
	sticky("ike.resp_spi", ""),
	sticky("ike.vendor", ""),
	sticky("ike.key_exchange_payload", ""),
	sticky("ike.nonce_payload", ""),
	appLayer("ike.chosen_sa_attribute", KindRaw),
	appLayer("ike.exchtype", KindRaw),
	appLayer("ike.key_exchange_payload_length", KindRaw),
	appLayer("ike.nonce_payload_length", KindRaw),

	// DHCP.
	appLayer("dhcp.leasetime", KindRaw),
	appLayer("dhcp.rebinding_time", KindRaw),
	appLayer("dhcp.renewal_time", KindRaw),

	// QUIC.
	sticky("quic.cyu.hash", ""),
	sticky("quic.cyu.string", ""),
	sticky("quic.sni", ""),
	sticky("quic.ua", ""),
	sticky("quic.version", ""),

	// SMTP.
	addedIn(Suricata8, sticky("smtp.helo", "")),
	addedIn(Suricata8, sticky("smtp.mail_from", "")),
	addedIn(Suricata8, sticky("smtp.rcpt_to", "")),

	// MQTT.
	sticky("mqtt.connect.clientid", ""),
	sticky("mqtt.connect.password", ""),
	addedIn(Suricata8, sticky("mqtt.connect.protocol_string", "")),
	sticky("mqtt.connect.username", ""),
	sticky("mqtt.connect.willmessage", ""),
	sticky("mqtt.connect.willtopic", ""),
	sticky("mqtt.publish.message", ""),
	sticky("mqtt.publish.topic", ""),
	sticky("mqtt.subscribe.topic", ""),
	sticky("mqtt.unsubscribe.topic", ""),
	appLayer("mqtt.connect.flags", KindCSV),
	appLayer("mqtt.connack.session_present", KindIdent),
	// 7.0 registers this alias of mqtt.reason_code; 8.0 does not.
	{Name: "mqtt.connack.return_code", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Successor: "mqtt.reason_code", Removed: Suricata8},
	appLayer("mqtt.qos", KindRaw),
	appLayer("mqtt.type", KindRaw),
	appLayer("mqtt.flags", KindCSV),
	appLayer("mqtt.reason_code", KindRaw),
	appLayer("mqtt.protocol_version", KindRaw),

	// LDAP. The responses keywords take an optional index before their
	// value, so those values are not decoded.
	addedIn(Suricata8, enumMatch("ldap.request.operation", 8)),
	addedIn(Suricata8, sticky("ldap.request.dn", "")),
	addedIn(Suricata8, sticky("ldap.request.attribute_type", "")),
	addedIn(Suricata8, uintMatch("ldap.responses.count", 32)),
	{Name: "ldap.responses.operation", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Repeatable: true, Added: Suricata8},
	{Name: "ldap.responses.result_code", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Repeatable: true, Added: Suricata8},
	addedIn(Suricata8, sticky("ldap.responses.dn", "")),
	addedIn(Suricata8, sticky("ldap.responses.attribute_type", "")),
	addedIn(Suricata8, sticky("ldap.responses.message", "")),

	// NTP.
	addedIn(Suricata8, uintMatch("ntp.version", 8)),
	addedIn(Suricata8, enumMatch("ntp.mode", 8)),
	addedIn(Suricata8, uintMatch("ntp.stratum", 8)),
	addedIn(Suricata8, sticky("ntp.reference_id", "")),

	// EtherNet/IP and CIP.
	addedIn(Suricata8, enumMatch("enip.status", 32)),
	addedIn(Suricata8, uintMatch("enip.protocol_version", 16)),
	addedIn(Suricata8, uintMatch("enip.capabilities", 16)),
	addedIn(Suricata8, uintMatch("enip.vendor_id", 16)),
	addedIn(Suricata8, uintMatch("enip.device_type", 16)),
	addedIn(Suricata8, uintMatch("enip.product_code", 16)),
	addedIn(Suricata8, uintMatch("enip.revision", 16)),
	addedIn(Suricata8, uintMatch("enip.identity_status", 16)),
	addedIn(Suricata8, uintMatch("enip.serial", 32)),
	addedIn(Suricata8, uintMatch("enip.state", 8)),
	addedIn(Suricata8, sticky("enip.product_name", "")),
	addedIn(Suricata8, sticky("enip.service_name", "")),
	addedIn(Suricata8, uintMatch("enip.cip_attribute", 32)),
	addedIn(Suricata8, uintMatch("enip.cip_class", 32)),
	addedIn(Suricata8, uintMatch("enip.cip_instance", 32)),
	addedIn(Suricata8, uintMatch("enip.cip_status", 8)),
	addedIn(Suricata8, uintMatch("enip.cip_extendedstatus", 16)),

	// WebSocket. websocket.flags takes named flags.
	addedIn(Suricata8, sticky("websocket.payload", "")),
	addedIn(Suricata8, enumMatch("websocket.opcode", 8)),
	addedIn(Suricata8, uintMatch("websocket.mask", 32)),
	{Name: "websocket.flags", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Repeatable: true, Added: Suricata8},

	// Email (SMTP), PostgreSQL.
	addedIn(Suricata8, sticky("email.from", "")),
	addedIn(Suricata8, sticky("email.to", "")),
	addedIn(Suricata8, sticky("email.cc", "")),
	addedIn(Suricata8, sticky("email.subject", "")),
	addedIn(Suricata8, sticky("email.date", "")),
	addedIn(Suricata8, sticky("email.message_id", "")),
	addedIn(Suricata8, sticky("email.x_mailer", "")),
	addedIn(Suricata8, sticky("email.url", "")),
	addedIn(Suricata8, sticky("email.received", "")),
	addedIn(Suricata8, sticky("pgsql.query", "")),

	// Other application layers.
	{Name: "modbus", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	sticky("dnp3.data", ""),
	// The dotted names Suricata gives the dnp3_* keywords.
	{Name: "dnp3.func", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Replaces: "dnp3_func"},
	{Name: "dnp3.ind", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Replaces: "dnp3_ind"},
	{Name: "dnp3.obj", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Replaces: "dnp3_obj"},
	appLayer("nfs_procedure", KindRaw),
	appLayer("nfs_version", KindRaw),
	appLayer("nfs.version", KindRaw),
	// app-layer-protocol takes an optional '!' before the name.
	{Name: "app-layer-protocol", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "app-layer-event", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleAppLayer},
	// app-layer-state takes an optional '<' or '>' before the state.
	{Name: "app-layer-state", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Added: Suricata8},

	// Frames: frame selects the frame named by its value as the buffer.
	{Name: "frame", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleStickyBuffer, Repeatable: true},

	// Packet headers.
	sticky("tcp.hdr", ""),
	sticky("udp.hdr", ""),
	sticky("ipv4.hdr", ""),
	sticky("ipv6.hdr", ""),
	sticky("icmpv4.hdr", ""),
	sticky("icmpv6.hdr", ""),
	sticky("ip.src", ""),
	sticky("ip.dst", ""),
	// The checksum keywords take valid or invalid, which Suricata also
	// reads in quotes.
	withRole(RoleNonPayload, appLayer("ipv4-csum", KindRaw)),
	withRole(RoleNonPayload, appLayer("tcpv4-csum", KindRaw)),
	withRole(RoleNonPayload, appLayer("tcpv6-csum", KindRaw)),
	withRole(RoleNonPayload, appLayer("udpv4-csum", KindRaw)),
	withRole(RoleNonPayload, appLayer("udpv6-csum", KindRaw)),
	withRole(RoleNonPayload, appLayer("icmpv4-csum", KindRaw)),
	withRole(RoleNonPayload, appLayer("icmpv6-csum", KindRaw)),
	// The tcp.* names Suricata gives seq, ack and window.
	{Name: "tcp.seq", Dialects: SetSuricata, Value: Required, Kind: KindUint, Role: RoleNonPayload, Replaces: "seq"},
	{Name: "tcp.ack", Dialects: SetSuricata, Value: Required, Kind: KindUint, Role: RoleNonPayload, Replaces: "ack"},
	{Name: "tcp.window", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleNonPayload, Replaces: "window"},
	addedIn(Suricata8, withRole(RoleNonPayload, uintMatch("tcp.wscale", 8))),
	{Name: "tcp.session", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleNonPayload, Added: Suricata8},
	// vlan.id takes an id and an optional layer.
	{Name: "vlan.id", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleNonPayload, Repeatable: true, Added: Suricata8},
	addedIn(Suricata8, withRole(RoleNonPayload, uintMatch("vlan.layers", 8))),
	{Name: "tcp.flags", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "tcp.mss", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "icmpv6.mtu", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "l3_proto", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleNonPayload},
	{Name: "geoip", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleNonPayload},
	{Name: "iprep", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleNonPayload, Repeatable: true},
	{Name: "decode-event", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleNonPayload},
	{Name: "engine-event", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleNonPayload},
	{Name: "stream-event", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleNonPayload},

	// Flow and state.
	{Name: "flowint", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleFlow, Repeatable: true},
	{Name: "xbits", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleFlow, Repeatable: true},
	{Name: "hostbits", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleFlow, Repeatable: true},
	{Name: "flowvar", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleFlow, Repeatable: true},
	{Name: "pktvar", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleFlow, Repeatable: true},
	// flow.pkts and flow.bytes take a direction, then a number.
	{Name: "flow.pkts", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleFlow, Added: Suricata8},
	{Name: "flow.bytes", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleFlow, Added: Suricata8},
	{Name: "flow.elephant", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleFlow, Added: Suricata8},
	{Name: "flow.age", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow, Bits: 32},
	{Name: "flow.pkts_toserver", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow, Added: Suricata8, Bits: 32},
	{Name: "flow.pkts_toclient", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow, Added: Suricata8, Bits: 32},
	{Name: "flow.bytes_toserver", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow, Added: Suricata8, Bits: 64},
	{Name: "flow.bytes_toclient", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow, Added: Suricata8, Bits: 64},
	{Name: "dataset", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "datarep", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},

	// Post-detection and rule control.
	{Name: "noalert", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RolePostDetect},
	// alert undoes noalert, in a rule whose action does not alert.
	{Name: "alert", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RolePostDetect},
	{Name: "nfq_set_mark", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePostDetect},
	{Name: "prefilter", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleOther},
	{Name: "bypass", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RolePostDetect},
	{Name: "target", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleMeta},
	{Name: "requires", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleOther},
	{Name: "config", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleOther},
	{Name: "lua", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleOther, Repeatable: true},
	{Name: "luajit", Dialects: SetSuricata, Deprecated: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleOther, Repeatable: true, Successor: "lua", Removed: Suricata8},
}

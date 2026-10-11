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

// suricataKeywords are the keywords that exist only in Suricata, following
// the Suricata 7 keyword index plus a few from later versions. Values with grammars of their own are KindRaw.
var suricataKeywords = []Keyword{
	// Content modifiers, buffer tests and transforms. A buffer test
	// (bsize, absent) examines the active sticky buffer itself; a
	// transform rewrites it before the matches that follow.
	{Name: "startswith", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true},
	{Name: "endswith", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleModifier, Repeatable: true},
	{Name: "bsize", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleBufferTest, Repeatable: true},
	{Name: "absent", Dialects: SetSuricata, Value: Optional, Kind: KindRaw, Role: RoleBufferTest, Repeatable: true},
	// pcrexform takes a quoted regular expression, whose escapes are
	// PCRE's rather than a quoted string's.
	{Name: "pcrexform", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleTransform, Repeatable: true},
	{Name: "xor", Dialects: SetSuricata, Value: Required, Kind: KindQuoted, Role: RoleTransform, Repeatable: true},
	{Name: "from_base64", Dialects: SetSuricata, Value: Optional, Kind: KindRaw, Role: RoleTransform, Repeatable: true},
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

	// HTTP sticky buffers.
	sticky("http.uri", "http_uri"),
	sticky("http.uri.raw", "http_raw_uri"),
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
	sticky("http.accept", ""),
	sticky("http.accept_lang", ""),
	sticky("http.accept_enc", ""),
	sticky("http.referer", ""),
	sticky("http.connection", ""),
	sticky("http.content_type", ""),
	sticky("http.content_len", ""),
	sticky("http.protocol", ""),
	sticky("http.start", ""),
	sticky("http.response_line", ""),
	sticky("http.response_body", ""),
	sticky("http.stat_code", "http_stat_code"),
	sticky("http.stat_msg", "http_stat_msg"),
	sticky("http.server", ""),
	sticky("http.location", ""),
	legacyModifier("http_server_body", "http.response_body"),
	legacyModifier("http_user_agent", "http.user_agent"),
	legacyModifier("http_host", "http.host"),
	legacyModifier("http_raw_host", "http.host.raw"),
	legacySticky("http_accept", "http.accept"),
	legacySticky("http_accept_lang", "http.accept_lang"),
	legacySticky("http_accept_enc", "http.accept_enc"),
	legacySticky("http_referer", "http.referer"),
	legacySticky("http_connection", "http.connection"),
	legacySticky("http_content_type", "http.content_type"),
	legacySticky("http_content_len", "http.content_len"),
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
	sticky("http2.header", ""),

	// Files.
	sticky("file.data", "file_data"),
	sticky("file.name", ""),
	sticky("file.magic", ""),
	{Name: "filename", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "fileext", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "filemagic", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "filestore", Dialects: SetSuricata, Value: Optional, Kind: KindRaw, Role: RolePostDetect},
	{Name: "filemd5", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload},
	{Name: "filesha1", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload},
	{Name: "filesha256", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload},
	{Name: "filesize", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RolePayload},

	// DNS.
	sticky("dns.query", ""),
	legacySticky("dns_query", "dns.query"),
	sticky("dns.answer.name", ""),
	appLayer("dns.opcode", KindRelInt),

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

	// JA3, JA3S, JA4.
	sticky("ja3.hash", ""),
	sticky("ja3.string", ""),
	legacySticky("ja3_hash", "ja3.hash"),
	legacySticky("ja3_string", "ja3.string"),
	sticky("ja3s.hash", ""),
	sticky("ja3s.string", ""),
	sticky("ja4.hash", ""),

	// SSH.
	sticky("ssh.proto", ""),
	sticky("ssh.software", ""),
	legacySticky("ssh_proto", "ssh.proto"),
	legacySticky("ssh_software", "ssh.software"),
	sticky("ssh.hassh", ""),
	sticky("ssh.hassh.string", ""),
	sticky("ssh.hassh.server", ""),
	sticky("ssh.hassh.server.string", ""),
	appLayer("ssh.protoversion", KindRaw),
	appLayer("ssh.softwareversion", KindRaw),

	// SMB.
	sticky("smb.named_pipe", ""),
	sticky("smb.share", ""),
	sticky("smb.ntlmssp_user", ""),
	sticky("smb.ntlmssp_domain", ""),
	legacySticky("smb_named_pipe", "smb.named_pipe"),
	legacySticky("smb_share", "smb.share"),

	// Kerberos.
	sticky("krb5.cname", ""),
	sticky("krb5.sname", ""),
	legacySticky("krb5_cname", "krb5.cname"),
	legacySticky("krb5_sname", "krb5.sname"),
	appLayer("krb5_msg_type", KindRaw),
	appLayer("krb5_err_code", KindRaw),
	appLayer("krb5.ticket_encryption", KindRaw),
	{Name: "krb5.weak_encryption", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleAppLayer},

	// DCE/RPC.
	{Name: "dcerpc.iface", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Replaces: "dce_iface"},
	{Name: "dcerpc.opnum", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer, Replaces: "dce_opnum"},
	sticky("dcerpc.stub_data", "dce_stub_data"),

	// SNMP.
	sticky("snmp.community", ""),
	sticky("snmp.usm", ""),
	appLayer("snmp.version", KindRaw),
	appLayer("snmp.pdu_type", KindRaw),

	// SIP.
	sticky("sip.method", ""),
	sticky("sip.uri", ""),
	sticky("sip.protocol", ""),
	sticky("sip.stat_code", ""),
	sticky("sip.stat_msg", ""),
	sticky("sip.request_line", ""),
	sticky("sip.response_line", ""),

	// RFB.
	sticky("rfb.name", ""),
	appLayer("rfb.sectype", KindRaw),
	appLayer("rfb.secresult", KindIdent),

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
	appLayer("quic.version", KindRaw),

	// SMTP.
	sticky("smtp.helo", ""),
	sticky("smtp.mail_from", ""),
	sticky("smtp.rcpt_to", ""),

	// MQTT.
	sticky("mqtt.connect.clientid", ""),
	sticky("mqtt.connect.password", ""),
	sticky("mqtt.connect.protocol_string", ""),
	sticky("mqtt.connect.username", ""),
	sticky("mqtt.connect.willmessage", ""),
	sticky("mqtt.connect.willtopic", ""),
	sticky("mqtt.publish.message", ""),
	sticky("mqtt.publish.topic", ""),
	sticky("mqtt.subscribe.topic", ""),
	sticky("mqtt.unsubscribe.topic", ""),
	appLayer("mqtt.connect.flags", KindCSV),
	appLayer("mqtt.connack.session_present", KindIdent),
	appLayer("mqtt.connack.reason_code", KindRaw),
	appLayer("mqtt.qos", KindRaw),
	appLayer("mqtt.type", KindRaw),
	appLayer("mqtt.flags", KindCSV),
	appLayer("mqtt.reason_code", KindRaw),
	appLayer("mqtt.protocol_version", KindRaw),

	// Other application layers.
	{Name: "modbus", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	sticky("dnp3.data", ""),
	appLayer("nfs_procedure", KindRaw),
	appLayer("nfs_version", KindRaw),
	appLayer("ftpdata_command", KindIdent),
	// app-layer-protocol takes an optional '!' before the name.
	{Name: "app-layer-protocol", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleAppLayer},
	{Name: "app-layer-event", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleAppLayer},

	// Packet headers.
	sticky("tcp.hdr", ""),
	sticky("udp.hdr", ""),
	sticky("ip.hdr", ""),
	sticky("ipv4.hdr", ""),
	sticky("ipv6.hdr", ""),
	sticky("icmpv4.hdr", ""),
	sticky("icmpv6.hdr", ""),
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
	{Name: "flow.age", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow},
	{Name: "flow.pkts_toserver", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow},
	{Name: "flow.pkts_toclient", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow},
	{Name: "flow.bytes_toserver", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow},
	{Name: "flow.bytes_toclient", Dialects: SetSuricata, Value: Required, Kind: KindRelInt, Role: RoleFlow},
	{Name: "dataset", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},
	{Name: "datarep", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RolePayload, Repeatable: true},

	// Post-detection and rule control.
	{Name: "noalert", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RolePostDetect},
	{Name: "prefilter", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RoleOther},
	{Name: "bypass", Dialects: SetSuricata, Value: NoValue, Kind: KindNone, Role: RolePostDetect},
	{Name: "target", Dialects: SetSuricata, Value: Required, Kind: KindIdent, Role: RoleMeta},
	{Name: "requires", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleOther},
	{Name: "config", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleOther},
	{Name: "lua", Dialects: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleOther, Repeatable: true},
	{Name: "luajit", Dialects: SetSuricata, Deprecated: SetSuricata, Value: Required, Kind: KindRaw, Role: RoleOther, Repeatable: true, Successor: "lua"},
}

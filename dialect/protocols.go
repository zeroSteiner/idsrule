package dialect

import "slices"

// snort2Protocols are the protocols a Snort 2.9 rule header accepts.
var snort2Protocols = []string{"ip", "tcp", "udp", "icmp"}

// suricataProtocols are the protocols a Suricata rule header accepts: the
// network protocols, their aliases, and the application-layer protocols.
// The list follows Suricata 7 and includes the protocols later versions
// added, so that a rule for a newer engine is not rejected.
var suricataProtocols = []string{
	// Network layer and transport.
	"ip", "ip4", "ip6", "ipv4", "ipv6", "pkthdr",
	"tcp", "tcp-pkt", "tcp-stream", "udp", "sctp",
	"icmp", "icmpv4", "icmpv6", "igmp",
	// Application layer.
	"bittorrent-dht", "dcerpc", "dhcp", "dnp3", "dns", "enip", "ftp", "ftp-data",
	"http", "http1", "http2", "ike", "ikev2", "imap", "irc", "jabber", "krb5",
	"ldap", "mdns", "modbus", "mqtt", "nfs", "ntp", "pgsql", "pop3", "quic",
	"rdp", "rfb", "sip", "smb", "smtp", "snmp", "ssh", "telnet", "tftp", "tls",
	"websocket",
}

// Protocols returns the protocols a rule header of d accepts, or the sorted
// union of every dialect's protocols for Unknown and for a dialect outside
// the defined range. The slice is the caller's.
func (d Dialect) Protocols() []string {
	switch d {
	case Snort2:
		return slices.Clone(snort2Protocols)
	case Suricata:
		return slices.Clone(suricataProtocols)
	case Unknown:
	}
	return union(snort2Protocols, suricataProtocols)
}

// IsProtocol reports whether s is a protocol a rule header of d accepts;
// for Unknown or an undefined dialect, of any dialect.
func (d Dialect) IsProtocol(s string) bool {
	return slices.Contains(d.Protocols(), s)
}

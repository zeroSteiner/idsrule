package dialect

import (
	"slices"
	"strings"
)

// snort2Protocols are the protocols a Snort 2.9 rule header accepts.
var snort2Protocols = []string{"ip", "tcp", "udp", "icmp"}

// suricataProtocols are the protocols a Suricata rule header accepts: the
// network protocols, their aliases, and the application-layer protocols.
// The list is the union of Suricata 7.0's and 8.0's; ProtocolAdded says
// which came with 8.0.
var suricataProtocols = slices.Concat(suricataPacketProtocols, suricataAppProtocols)

// suricataPacketProtocols are the Suricata protocols of the network and
// transport layers; a packet hook ("tcp:all") follows only them.
var suricataPacketProtocols = []string{
	"ip", "ip4", "ip6", "ipv4", "ipv6", "pkthdr",
	"tcp", "tcp-pkt", "tcp-stream", "udp", "sctp",
	"icmp", "icmpv4", "icmpv6", "igmp",
}

// suricataAppProtocols are the Suricata application-layer protocols.
var suricataAppProtocols = []string{
	"bittorrent-dht", "dcerpc", "dhcp", "dnp3", "dns", "doh2", "enip", "ftp", "ftp-data",
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

// suricataProtocolsAdded are the Suricata protocols that not every release
// the tables describe has, with the release that added them.
var suricataProtocolsAdded = map[string]Version{
	"doh2": Suricata8, "ldap": Suricata8, "mdns": Suricata8, "pop3": Suricata8, "websocket": Suricata8,
}

// ProtocolAdded returns the release of d that added the protocol s, or
// AnyVersion when every release the tables describe has it or it is not
// one of d's protocols. The name is compared without regard to case.
func (d Dialect) ProtocolAdded(s string) Version {
	if d != Suricata {
		return AnyVersion
	}
	return suricataProtocolsAdded[strings.ToLower(s)]
}

// IsPacketProtocol reports whether s is a network-layer or transport
// protocol of d, such as tcp or pkthdr, rather than an application-layer
// one; for Unknown or an undefined dialect, of any dialect. The comparison
// ignores case.
func (d Dialect) IsPacketProtocol(s string) bool {
	switch d {
	case Snort2:
		return containsFold(snort2Protocols, s)
	case Suricata:
		return containsFold(suricataPacketProtocols, s)
	case Unknown:
	}
	return containsFold(snort2Protocols, s) || containsFold(suricataPacketProtocols, s)
}

// IsProtocol reports whether s is a protocol a rule header of d accepts;
// for Unknown or an undefined dialect, of any dialect. The comparison
// ignores case, as both engines do; only the names in the tables are
// protocols, so a protocol number is not one.
func (d Dialect) IsProtocol(s string) bool {
	return containsFold(d.Protocols(), s)
}

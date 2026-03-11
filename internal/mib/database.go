package mib

// GetExtendedMIBDatabase returns a comprehensive OID database for network monitoring.
func GetExtendedMIBDatabase() []OIDEntry {
	return []OIDEntry{
		// ═══ SNMPv2-MIB (System) ═══
		{OID: "1.3.6.1.2.1.1.1", Name: "sysDescr", Module: "SNMPv2-MIB", Description: "System description", Syntax: "DisplayString", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.2", Name: "sysObjectID", Module: "SNMPv2-MIB", Description: "System object identifier", Syntax: "OBJECT IDENTIFIER", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.3", Name: "sysUpTime", Module: "SNMPv2-MIB", Description: "System uptime in timeticks", Syntax: "TimeTicks", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.4", Name: "sysContact", Module: "SNMPv2-MIB", Description: "System contact person", Syntax: "DisplayString", Access: "read-write", Category: "system"},
		{OID: "1.3.6.1.2.1.1.5", Name: "sysName", Module: "SNMPv2-MIB", Description: "System hostname", Syntax: "DisplayString", Access: "read-write", Category: "system"},
		{OID: "1.3.6.1.2.1.1.6", Name: "sysLocation", Module: "SNMPv2-MIB", Description: "System physical location", Syntax: "DisplayString", Access: "read-write", Category: "system"},
		{OID: "1.3.6.1.2.1.1.7", Name: "sysServices", Module: "SNMPv2-MIB", Description: "System services", Syntax: "INTEGER", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.8", Name: "sysORLastChange", Module: "SNMPv2-MIB", Description: "Last change time of sysOR table", Syntax: "TimeTicks", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.9.1.2", Name: "sysORID", Module: "SNMPv2-MIB", Description: "OR table entry OID", Syntax: "OBJECT IDENTIFIER", Access: "read-only", Category: "system"},
		{OID: "1.3.6.1.2.1.1.9.1.3", Name: "sysORDescr", Module: "SNMPv2-MIB", Description: "OR table entry description", Syntax: "DisplayString", Access: "read-only", Category: "system"},

		// ═══ IF-MIB (Interfaces) ═══
		{OID: "1.3.6.1.2.1.2.1", Name: "ifNumber", Module: "IF-MIB", Description: "Number of network interfaces", Syntax: "INTEGER", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.1", Name: "ifIndex", Module: "IF-MIB", Description: "Interface index", Syntax: "InterfaceIndex", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.2", Name: "ifDescr", Module: "IF-MIB", Description: "Interface description", Syntax: "DisplayString", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.3", Name: "ifType", Module: "IF-MIB", Description: "Interface type", Syntax: "IANAifType", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.4", Name: "ifMtu", Module: "IF-MIB", Description: "Interface MTU size", Syntax: "INTEGER", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.5", Name: "ifSpeed", Module: "IF-MIB", Description: "Interface speed (bps)", Syntax: "Gauge32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.6", Name: "ifPhysAddress", Module: "IF-MIB", Description: "Interface MAC address", Syntax: "PhysAddress", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.7", Name: "ifAdminStatus", Module: "IF-MIB", Description: "Interface admin status (1=up,2=down,3=testing)", Syntax: "INTEGER", Access: "read-write", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.8", Name: "ifOperStatus", Module: "IF-MIB", Description: "Interface operational status (1=up,2=down)", Syntax: "INTEGER", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.9", Name: "ifLastChange", Module: "IF-MIB", Description: "Last status change time", Syntax: "TimeTicks", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.10", Name: "ifInOctets", Module: "IF-MIB", Description: "Incoming octets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.11", Name: "ifInUcastPkts", Module: "IF-MIB", Description: "Incoming unicast packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.12", Name: "ifInNUcastPkts", Module: "IF-MIB", Description: "Incoming non-unicast packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.13", Name: "ifInDiscards", Module: "IF-MIB", Description: "Incoming discarded packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.14", Name: "ifInErrors", Module: "IF-MIB", Description: "Incoming error packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.15", Name: "ifInUnknownProtos", Module: "IF-MIB", Description: "Incoming unknown protocol packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.16", Name: "ifOutOctets", Module: "IF-MIB", Description: "Outgoing octets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.17", Name: "ifOutUcastPkts", Module: "IF-MIB", Description: "Outgoing unicast packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.18", Name: "ifOutNUcastPkts", Module: "IF-MIB", Description: "Outgoing non-unicast packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.19", Name: "ifOutDiscards", Module: "IF-MIB", Description: "Outgoing discarded packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.20", Name: "ifOutErrors", Module: "IF-MIB", Description: "Outgoing error packets", Syntax: "Counter32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.2.2.1.21", Name: "ifOutQLen", Module: "IF-MIB", Description: "Output queue length", Syntax: "Gauge32", Access: "read-only", Category: "interfaces"},
		// IF-MIB 64-bit counters
		{OID: "1.3.6.1.2.1.31.1.1.1.1", Name: "ifName", Module: "IF-MIB", Description: "Interface short name", Syntax: "DisplayString", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.6", Name: "ifHCInOctets", Module: "IF-MIB", Description: "Incoming octets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.7", Name: "ifHCInUcastPkts", Module: "IF-MIB", Description: "Incoming unicast packets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.8", Name: "ifHCInMulticastPkts", Module: "IF-MIB", Description: "Incoming multicast packets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.9", Name: "ifHCInBroadcastPkts", Module: "IF-MIB", Description: "Incoming broadcast packets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.10", Name: "ifHCOutOctets", Module: "IF-MIB", Description: "Outgoing octets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.11", Name: "ifHCOutUcastPkts", Module: "IF-MIB", Description: "Outgoing unicast packets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.12", Name: "ifHCOutMulticastPkts", Module: "IF-MIB", Description: "Outgoing multicast packets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.13", Name: "ifHCOutBroadcastPkts", Module: "IF-MIB", Description: "Outgoing broadcast packets (64-bit)", Syntax: "Counter64", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.15", Name: "ifHighSpeed", Module: "IF-MIB", Description: "Interface speed (Mbps)", Syntax: "Gauge32", Access: "read-only", Category: "interfaces"},
		{OID: "1.3.6.1.2.1.31.1.1.1.18", Name: "ifAlias", Module: "IF-MIB", Description: "Interface alias/description", Syntax: "DisplayString", Access: "read-write", Category: "interfaces"},

		// ═══ IP-MIB ═══
		{OID: "1.3.6.1.2.1.4.1", Name: "ipForwarding", Module: "IP-MIB", Description: "IP forwarding enabled (1=yes,2=no)", Syntax: "INTEGER", Access: "read-write", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.2", Name: "ipDefaultTTL", Module: "IP-MIB", Description: "Default IP TTL", Syntax: "INTEGER", Access: "read-write", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.3", Name: "ipInReceives", Module: "IP-MIB", Description: "IP datagrams received", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.4", Name: "ipInHdrErrors", Module: "IP-MIB", Description: "IP header errors", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.5", Name: "ipInAddrErrors", Module: "IP-MIB", Description: "IP address errors", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.6", Name: "ipForwDatagrams", Module: "IP-MIB", Description: "IP forwarded datagrams", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.9", Name: "ipInDelivers", Module: "IP-MIB", Description: "IP datagrams delivered locally", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.10", Name: "ipOutRequests", Module: "IP-MIB", Description: "IP output requests", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.11", Name: "ipOutDiscards", Module: "IP-MIB", Description: "IP output discards", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.12", Name: "ipOutNoRoutes", Module: "IP-MIB", Description: "IP no route discards", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.14", Name: "ipReasmReqds", Module: "IP-MIB", Description: "IP reassembly required", Syntax: "Counter32", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.20.1.1", Name: "ipAdEntAddr", Module: "IP-MIB", Description: "IP address entry", Syntax: "IpAddress", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.20.1.2", Name: "ipAdEntIfIndex", Module: "IP-MIB", Description: "IP address interface index", Syntax: "INTEGER", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.20.1.3", Name: "ipAdEntNetMask", Module: "IP-MIB", Description: "IP address subnet mask", Syntax: "IpAddress", Access: "read-only", Category: "ip"},
		{OID: "1.3.6.1.2.1.4.21.1.1", Name: "ipRouteDestination", Module: "IP-MIB", Description: "Route destination", Syntax: "IpAddress", Access: "read-only", Category: "ip_routing"},
		{OID: "1.3.6.1.2.1.4.21.1.7", Name: "ipRouteNextHop", Module: "IP-MIB", Description: "Route next hop", Syntax: "IpAddress", Access: "read-only", Category: "ip_routing"},
		{OID: "1.3.6.1.2.1.4.21.1.8", Name: "ipRouteType", Module: "IP-MIB", Description: "Route type (1=other,2=invalid,3=direct,4=indirect)", Syntax: "INTEGER", Access: "read-only", Category: "ip_routing"},
		{OID: "1.3.6.1.2.1.4.21.1.11", Name: "ipRouteMask", Module: "IP-MIB", Description: "Route mask", Syntax: "IpAddress", Access: "read-only", Category: "ip_routing"},
		{OID: "1.3.6.1.2.1.4.22.1.2", Name: "ipNetToMediaPhysAddress", Module: "IP-MIB", Description: "ARP table MAC address", Syntax: "PhysAddress", Access: "read-write", Category: "arp"},
		{OID: "1.3.6.1.2.1.4.22.1.3", Name: "ipNetToMediaNetAddress", Module: "IP-MIB", Description: "ARP table IP address", Syntax: "IpAddress", Access: "read-only", Category: "arp"},
		{OID: "1.3.6.1.2.1.4.22.1.4", Name: "ipNetToMediaType", Module: "IP-MIB", Description: "ARP entry type (1=other,2=invalid,3=dynamic,4=static)", Syntax: "INTEGER", Access: "read-write", Category: "arp"},

		// ═══ TCP-MIB ═══
		{OID: "1.3.6.1.2.1.6.1", Name: "tcpRtoAlgorithm", Module: "TCP-MIB", Description: "TCP retransmission algorithm", Syntax: "INTEGER", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.5", Name: "tcpActiveOpens", Module: "TCP-MIB", Description: "Active TCP connections opened", Syntax: "Counter32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.6", Name: "tcpPassiveOpens", Module: "TCP-MIB", Description: "Passive TCP connections opened", Syntax: "Counter32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.7", Name: "tcpAttemptFails", Module: "TCP-MIB", Description: "TCP connection attempt failures", Syntax: "Counter32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.8", Name: "tcpEstabResets", Module: "TCP-MIB", Description: "TCP established connection resets", Syntax: "Counter32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.9", Name: "tcpCurrEstab", Module: "TCP-MIB", Description: "Currently established TCP connections", Syntax: "Gauge32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.10", Name: "tcpInSegs", Module: "TCP-MIB", Description: "TCP segments received", Syntax: "Counter32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.11", Name: "tcpOutSegs", Module: "TCP-MIB", Description: "TCP segments sent", Syntax: "Counter32", Access: "read-only", Category: "tcp"},
		{OID: "1.3.6.1.2.1.6.12", Name: "tcpRetransSegs", Module: "TCP-MIB", Description: "TCP segments retransmitted", Syntax: "Counter32", Access: "read-only", Category: "tcp"},

		// ═══ UDP-MIB ═══
		{OID: "1.3.6.1.2.1.7.1", Name: "udpInDatagrams", Module: "UDP-MIB", Description: "UDP datagrams received", Syntax: "Counter32", Access: "read-only", Category: "udp"},
		{OID: "1.3.6.1.2.1.7.2", Name: "udpNoPorts", Module: "UDP-MIB", Description: "UDP no port datagrams", Syntax: "Counter32", Access: "read-only", Category: "udp"},
		{OID: "1.3.6.1.2.1.7.3", Name: "udpInErrors", Module: "UDP-MIB", Description: "UDP input errors", Syntax: "Counter32", Access: "read-only", Category: "udp"},
		{OID: "1.3.6.1.2.1.7.4", Name: "udpOutDatagrams", Module: "UDP-MIB", Description: "UDP datagrams sent", Syntax: "Counter32", Access: "read-only", Category: "udp"},

		// ═══ ICMP ═══
		{OID: "1.3.6.1.2.1.5.1", Name: "icmpInMsgs", Module: "IP-MIB", Description: "ICMP messages received", Syntax: "Counter32", Access: "read-only", Category: "icmp"},
		{OID: "1.3.6.1.2.1.5.2", Name: "icmpInErrors", Module: "IP-MIB", Description: "ICMP errors received", Syntax: "Counter32", Access: "read-only", Category: "icmp"},
		{OID: "1.3.6.1.2.1.5.8", Name: "icmpInEchos", Module: "IP-MIB", Description: "ICMP echo requests received (pings)", Syntax: "Counter32", Access: "read-only", Category: "icmp"},
		{OID: "1.3.6.1.2.1.5.14", Name: "icmpOutMsgs", Module: "IP-MIB", Description: "ICMP messages sent", Syntax: "Counter32", Access: "read-only", Category: "icmp"},

		// ═══ BRIDGE-MIB (L2 Switching) ═══
		{OID: "1.3.6.1.2.1.17.1.1", Name: "dot1dBaseBridgeAddress", Module: "BRIDGE-MIB", Description: "Bridge MAC address", Syntax: "MacAddress", Access: "read-only", Category: "bridge"},
		{OID: "1.3.6.1.2.1.17.1.2", Name: "dot1dBaseNumPorts", Module: "BRIDGE-MIB", Description: "Number of bridge ports", Syntax: "INTEGER", Access: "read-only", Category: "bridge"},
		{OID: "1.3.6.1.2.1.17.1.3", Name: "dot1dBaseType", Module: "BRIDGE-MIB", Description: "Bridge type (1=unknown,2=transparent,3=sourceroute,4=srt)", Syntax: "INTEGER", Access: "read-only", Category: "bridge"},
		{OID: "1.3.6.1.2.1.17.1.4.1.1", Name: "dot1dBasePort", Module: "BRIDGE-MIB", Description: "Bridge port number", Syntax: "INTEGER", Access: "read-only", Category: "bridge"},
		{OID: "1.3.6.1.2.1.17.1.4.1.2", Name: "dot1dBasePortIfIndex", Module: "BRIDGE-MIB", Description: "Bridge port ifIndex mapping", Syntax: "InterfaceIndex", Access: "read-only", Category: "bridge"},
		{OID: "1.3.6.1.2.1.17.2.1", Name: "dot1dStpProtocolSpecification", Module: "BRIDGE-MIB", Description: "STP protocol (1=unknown,2=decLb100,3=ieee8021d)", Syntax: "INTEGER", Access: "read-only", Category: "stp"},
		{OID: "1.3.6.1.2.1.17.2.2", Name: "dot1dStpPriority", Module: "BRIDGE-MIB", Description: "STP bridge priority", Syntax: "INTEGER", Access: "read-write", Category: "stp"},
		{OID: "1.3.6.1.2.1.17.2.5", Name: "dot1dStpDesignatedRoot", Module: "BRIDGE-MIB", Description: "STP designated root bridge ID", Syntax: "BridgeId", Access: "read-only", Category: "stp"},
		{OID: "1.3.6.1.2.1.17.2.6", Name: "dot1dStpRootCost", Module: "BRIDGE-MIB", Description: "STP root path cost", Syntax: "INTEGER", Access: "read-only", Category: "stp"},
		{OID: "1.3.6.1.2.1.17.2.7", Name: "dot1dStpRootPort", Module: "BRIDGE-MIB", Description: "STP root port number", Syntax: "INTEGER", Access: "read-only", Category: "stp"},
		{OID: "1.3.6.1.2.1.17.2.15.1.3", Name: "dot1dStpPortState", Module: "BRIDGE-MIB", Description: "STP port state (1=disabled,2=blocking,3=listening,4=learning,5=forwarding)", Syntax: "INTEGER", Access: "read-only", Category: "stp"},
		{OID: "1.3.6.1.2.1.17.4.3.1.1", Name: "dot1dTpFdbAddress", Module: "BRIDGE-MIB", Description: "MAC address table entry", Syntax: "MacAddress", Access: "read-only", Category: "mac_table"},
		{OID: "1.3.6.1.2.1.17.4.3.1.2", Name: "dot1dTpFdbPort", Module: "BRIDGE-MIB", Description: "MAC address table port", Syntax: "INTEGER", Access: "read-only", Category: "mac_table"},
		{OID: "1.3.6.1.2.1.17.4.3.1.3", Name: "dot1dTpFdbStatus", Module: "BRIDGE-MIB", Description: "MAC address entry status (1=other,2=invalid,3=learned,4=self,5=mgmt)", Syntax: "INTEGER", Access: "read-only", Category: "mac_table"},

		// ═══ Q-BRIDGE-MIB (VLANs) ═══
		{OID: "1.3.6.1.2.1.17.7.1.1.1", Name: "dot1qVlanVersionNumber", Module: "Q-BRIDGE-MIB", Description: "802.1Q VLAN version", Syntax: "INTEGER", Access: "read-only", Category: "vlan"},
		{OID: "1.3.6.1.2.1.17.7.1.1.2", Name: "dot1qMaxVlanId", Module: "Q-BRIDGE-MIB", Description: "Maximum VLAN ID supported", Syntax: "INTEGER", Access: "read-only", Category: "vlan"},
		{OID: "1.3.6.1.2.1.17.7.1.1.4", Name: "dot1qNumVlans", Module: "Q-BRIDGE-MIB", Description: "Number of active VLANs", Syntax: "Unsigned32", Access: "read-only", Category: "vlan"},
		{OID: "1.3.6.1.2.1.17.7.1.4.2.1.3", Name: "dot1qVlanFdbId", Module: "Q-BRIDGE-MIB", Description: "VLAN FDB identifier", Syntax: "Unsigned32", Access: "read-only", Category: "vlan"},
		{OID: "1.3.6.1.2.1.17.7.1.4.3.1.1", Name: "dot1qVlanStaticName", Module: "Q-BRIDGE-MIB", Description: "VLAN name", Syntax: "SnmpAdminString", Access: "read-write", Category: "vlan"},
		{OID: "1.3.6.1.2.1.17.7.1.4.3.1.2", Name: "dot1qVlanStaticEgressPorts", Module: "Q-BRIDGE-MIB", Description: "VLAN egress port set", Syntax: "PortList", Access: "read-write", Category: "vlan"},
		{OID: "1.3.6.1.2.1.17.7.1.4.3.1.4", Name: "dot1qVlanStaticUntaggedPorts", Module: "Q-BRIDGE-MIB", Description: "VLAN untagged port set", Syntax: "PortList", Access: "read-write", Category: "vlan"},
		{OID: "1.3.6.1.2.1.17.7.1.4.3.1.5", Name: "dot1qVlanStaticRowStatus", Module: "Q-BRIDGE-MIB", Description: "VLAN row status", Syntax: "RowStatus", Access: "read-write", Category: "vlan"},
		{OID: "1.3.6.1.2.1.17.7.1.4.5.1.1", Name: "dot1qPvid", Module: "Q-BRIDGE-MIB", Description: "Port PVID (native VLAN)", Syntax: "VlanIndex", Access: "read-write", Category: "vlan"},

		// ═══ LLDP-MIB ═══
		{OID: "1.0.8802.1.1.2.1.3.1", Name: "lldpLocChassisIdSubtype", Module: "LLDP-MIB", Description: "Local chassis ID subtype", Syntax: "INTEGER", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.3.2", Name: "lldpLocChassisId", Module: "LLDP-MIB", Description: "Local chassis ID", Syntax: "OCTET STRING", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.3.3", Name: "lldpLocSysName", Module: "LLDP-MIB", Description: "Local system name", Syntax: "SnmpAdminString", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.3.4", Name: "lldpLocSysDesc", Module: "LLDP-MIB", Description: "Local system description", Syntax: "SnmpAdminString", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.4.1.1.5", Name: "lldpRemChassisId", Module: "LLDP-MIB", Description: "Remote chassis ID", Syntax: "OCTET STRING", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.4.1.1.7", Name: "lldpRemPortId", Module: "LLDP-MIB", Description: "Remote port ID", Syntax: "OCTET STRING", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.4.1.1.8", Name: "lldpRemPortDesc", Module: "LLDP-MIB", Description: "Remote port description", Syntax: "SnmpAdminString", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.4.1.1.9", Name: "lldpRemSysName", Module: "LLDP-MIB", Description: "Remote system name (neighbor hostname)", Syntax: "SnmpAdminString", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.4.1.1.10", Name: "lldpRemSysDesc", Module: "LLDP-MIB", Description: "Remote system description", Syntax: "SnmpAdminString", Access: "read-only", Category: "lldp"},
		{OID: "1.0.8802.1.1.2.1.4.2.1.3", Name: "lldpRemManAddrIfId", Module: "LLDP-MIB", Description: "Remote management address interface", Syntax: "INTEGER", Access: "read-only", Category: "lldp"},

		// ═══ ENTITY-MIB (Hardware Inventory) ═══
		{OID: "1.3.6.1.2.1.47.1.1.1.1.2", Name: "entPhysicalDescr", Module: "ENTITY-MIB", Description: "Physical entity description", Syntax: "DisplayString", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.4", Name: "entPhysicalContainedIn", Module: "ENTITY-MIB", Description: "Parent physical entity index", Syntax: "INTEGER", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.5", Name: "entPhysicalClass", Module: "ENTITY-MIB", Description: "Physical entity class (1=other,3=chassis,6=psu,7=fan,9=sensor,10=module,11=port)", Syntax: "INTEGER", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.7", Name: "entPhysicalName", Module: "ENTITY-MIB", Description: "Physical entity name", Syntax: "DisplayString", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.8", Name: "entPhysicalHardwareRev", Module: "ENTITY-MIB", Description: "Hardware revision", Syntax: "DisplayString", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.9", Name: "entPhysicalFirmwareRev", Module: "ENTITY-MIB", Description: "Firmware revision", Syntax: "DisplayString", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.10", Name: "entPhysicalSoftwareRev", Module: "ENTITY-MIB", Description: "Software revision", Syntax: "DisplayString", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.11", Name: "entPhysicalSerialNum", Module: "ENTITY-MIB", Description: "Serial number", Syntax: "DisplayString", Access: "read-write", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.12", Name: "entPhysicalMfgName", Module: "ENTITY-MIB", Description: "Manufacturer name", Syntax: "DisplayString", Access: "read-only", Category: "entity"},
		{OID: "1.3.6.1.2.1.47.1.1.1.1.13", Name: "entPhysicalModelName", Module: "ENTITY-MIB", Description: "Model name", Syntax: "DisplayString", Access: "read-only", Category: "entity"},

		// ═══ ENTITY-SENSOR-MIB ═══
		{OID: "1.3.6.1.2.1.99.1.1.1.1", Name: "entPhySensorType", Module: "ENTITY-SENSOR-MIB", Description: "Sensor type (8=celsius,12=truthvalue)", Syntax: "INTEGER", Access: "read-only", Category: "sensors"},
		{OID: "1.3.6.1.2.1.99.1.1.1.4", Name: "entPhySensorValue", Module: "ENTITY-SENSOR-MIB", Description: "Sensor current value", Syntax: "INTEGER", Access: "read-only", Category: "sensors"},
		{OID: "1.3.6.1.2.1.99.1.1.1.5", Name: "entPhySensorOperStatus", Module: "ENTITY-SENSOR-MIB", Description: "Sensor operational status (1=ok,2=unavailable,3=nonoperational)", Syntax: "INTEGER", Access: "read-only", Category: "sensors"},

		// ═══ HOST-RESOURCES-MIB ═══
		{OID: "1.3.6.1.2.1.25.1.1", Name: "hrSystemUptime", Module: "HOST-RESOURCES-MIB", Description: "Host uptime", Syntax: "TimeTicks", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.1.6", Name: "hrSystemProcesses", Module: "HOST-RESOURCES-MIB", Description: "Number of processes", Syntax: "Gauge32", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.2.2", Name: "hrMemorySize", Module: "HOST-RESOURCES-MIB", Description: "Total memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "host"},
		{OID: "1.3.6.1.2.1.25.2.3.1.2", Name: "hrStorageType", Module: "HOST-RESOURCES-MIB", Description: "Storage type", Syntax: "OBJECT IDENTIFIER", Access: "read-only", Category: "storage"},
		{OID: "1.3.6.1.2.1.25.2.3.1.3", Name: "hrStorageDescr", Module: "HOST-RESOURCES-MIB", Description: "Storage description", Syntax: "DisplayString", Access: "read-only", Category: "storage"},
		{OID: "1.3.6.1.2.1.25.2.3.1.4", Name: "hrStorageAllocationUnits", Module: "HOST-RESOURCES-MIB", Description: "Storage allocation unit (bytes)", Syntax: "INTEGER", Access: "read-only", Category: "storage"},
		{OID: "1.3.6.1.2.1.25.2.3.1.5", Name: "hrStorageSize", Module: "HOST-RESOURCES-MIB", Description: "Storage total size (units)", Syntax: "INTEGER", Access: "read-only", Category: "storage"},
		{OID: "1.3.6.1.2.1.25.2.3.1.6", Name: "hrStorageUsed", Module: "HOST-RESOURCES-MIB", Description: "Storage used space (units)", Syntax: "INTEGER", Access: "read-only", Category: "storage"},
		{OID: "1.3.6.1.2.1.25.3.3.1.2", Name: "hrProcessorLoad", Module: "HOST-RESOURCES-MIB", Description: "CPU load percentage", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},

		// ═══ UCD-SNMP-MIB (Linux) ═══
		{OID: "1.3.6.1.4.1.2021.4.3", Name: "memTotalSwap", Module: "UCD-SNMP-MIB", Description: "Total swap space (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.4", Name: "memAvailSwap", Module: "UCD-SNMP-MIB", Description: "Available swap (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.5", Name: "memTotalReal", Module: "UCD-SNMP-MIB", Description: "Total RAM (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.6", Name: "memAvailReal", Module: "UCD-SNMP-MIB", Description: "Available RAM (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.11", Name: "memTotalFree", Module: "UCD-SNMP-MIB", Description: "Total free memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.14", Name: "memBuffer", Module: "UCD-SNMP-MIB", Description: "Buffer memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.4.15", Name: "memCached", Module: "UCD-SNMP-MIB", Description: "Cached memory (KB)", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.10.1.3.1", Name: "laLoad1", Module: "UCD-SNMP-MIB", Description: "1-min load average", Syntax: "DisplayString", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.10.1.3.2", Name: "laLoad5", Module: "UCD-SNMP-MIB", Description: "5-min load average", Syntax: "DisplayString", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.10.1.3.3", Name: "laLoad15", Module: "UCD-SNMP-MIB", Description: "15-min load average", Syntax: "DisplayString", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.11.9", Name: "ssCpuUser", Module: "UCD-SNMP-MIB", Description: "CPU user time %", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.4.1.2021.11.10", Name: "ssCpuSystem", Module: "UCD-SNMP-MIB", Description: "CPU system time %", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},
		{OID: "1.3.6.1.2.1.4.1.2021.11.11", Name: "ssCpuIdle", Module: "UCD-SNMP-MIB", Description: "CPU idle time %", Syntax: "INTEGER", Access: "read-only", Category: "cpu_memory"},

		// ═══ SNMP Traps ═══
		{OID: "1.3.6.1.6.3.1.1.5.1", Name: "coldStart", Module: "SNMPv2-MIB", Description: "Device cold start (full power-on restart)", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.5.2", Name: "warmStart", Module: "SNMPv2-MIB", Description: "Device warm start (software restart)", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.5.3", Name: "linkDown", Module: "IF-MIB", Description: "Interface link down", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.5.4", Name: "linkUp", Module: "IF-MIB", Description: "Interface link up", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.5.5", Name: "authenticationFailure", Module: "SNMPv2-MIB", Description: "SNMP authentication failure", Syntax: "NOTIFICATION-TYPE", Category: "trap"},
		{OID: "1.3.6.1.6.3.1.1.4.1", Name: "snmpTrapOID", Module: "SNMPv2-MIB", Description: "Trap OID identifier", Syntax: "OBJECT IDENTIFIER", Category: "trap"},

		// ═══ POWER-ETHERNET-MIB (PoE) ═══
		{OID: "1.3.6.1.2.1.105.1.1.1.3", Name: "pethPsePortAdminEnable", Module: "POWER-ETHERNET-MIB", Description: "PoE port admin state (1=enabled,2=disabled)", Syntax: "INTEGER", Access: "read-write", Category: "poe"},
		{OID: "1.3.6.1.2.1.105.1.1.1.4", Name: "pethPsePortPowerPairsControlAbility", Module: "POWER-ETHERNET-MIB", Description: "PoE pair control ability", Syntax: "TruthValue", Access: "read-only", Category: "poe"},
		{OID: "1.3.6.1.2.1.105.1.1.1.6", Name: "pethPsePortDetectionStatus", Module: "POWER-ETHERNET-MIB", Description: "PoE detection status (1=disabled,2=searching,3=delivering,4=fault)", Syntax: "INTEGER", Access: "read-only", Category: "poe"},
		{OID: "1.3.6.1.2.1.105.1.3.1.1.2", Name: "pethMainPsePower", Module: "POWER-ETHERNET-MIB", Description: "Total PoE power available (watts)", Syntax: "Unsigned32", Access: "read-only", Category: "poe"},
		{OID: "1.3.6.1.2.1.105.1.3.1.1.4", Name: "pethMainPseConsumptionPower", Module: "POWER-ETHERNET-MIB", Description: "Current PoE power consumption (watts)", Syntax: "Unsigned32", Access: "read-only", Category: "poe"},

		// ═══ SNMP Engine ═══
		{OID: "1.3.6.1.6.3.10.2.1.1", Name: "snmpEngineID", Module: "SNMP-FRAMEWORK-MIB", Description: "SNMP engine ID", Syntax: "OCTET STRING", Access: "read-only", Category: "snmp_engine"},
		{OID: "1.3.6.1.6.3.10.2.1.3", Name: "snmpEngineTime", Module: "SNMP-FRAMEWORK-MIB", Description: "SNMP engine uptime (seconds)", Syntax: "INTEGER", Access: "read-only", Category: "snmp_engine"},

		// ═══ Eltex (MES2348B vendor-specific) ═══
		{OID: "1.3.6.1.4.1.35265.1.23.1.1.1", Name: "eltexSwVersion", Module: "ELTEX-MIB", Description: "Eltex software version", Syntax: "DisplayString", Access: "read-only", Category: "eltex"},
		{OID: "1.3.6.1.4.1.35265.1.23.1.2.1", Name: "eltexHwVersion", Module: "ELTEX-MIB", Description: "Eltex hardware version", Syntax: "DisplayString", Access: "read-only", Category: "eltex"},
		{OID: "1.3.6.1.4.1.35265.1.23.1.3.1", Name: "eltexSerialNumber", Module: "ELTEX-MIB", Description: "Eltex device serial number", Syntax: "DisplayString", Access: "read-only", Category: "eltex"},
		{OID: "1.3.6.1.4.1.89.53.15.1.9", Name: "rlPhdUnitEnvParamTempSensorValue", Module: "RADLAN-Physicaldescription-MIB", Description: "Eltex/Radlan temperature sensor", Syntax: "INTEGER", Access: "read-only", Category: "eltex"},
		{OID: "1.3.6.1.4.1.89.53.15.1.10", Name: "rlPhdUnitEnvParamFan1Status", Module: "RADLAN-Physicaldescription-MIB", Description: "Fan 1 status (1=normal,2=notFunctioning)", Syntax: "INTEGER", Access: "read-only", Category: "eltex"},
		{OID: "1.3.6.1.4.1.89.53.15.1.11", Name: "rlPhdUnitEnvParamFan2Status", Module: "RADLAN-Physicaldescription-MIB", Description: "Fan 2 status", Syntax: "INTEGER", Access: "read-only", Category: "eltex"},
	}
}

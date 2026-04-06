package discovery

// topology.go — L2/L3 Topology Map builder using LLDP and CDP neighbor data.
//
// Queries LLDP-MIB (IEEE 802.1AB) and CDP (Cisco) tables from registered
// devices to build a network topology graph showing device interconnections.

import (
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/rs/zerolog"
)

// ── Topology Types ───────────────────────────────────────────────────────────

// TopologyNode represents a device in the topology map.
type TopologyNode struct {
	ID         string `json:"id"`          // Unique node ID (usually IP)
	Label      string `json:"label"`       // Display name (sysName or IP)
	IP         string `json:"ip"`
	Vendor     string `json:"vendor"`
	DeviceType string `json:"device_type"` // router, switch, firewall, server
	Status     string `json:"status"`      // up, down, unknown
	Interfaces int    `json:"interfaces"`
}

// TopologyLink represents a connection between two nodes.
type TopologyLink struct {
	ID           string `json:"id"`
	Source       string `json:"source"`        // Source node ID
	Target       string `json:"target"`        // Target node ID
	SourcePort   string `json:"source_port"`   // Local port/interface name
	TargetPort   string `json:"target_port"`   // Remote port/interface name
	Protocol     string `json:"protocol"`      // "lldp" or "cdp"
	Speed        string `json:"speed,omitempty"`
}

// TopologyMap is the complete network graph.
type TopologyMap struct {
	Nodes       []TopologyNode `json:"nodes"`
	Links       []TopologyLink `json:"links"`
	GeneratedAt time.Time      `json:"generated_at"`
	ScanTime    string         `json:"scan_time"`
}

// ── LLDP OIDs (IEEE 802.1AB) ─────────────────────────────────────────────────

const (
	// lldpRemTable — Remote system information
	lldpRemChassisID   = "1.0.8802.1.1.2.1.4.1.1.5"  // ChassisIdSubtype → ChassisId
	lldpRemPortID      = "1.0.8802.1.1.2.1.4.1.1.7"  // PortIdSubtype → PortId
	lldpRemPortDesc    = "1.0.8802.1.1.2.1.4.1.1.8"  // Port description
	lldpRemSysName     = "1.0.8802.1.1.2.1.4.1.1.9"  // Remote system name
	lldpRemSysDesc     = "1.0.8802.1.1.2.1.4.1.1.10" // Remote system description
	lldpRemManAddrType = "1.0.8802.1.1.2.1.4.2.1.1"  // Management address type
	lldpRemManAddr     = "1.0.8802.1.1.2.1.4.2.1.2"  // Management address

	// lldpLocPortTable — Local port info
	lldpLocPortDesc = "1.0.8802.1.1.2.1.3.7.1.4" // Local port description
)

// ── CDP OIDs (Cisco Discovery Protocol) ──────────────────────────────────────

const (
	cdpCacheDeviceID   = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"  // Remote device ID
	cdpCacheDevicePort = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"  // Remote port
	cdpCachePlatform   = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"  // Remote platform
	cdpCacheAddress    = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"  // Remote IP address
)

// ── Topology Builder ─────────────────────────────────────────────────────────

// DeviceInfo holds minimal info needed for topology discovery.
type DeviceInfo struct {
	Name        string
	IP          string
	Port        int
	Community   string
	SNMPVersion string
	Status      string
	Vendor      string
	DeviceType  string
	SysName     string
	Interfaces  int
}

// TopologyBuilder constructs topology maps by querying LLDP/CDP on devices.
type TopologyBuilder struct {
	log     zerolog.Logger
	timeout time.Duration
}

// NewTopologyBuilder creates a new topology builder.
func NewTopologyBuilder(log zerolog.Logger) *TopologyBuilder {
	return &TopologyBuilder{
		log:     log.With().Str("component", "topology").Logger(),
		timeout: 5 * time.Second,
	}
}

// BuildTopology queries LLDP and CDP tables from all devices and builds a graph.
func (t *TopologyBuilder) BuildTopology(devices []DeviceInfo) *TopologyMap {
	start := time.Now()

	nodeMap := make(map[string]*TopologyNode)
	linkMap := make(map[string]*TopologyLink)

	// Add known devices as nodes
	for _, d := range devices {
		nodeMap[d.IP] = &TopologyNode{
			ID:         d.IP,
			Label:      d.SysName,
			IP:         d.IP,
			Vendor:     d.Vendor,
			DeviceType: d.DeviceType,
			Status:     d.Status,
			Interfaces: d.Interfaces,
		}
		if nodeMap[d.IP].Label == "" {
			nodeMap[d.IP].Label = d.Name
		}
	}

	// Query each device for LLDP/CDP neighbors
	for _, d := range devices {
		if d.Status != "up" || d.Community == "" {
			continue
		}

		neighbors := t.queryNeighbors(d)
		for _, n := range neighbors {
			// Add remote node if not already known
			if _, exists := nodeMap[n.remoteIP]; !exists && n.remoteIP != "" {
				nodeMap[n.remoteIP] = &TopologyNode{
					ID:         n.remoteIP,
					Label:      n.remoteName,
					IP:         n.remoteIP,
					Vendor:     detectVendor(n.remoteDescr),
					DeviceType: detectDeviceType(n.remoteDescr),
					Status:     "unknown",
				}
			}

			// Create link
			targetID := n.remoteIP
			if targetID == "" {
				targetID = n.remoteName
				if _, exists := nodeMap[targetID]; !exists {
					nodeMap[targetID] = &TopologyNode{
						ID:         targetID,
						Label:      n.remoteName,
						Vendor:     detectVendor(n.remoteDescr),
						DeviceType: detectDeviceType(n.remoteDescr),
						Status:     "unknown",
					}
				}
			}

			linkID := normalizeLinkID(d.IP, targetID)
			if _, exists := linkMap[linkID]; !exists {
				linkMap[linkID] = &TopologyLink{
					ID:         linkID,
					Source:      d.IP,
					Target:      targetID,
					SourcePort:  n.localPort,
					TargetPort:  n.remotePort,
					Protocol:    n.protocol,
				}
			}
		}
	}

	// Convert maps to slices
	nodes := make([]TopologyNode, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, *n)
	}
	links := make([]TopologyLink, 0, len(linkMap))
	for _, l := range linkMap {
		links = append(links, *l)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	t.log.Info().
		Int("nodes", len(nodes)).
		Int("links", len(links)).
		Str("elapsed", elapsed.String()).
		Msg("topology map built")

	return &TopologyMap{
		Nodes:       nodes,
		Links:       links,
		GeneratedAt: time.Now(),
		ScanTime:    elapsed.String(),
	}
}

// ── Neighbor query ──────────────────────────────────────────────────────────

type neighbor struct {
	remoteIP    string
	remoteName  string
	remoteDescr string
	remotePort  string
	localPort   string
	protocol    string
}

func (t *TopologyBuilder) queryNeighbors(d DeviceInfo) []neighbor {
	var neighbors []neighbor

	snmp := &gosnmp.GoSNMP{
		Target:    d.IP,
		Port:      uint16(d.Port),
		Community: d.Community,
		Timeout:   t.timeout,
		Retries:   1,
	}
	switch d.SNMPVersion {
	case "v1":
		snmp.Version = gosnmp.Version1
	default:
		snmp.Version = gosnmp.Version2c
	}

	if err := snmp.ConnectIPv4(); err != nil {
		t.log.Debug().Str("device", d.IP).Err(err).Msg("failed to connect for topology")
		return nil
	}
	defer snmp.Conn.Close()

	// Try LLDP first
	lldpNeighbors := t.queryLLDP(snmp, d.IP)
	neighbors = append(neighbors, lldpNeighbors...)

	// Try CDP (Cisco)
	cdpNeighbors := t.queryCDP(snmp, d.IP)
	neighbors = append(neighbors, cdpNeighbors...)

	return neighbors
}

func (t *TopologyBuilder) queryLLDP(snmp *gosnmp.GoSNMP, localIP string) []neighbor {
	var neighbors []neighbor

	// Walk lldpRemSysName
	results, err := snmp.BulkWalkAll(lldpRemSysName)
	if err != nil || len(results) == 0 {
		return nil
	}

	for _, pdu := range results {
		n := neighbor{
			protocol:   "lldp",
			remoteName: pduToString(pdu),
		}

		// Try to get remote port description
		idx := strings.TrimPrefix(pdu.Name, "."+lldpRemSysName+".")
		portResults, err := snmp.Get([]string{lldpRemPortDesc + "." + idx})
		if err == nil && len(portResults.Variables) > 0 {
			n.remotePort = pduToString(portResults.Variables[0])
		}

		// Try to get remote system description
		descResults, err := snmp.Get([]string{lldpRemSysDesc + "." + idx})
		if err == nil && len(descResults.Variables) > 0 {
			n.remoteDescr = pduToString(descResults.Variables[0])
		}

		neighbors = append(neighbors, n)
	}

	return neighbors
}

func (t *TopologyBuilder) queryCDP(snmp *gosnmp.GoSNMP, localIP string) []neighbor {
	var neighbors []neighbor

	results, err := snmp.BulkWalkAll(cdpCacheDeviceID)
	if err != nil || len(results) == 0 {
		return nil
	}

	for _, pdu := range results {
		n := neighbor{
			protocol:   "cdp",
			remoteName: pduToString(pdu),
		}

		idx := strings.TrimPrefix(pdu.Name, "."+cdpCacheDeviceID+".")

		// Get remote port
		portResults, err := snmp.Get([]string{cdpCacheDevicePort + "." + idx})
		if err == nil && len(portResults.Variables) > 0 {
			n.remotePort = pduToString(portResults.Variables[0])
		}

		// Get remote address (IP)
		addrResults, err := snmp.Get([]string{cdpCacheAddress + "." + idx})
		if err == nil && len(addrResults.Variables) > 0 {
			if bytes, ok := addrResults.Variables[0].Value.([]byte); ok && len(bytes) == 4 {
				n.remoteIP = fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
			}
		}

		neighbors = append(neighbors, n)
	}

	return neighbors
}

// normalizeLinkID creates a consistent link ID regardless of direction.
func normalizeLinkID(a, b string) string {
	if a < b {
		return a + "--" + b
	}
	return b + "--" + a
}

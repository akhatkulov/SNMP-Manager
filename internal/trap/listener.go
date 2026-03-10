package trap

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gosnmp/gosnmp"
	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/config"
	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/mib"
	"github.com/me262/snmp-manager/internal/pipeline"
)

// Listener receives SNMP traps and converts them into pipeline events.
type Listener struct {
	log      zerolog.Logger
	cfg      config.TrapReceiverConfig
	registry *device.Registry
	resolver *mib.Resolver
	pipe     *pipeline.Pipeline
	listener *gosnmp.TrapListener

	// Deduplication
	mu       sync.RWMutex
	seen     map[string]time.Time
	dedupTTL time.Duration

	// Metrics
	totalTraps   int64
	v1Traps      int64
	v2cTraps     int64
	v3Traps      int64
	unknownTraps int64
	droppedTraps int64
}

// NewListener creates a new SNMP trap listener.
func NewListener(log zerolog.Logger, cfg config.TrapReceiverConfig, registry *device.Registry, resolver *mib.Resolver, pipe *pipeline.Pipeline) *Listener {
	return &Listener{
		log:      log.With().Str("component", "trap-listener").Logger(),
		cfg:      cfg,
		registry: registry,
		resolver: resolver,
		pipe:     pipe,
		seen:     make(map[string]time.Time),
		dedupTTL: 30 * time.Second,
	}
}

// Run starts the trap listener. Blocks until context is cancelled.
func (l *Listener) Run(ctx context.Context) error {
	if !l.cfg.Enabled {
		l.log.Info().Msg("trap receiver is disabled")
		return nil
	}

	l.listener = gosnmp.NewTrapListener()
	l.listener.OnNewTrap = l.handleTrap
	l.listener.Params = gosnmp.Default
	l.listener.Params.Logger = gosnmp.NewLogger(&snmpLogger{log: l.log})

	// Configure SNMPv3 if users are defined
	if len(l.cfg.V3Users) > 0 {
		l.listener.Params.Version = gosnmp.Version3
		l.listener.Params.SecurityModel = gosnmp.UserSecurityModel
		l.listener.Params.MsgFlags = gosnmp.AuthPriv
		// Set the first user as the default (gosnmp handles multi-user via callback)
		user := l.cfg.V3Users[0]
		l.listener.Params.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 user.Username,
			AuthenticationProtocol:   parseAuthProtocol(user.AuthProtocol),
			AuthenticationPassphrase: user.AuthPassphrase,
			PrivacyProtocol:          parsePrivProtocol(user.PrivProtocol),
			PrivacyPassphrase:        user.PrivPassphrase,
		}
	}

	// Start deduplication cleanup goroutine
	go l.cleanupDedup(ctx)

	l.log.Info().Str("address", l.cfg.ListenAddress).Msg("starting trap listener")

	// Listen in a goroutine so we can handle context cancellation
	errCh := make(chan error, 1)
	go func() {
		errCh <- l.listener.Listen(l.cfg.ListenAddress)
	}()

	select {
	case <-ctx.Done():
		l.listener.Close()
		l.log.Info().
			Int64("total", l.totalTraps).
			Int64("v1", l.v1Traps).
			Int64("v2c", l.v2cTraps).
			Int64("v3", l.v3Traps).
			Int64("dropped", l.droppedTraps).
			Msg("trap listener stopped")
		return nil
	case err := <-errCh:
		return fmt.Errorf("trap listener error: %w", err)
	}
}

// handleTrap processes an incoming SNMP trap.
func (l *Listener) handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	l.mu.Lock()
	l.totalTraps++
	l.mu.Unlock()

	sourceIP := addr.IP.String()

	l.log.Info().
		Str("source", sourceIP).
		Int("variables", len(packet.Variables)).
		Str("version", versionString(packet.Version)).
		Str("community", packet.Community).
		Msg("📥 trap received")

	// Update per-version counters
	l.mu.Lock()
	switch packet.Version {
	case gosnmp.Version1:
		l.v1Traps++
	case gosnmp.Version2c:
		l.v2cTraps++
	case gosnmp.Version3:
		l.v3Traps++
	default:
		l.unknownTraps++
	}
	l.mu.Unlock()

	// Update device trap count if known
	if dev, ok := l.registry.GetByIP(sourceIP); ok {
		dev.IncrementTrapCount()
	}

	// Convert trap variables to events
	events := l.trapToEvents(packet, sourceIP)

	// Submit to pipeline
	for _, event := range events {
		if l.isDuplicate(event) {
			l.mu.Lock()
			l.droppedTraps++
			l.mu.Unlock()
			continue
		}
		l.pipe.Submit(event)
	}
}

// trapToEvents converts an SNMP trap packet into pipeline events.
func (l *Listener) trapToEvents(packet *gosnmp.SnmpPacket, sourceIP string) []*pipeline.SNMPEvent {
	var events []*pipeline.SNMPEvent

	// Build source info
	source := pipeline.SourceInfo{
		IP: sourceIP,
	}
	if dev, ok := l.registry.GetByIP(sourceIP); ok {
		source.Hostname = dev.SysName
		source.DeviceType = dev.DeviceType
		source.Vendor = dev.Vendor
		source.SysName = dev.SysName
		if loc, ok := dev.Tags["location"]; ok {
			source.Location = loc
		}
	}

	// Determine the trap OID (snmpTrapOID is in the varbinds for v2c/v3)
	trapOID := ""
	var variables []pipeline.Variable

	for _, v := range packet.Variables {
		oid := strings.TrimPrefix(v.Name, ".")

		// snmpTrapOID.0 = 1.3.6.1.6.3.1.1.4.1.0
		if oid == "1.3.6.1.6.3.1.1.4.1.0" {
			if v.Type == gosnmp.ObjectIdentifier {
				trapOID = strings.TrimPrefix(v.Value.(string), ".")
			}
			continue
		}

		// sysUpTime.0 = 1.3.6.1.2.1.1.3.0 (skip, it's metadata)
		if oid == "1.3.6.1.2.1.1.3.0" {
			continue
		}

		value, valueType := extractTrapValue(&v)
		variables = append(variables, pipeline.Variable{
			OID:       oid,
			Value:     value,
			ValueType: valueType,
		})
	}

	// For v1 traps, use the enterprise OID + generic/specific trap
	if packet.Version == gosnmp.Version1 && trapOID == "" {
		trapOID = strings.TrimPrefix(packet.Enterprise, ".")
	}

	// If no trap OID found, use the first variable's OID
	if trapOID == "" && len(packet.Variables) > 0 {
		trapOID = strings.TrimPrefix(packet.Variables[0].Name, ".")
	}

	event := &pipeline.SNMPEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		EventType: pipeline.EventTypeTrap,
		Source:    source,
		SNMP: pipeline.SNMPData{
			Version:     versionString(packet.Version),
			OID:         trapOID,
			RequestType: "trap",
			Variables:   variables,
		},
	}

	// Set primary value from variables if available
	if len(variables) > 0 {
		event.SNMP.Value = variables[0].Value
		event.SNMP.ValueType = variables[0].ValueType
		event.SNMP.ValueString = fmt.Sprintf("%v", variables[0].Value)
	}

	events = append(events, event)
	return events
}

// isDuplicate checks if an event is a duplicate (same source + OID within TTL).
func (l *Listener) isDuplicate(event *pipeline.SNMPEvent) bool {
	key := fmt.Sprintf("%s:%s", event.Source.IP, event.SNMP.OID)

	l.mu.Lock()
	defer l.mu.Unlock()

	if lastSeen, ok := l.seen[key]; ok {
		if time.Since(lastSeen) < l.dedupTTL {
			return true
		}
	}
	l.seen[key] = time.Now()
	return false
}

// cleanupDedup periodically removes expired dedup entries.
func (l *Listener) cleanupDedup(ctx context.Context) {
	ticker := time.NewTicker(l.dedupTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.mu.Lock()
			now := time.Now()
			for key, ts := range l.seen {
				if now.Sub(ts) > l.dedupTTL {
					delete(l.seen, key)
				}
			}
			l.mu.Unlock()
		}
	}
}

// Stats returns trap listener statistics.
func (l *Listener) Stats() TrapStats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return TrapStats{
		TotalTraps:   l.totalTraps,
		V1Traps:      l.v1Traps,
		V2cTraps:     l.v2cTraps,
		V3Traps:      l.v3Traps,
		UnknownTraps: l.unknownTraps,
		DroppedTraps: l.droppedTraps,
	}
}

// TrapStats holds trap listener metrics.
type TrapStats struct {
	TotalTraps   int64 `json:"total_traps"`
	V1Traps      int64 `json:"v1_traps"`
	V2cTraps     int64 `json:"v2c_traps"`
	V3Traps      int64 `json:"v3_traps"`
	UnknownTraps int64 `json:"unknown_traps"`
	DroppedTraps int64 `json:"dropped_traps"`
}

// extractTrapValue extracts the value from a trap variable binding.
func extractTrapValue(pdu *gosnmp.SnmpPDU) (any, string) {
	switch pdu.Type {
	case gosnmp.OctetString:
		return string(pdu.Value.([]byte)), "OctetString"
	case gosnmp.Integer:
		return pdu.Value.(int), "Integer"
	case gosnmp.Counter32:
		return pdu.Value.(uint), "Counter32"
	case gosnmp.Counter64:
		return pdu.Value.(uint64), "Counter64"
	case gosnmp.Gauge32:
		return pdu.Value.(uint), "Gauge32"
	case gosnmp.TimeTicks:
		return pdu.Value, "TimeTicks"
	case gosnmp.IPAddress:
		return pdu.Value.(string), "IPAddress"
	case gosnmp.ObjectIdentifier:
		return pdu.Value.(string), "ObjectIdentifier"
	default:
		return fmt.Sprintf("%v", pdu.Value), "Unknown"
	}
}

// versionString converts gosnmp.SnmpVersion to a human-readable string.
func versionString(v gosnmp.SnmpVersion) string {
	switch v {
	case gosnmp.Version1:
		return "v1"
	case gosnmp.Version2c:
		return "v2c"
	case gosnmp.Version3:
		return "v3"
	default:
		return "unknown"
	}
}

// parseAuthProtocol converts a string to gosnmp auth protocol.
func parseAuthProtocol(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(s) {
	case "MD5":
		return gosnmp.MD5
	case "SHA", "SHA1":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.SHA256
	}
}

// parsePrivProtocol converts a string to gosnmp privacy protocol.
func parsePrivProtocol(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(s) {
	case "DES":
		return gosnmp.DES
	case "AES", "AES128":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.AES256
	}
}

// snmpLogger adapts zerolog to gosnmp's logger interface.
type snmpLogger struct {
	log zerolog.Logger
}

func (s *snmpLogger) Print(v ...interface{}) {
	s.log.Debug().Msgf("%v", v...)
}

func (s *snmpLogger) Printf(format string, v ...interface{}) {
	s.log.Debug().Msgf(format, v...)
}

package poller

import (
	"context"
	"fmt"
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

// Poller manages scheduled SNMP polling of devices.
type Poller struct {
	log      zerolog.Logger
	cfg      config.PollerConfig
	registry *device.Registry
	resolver *mib.Resolver
	pipe     *pipeline.Pipeline

	// Worker pool
	jobCh    chan *pollJob
	wg       sync.WaitGroup

	// Metrics
	mu          sync.RWMutex
	totalPolls  int64
	totalErrors int64
}

type pollJob struct {
	device *device.Device
}

// New creates a new SNMP Poller.
func New(log zerolog.Logger, cfg config.PollerConfig, registry *device.Registry, resolver *mib.Resolver, pipe *pipeline.Pipeline) *Poller {
	return &Poller{
		log:      log.With().Str("component", "poller").Logger(),
		cfg:      cfg,
		registry: registry,
		resolver: resolver,
		pipe:     pipe,
		jobCh:    make(chan *pollJob, cfg.Workers*2),
	}
}

// Run starts the polling scheduler and worker pool. Blocks until context is cancelled.
func (p *Poller) Run(ctx context.Context) {
	// Start worker pool
	for i := 0; i < p.cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}

	p.log.Info().
		Int("workers", p.cfg.Workers).
		Dur("default_interval", p.cfg.DefaultInterval).
		Msg("poller started")

	// Scheduling loop
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Track last poll time per device
	lastPoll := make(map[string]time.Time)

	for {
		select {
		case <-ctx.Done():
			p.log.Info().Msg("poller shutting down...")
			close(p.jobCh)
			p.wg.Wait()
			p.log.Info().
				Int64("total_polls", p.totalPolls).
				Int64("total_errors", p.totalErrors).
				Msg("poller stopped")
			return

		case <-ticker.C:
			devices := p.registry.ListEnabled()
			now := time.Now()

			for _, dev := range devices {
				last, ok := lastPoll[dev.Name]
				if !ok || now.Sub(last) >= dev.PollInterval {
					select {
					case p.jobCh <- &pollJob{device: dev}:
						lastPoll[dev.Name] = now
					default:
						p.log.Warn().Str("device", dev.Name).Msg("poll queue full, skipping")
					}
				}
			}
		}
	}
}

// PollDevice performs an immediate poll of a specific device.
func (p *Poller) PollDevice(ctx context.Context, dev *device.Device) ([]*pipeline.SNMPEvent, error) {
	return p.doPoll(ctx, dev)
}

// worker processes polling jobs from the job channel.
func (p *Poller) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	for job := range p.jobCh {
		select {
		case <-ctx.Done():
			return
		default:
		}

		events, err := p.doPoll(ctx, job.device)
		if err != nil {
			p.mu.Lock()
			p.totalErrors++
			p.mu.Unlock()
			continue
		}

		// Submit events to pipeline
		for _, event := range events {
			p.pipe.Submit(event)
		}

		p.mu.Lock()
		p.totalPolls++
		p.mu.Unlock()
	}
}

// doPoll performs the actual SNMP poll on a device.
func (p *Poller) doPoll(ctx context.Context, dev *device.Device) ([]*pipeline.SNMPEvent, error) {
	start := time.Now()

	snmpClient, err := p.createSNMPClient(dev)
	if err != nil {
		dev.UpdateStatus(device.StatusError, 0, err)
		p.log.Error().Err(err).Str("device", dev.Name).Msg("failed to create SNMP client")
		return nil, err
	}

	if err := snmpClient.ConnectIPv4(); err != nil {
		dev.UpdateStatus(device.StatusDown, time.Since(start), err)
		p.log.Error().Err(err).Str("device", dev.Name).Str("ip", dev.IP).Msg("SNMP connect failed")
		return nil, fmt.Errorf("connect to %s: %w", dev.IP, err)
	}
	defer snmpClient.Conn.Close()

	// Collect OIDs based on configured groups
	oids := p.getOIDsForDevice(dev)
	if len(oids) == 0 {
		// Default: poll system info
		oids = p.resolver.GetOIDsForGroup("system")
	}

	var events []*pipeline.SNMPEvent

	// Poll in batches
	for i := 0; i < len(oids); i += p.cfg.MaxOIDsPerRequest {
		end := i + p.cfg.MaxOIDsPerRequest
		if end > len(oids) {
			end = len(oids)
		}
		batch := oids[i:end]

		// Prepend dots for gosnmp
		dotOids := make([]string, len(batch))
		for j, oid := range batch {
			if !strings.HasPrefix(oid, ".") {
				dotOids[j] = "." + oid
			} else {
				dotOids[j] = oid
			}
		}

		result, err := snmpClient.Get(dotOids)
		if err != nil {
			p.log.Warn().Err(err).Str("device", dev.Name).Int("batch", i/p.cfg.MaxOIDsPerRequest).Msg("SNMP GET failed")
			continue
		}

		for _, variable := range result.Variables {
			if variable.Type == gosnmp.NoSuchObject || variable.Type == gosnmp.NoSuchInstance {
				continue
			}

			event := p.variableToEvent(dev, &variable)
			events = append(events, event)
		}
	}

	// Also try to get system info to update device metadata
	p.updateDeviceInfo(snmpClient, dev)

	latency := time.Since(start)
	dev.UpdateStatus(device.StatusUp, latency, nil)

	p.log.Debug().
		Str("device", dev.Name).
		Int("events", len(events)).
		Dur("latency", latency).
		Msg("poll completed")

	return events, nil
}

// createSNMPClient creates a gosnmp client for the given device.
func (p *Poller) createSNMPClient(dev *device.Device) (*gosnmp.GoSNMP, error) {
	client := &gosnmp.GoSNMP{
		Target:    dev.IP,
		Port:      uint16(dev.Port),
		Timeout:   p.cfg.Timeout,
		Retries:   p.cfg.Retries,
		MaxOids:   p.cfg.MaxOIDsPerRequest,
	}

	switch strings.ToLower(dev.SNMPVersion) {
	case "v1":
		client.Version = gosnmp.Version1
		client.Community = dev.Community
	case "v2c":
		client.Version = gosnmp.Version2c
		client.Community = dev.Community
	case "v3":
		client.Version = gosnmp.Version3
		if dev.Credentials == nil {
			return nil, fmt.Errorf("device %s: SNMPv3 requires credentials", dev.Name)
		}
		client.SecurityModel = gosnmp.UserSecurityModel
		client.MsgFlags = gosnmp.AuthPriv
		client.ContextName = dev.Credentials.ContextName
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 dev.Credentials.Username,
			AuthenticationProtocol:   parseAuthProtocol(dev.Credentials.AuthProtocol),
			AuthenticationPassphrase: dev.Credentials.AuthPassphrase,
			PrivacyProtocol:          parsePrivProtocol(dev.Credentials.PrivProtocol),
			PrivacyPassphrase:        dev.Credentials.PrivPassphrase,
		}
	default:
		return nil, fmt.Errorf("unsupported SNMP version: %s", dev.SNMPVersion)
	}

	return client, nil
}

// variableToEvent converts an SNMP variable binding to a pipeline event.
func (p *Poller) variableToEvent(dev *device.Device, v *gosnmp.SnmpPDU) *pipeline.SNMPEvent {
	value, valueType := extractValue(v)

	event := &pipeline.SNMPEvent{
		ID:        uuid.New().String(),
		Timestamp: time.Now(),
		EventType: pipeline.EventTypePoll,
		Source: pipeline.SourceInfo{
			IP:         dev.IP,
			Port:       dev.Port,
			Hostname:   dev.SysName,
			DeviceType: dev.DeviceType,
			Vendor:     dev.Vendor,
		},
		SNMP: pipeline.SNMPData{
			Version:     dev.SNMPVersion,
			OID:         strings.TrimPrefix(v.Name, "."),
			Value:       value,
			ValueType:   valueType,
			RequestType: "get",
		},
	}

	// Copy tags from device
	for k, v := range dev.Tags {
		if event.Source.Location == "" && k == "location" {
			event.Source.Location = v
		}
	}

	return event
}

// updateDeviceInfo fetches system information to update device metadata.
func (p *Poller) updateDeviceInfo(client *gosnmp.GoSNMP, dev *device.Device) {
	sysOIDs := []string{
		".1.3.6.1.2.1.1.1.0", // sysDescr
		".1.3.6.1.2.1.1.3.0", // sysUpTime
		".1.3.6.1.2.1.1.5.0", // sysName
	}

	result, err := client.Get(sysOIDs)
	if err != nil {
		return
	}

	var descr, name, uptime string
	for _, v := range result.Variables {
		switch v.Name {
		case ".1.3.6.1.2.1.1.1.0":
			descr = fmt.Sprintf("%v", extractValueRaw(&v))
		case ".1.3.6.1.2.1.1.5.0":
			name = fmt.Sprintf("%v", extractValueRaw(&v))
		case ".1.3.6.1.2.1.1.3.0":
			uptime = fmt.Sprintf("%v", extractValueRaw(&v))
		}
	}

	if descr != "" || name != "" {
		dev.SetSysInfo(descr, name, uptime)
	}
}

// getOIDsForDevice returns the OIDs to poll based on device config.
func (p *Poller) getOIDsForDevice(dev *device.Device) []string {
	var oids []string
	for _, group := range dev.OIDGroups {
		groupOIDs := p.resolver.GetOIDsForGroup(group)
		oids = append(oids, groupOIDs...)
	}
	return oids
}

// extractValue converts a gosnmp PDU value to a Go value and type string.
func extractValue(pdu *gosnmp.SnmpPDU) (any, string) {
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
		return pdu.Value.(uint32), "TimeTicks"
	case gosnmp.IPAddress:
		return pdu.Value.(string), "IPAddress"
	case gosnmp.ObjectIdentifier:
		return pdu.Value.(string), "ObjectIdentifier"
	case gosnmp.Opaque:
		return pdu.Value, "Opaque"
	default:
		return fmt.Sprintf("%v", pdu.Value), "Unknown"
	}
}

// extractValueRaw returns the raw value as an interface.
func extractValueRaw(pdu *gosnmp.SnmpPDU) any {
	if pdu.Type == gosnmp.OctetString {
		return string(pdu.Value.([]byte))
	}
	return pdu.Value
}

// Stats returns poller statistics.
func (p *Poller) Stats() PollerStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return PollerStats{
		TotalPolls:  p.totalPolls,
		TotalErrors: p.totalErrors,
		QueueLen:    len(p.jobCh),
		QueueCap:    cap(p.jobCh),
		Workers:     p.cfg.Workers,
	}
}

// PollerStats holds poller performance metrics.
type PollerStats struct {
	TotalPolls  int64 `json:"total_polls"`
	TotalErrors int64 `json:"total_errors"`
	QueueLen    int   `json:"queue_len"`
	QueueCap    int   `json:"queue_cap"`
	Workers     int   `json:"workers"`
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
	case "AES192C":
		return gosnmp.AES192C
	case "AES256C":
		return gosnmp.AES256C
	default:
		return gosnmp.AES256
	}
}

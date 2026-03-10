package output

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/formatter"
	"github.com/me262/snmp-manager/internal/pipeline"
)

// SyslogOutput forwards formatted events to a syslog server (SIEM).
type SyslogOutput struct {
	log      zerolog.Logger
	address  string
	protocol string // "udp", "tcp"
	format   string // "cef", "json", "syslog", "leef"
	conn     net.Conn

	// Formatters
	cefFmt    *formatter.CEFFormatter
	jsonFmt   *formatter.JSONFormatter
	syslogFmt *formatter.SyslogFormatter
	leefFmt   *formatter.LEEFFormatter

	mu        sync.Mutex
	sent      int64
	errors    int64
	reconnects int64
}

// NewSyslogOutput creates a new syslog output.
func NewSyslogOutput(log zerolog.Logger, address, protocol, format string) *SyslogOutput {
	return &SyslogOutput{
		log:       log.With().Str("component", "output-syslog").Logger(),
		address:   address,
		protocol:  protocol,
		format:    format,
		cefFmt:    formatter.NewCEFFormatter(),
		jsonFmt:   formatter.NewJSONFormatter(false),
		syslogFmt: formatter.NewSyslogFormatter(),
		leefFmt:   formatter.NewLEEFFormatter(),
	}
}

// Name returns the output name.
func (s *SyslogOutput) Name() string {
	return fmt.Sprintf("syslog-%s-%s", s.protocol, s.address)
}

// Write formats and sends an event to the syslog server.
func (s *SyslogOutput) Write(ctx context.Context, event *pipeline.SNMPEvent) error {
	// Format the event
	formatted, err := s.formatEvent(event)
	if err != nil {
		return fmt.Errorf("format event: %w", err)
	}

	// Add newline
	message := formatted + "\n"

	// Send with retry
	for attempt := 0; attempt < 3; attempt++ {
		if err := s.send(message); err != nil {
			s.log.Warn().Err(err).Int("attempt", attempt+1).Msg("send failed, reconnecting")
			s.reconnect()
			continue
		}

		s.mu.Lock()
		s.sent++
		s.mu.Unlock()
		return nil
	}

	s.mu.Lock()
	s.errors++
	s.mu.Unlock()
	return fmt.Errorf("failed to send after 3 attempts to %s", s.address)
}

// Close closes the syslog connection.
func (s *SyslogOutput) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		s.log.Info().
			Int64("sent", s.sent).
			Int64("errors", s.errors).
			Msg("closing syslog output")
		return s.conn.Close()
	}
	return nil
}

func (s *SyslogOutput) formatEvent(event *pipeline.SNMPEvent) (string, error) {
	switch s.format {
	case "cef":
		return s.cefFmt.Format(event)
	case "json":
		return s.jsonFmt.Format(event)
	case "syslog":
		return s.syslogFmt.Format(event)
	case "leef":
		return s.leefFmt.Format(event)
	default:
		return s.jsonFmt.Format(event)
	}
}

func (s *SyslogOutput) send(message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		if err := s.connect(); err != nil {
			return err
		}
	}

	s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.conn.Write([]byte(message))
	if err != nil {
		s.conn = nil // Force reconnection
		return err
	}
	return nil
}

func (s *SyslogOutput) connect() error {
	conn, err := net.DialTimeout(s.protocol, s.address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to %s://%s: %w", s.protocol, s.address, err)
	}
	s.conn = conn
	s.log.Info().Str("address", s.address).Str("protocol", s.protocol).Msg("connected to syslog server")
	return nil
}

func (s *SyslogOutput) reconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.reconnects++

	if err := s.connect(); err != nil {
		s.log.Error().Err(err).Msg("reconnect failed")
	}
}

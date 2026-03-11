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

// TCPOutput sends JSON events over a persistent TCP connection (for Logstash TCP input).
type TCPOutput struct {
	log      zerolog.Logger
	address  string
	conn     net.Conn
	jsonFmt  *formatter.JSONFormatter

	mu         sync.Mutex
	sent       int64
	errors     int64
	reconnects int64
}

// NewTCPOutput creates a new TCP output (ideal for Logstash tcp input plugin).
func NewTCPOutput(log zerolog.Logger, address string) *TCPOutput {
	return &TCPOutput{
		log:     log.With().Str("component", "output-tcp").Logger(),
		address: address,
		jsonFmt: formatter.NewJSONFormatter(false),
	}
}

// Name returns the output name.
func (t *TCPOutput) Name() string {
	return fmt.Sprintf("tcp-%s", t.address)
}

// Write sends an event over TCP as a JSON line.
func (t *TCPOutput) Write(ctx context.Context, event *pipeline.SNMPEvent) error {
	data, err := t.jsonFmt.Format(event)
	if err != nil {
		return fmt.Errorf("format event: %w", err)
	}

	message := data + "\n"

	for attempt := 0; attempt < 3; attempt++ {
		if err := t.send(message); err != nil {
			t.log.Warn().Err(err).Int("attempt", attempt+1).Msg("tcp send failed, reconnecting")
			t.reconnect()
			continue
		}

		t.mu.Lock()
		t.sent++
		t.mu.Unlock()
		return nil
	}

	t.mu.Lock()
	t.errors++
	t.mu.Unlock()
	return fmt.Errorf("failed to send after 3 attempts to %s", t.address)
}

// Close closes the TCP connection.
func (t *TCPOutput) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		t.log.Info().
			Int64("sent", t.sent).
			Int64("errors", t.errors).
			Msg("closing tcp output")
		return t.conn.Close()
	}
	return nil
}

func (t *TCPOutput) send(message string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		if err := t.connect(); err != nil {
			return err
		}
	}

	t.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := t.conn.Write([]byte(message))
	if err != nil {
		t.conn = nil
		return err
	}
	return nil
}

func (t *TCPOutput) connect() error {
	conn, err := net.DialTimeout("tcp", t.address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to tcp://%s: %w", t.address, err)
	}
	t.conn = conn
	t.log.Info().Str("address", t.address).Msg("connected to tcp endpoint")
	return nil
}

func (t *TCPOutput) reconnect() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.reconnects++

	if err := t.connect(); err != nil {
		t.log.Error().Err(err).Msg("tcp reconnect failed")
	}
}

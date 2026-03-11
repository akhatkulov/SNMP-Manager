package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/formatter"
	"github.com/me262/snmp-manager/internal/pipeline"
)

// HTTPOutput sends events via HTTP POST to Logstash, Elasticsearch, or any HTTP endpoint.
type HTTPOutput struct {
	log     zerolog.Logger
	url     string
	headers map[string]string
	client  *http.Client
	jsonFmt *formatter.JSONFormatter

	mu     sync.Mutex
	sent   int64
	errors int64
}

// NewHTTPOutput creates a new HTTP output for Logstash/Elasticsearch/webhooks.
func NewHTTPOutput(log zerolog.Logger, url string, headers map[string]string, tlsSkipVerify bool) *HTTPOutput {
	transport := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		MaxConnsPerHost:     5,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: tlsSkipVerify},
	}

	return &HTTPOutput{
		log:     log.With().Str("component", "output-http").Logger(),
		url:     url,
		headers: headers,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		jsonFmt: formatter.NewJSONFormatter(false),
	}
}

// Name returns the output name.
func (h *HTTPOutput) Name() string {
	return fmt.Sprintf("http-%s", h.url)
}

// Write sends an event via HTTP POST.
func (h *HTTPOutput) Write(ctx context.Context, event *pipeline.SNMPEvent) error {
	data, err := h.jsonFmt.Format(event)
	if err != nil {
		return fmt.Errorf("format event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", h.url, bytes.NewBufferString(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.mu.Lock()
		h.errors++
		h.mu.Unlock()
		return fmt.Errorf("http post to %s: %w", h.url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		h.mu.Lock()
		h.errors++
		h.mu.Unlock()
		return fmt.Errorf("http %d from %s", resp.StatusCode, h.url)
	}

	h.mu.Lock()
	h.sent++
	h.mu.Unlock()
	return nil
}

// Close cleans up the HTTP client.
func (h *HTTPOutput) Close() error {
	h.log.Info().
		Int64("sent", h.sent).
		Int64("errors", h.errors).
		Msg("closing http output")
	h.client.CloseIdleConnections()
	return nil
}

// ElasticsearchOutput sends events directly to Elasticsearch.
type ElasticsearchOutput struct {
	log       zerolog.Logger
	addresses []string
	index     string
	username  string
	password  string
	client    *http.Client
	jsonFmt   *formatter.JSONFormatter

	mu       sync.Mutex
	sent     int64
	errors   int64
	addrIdx  int // round-robin index
}

// NewElasticsearchOutput creates a new Elasticsearch output.
func NewElasticsearchOutput(log zerolog.Logger, addresses []string, index, username, password string, tlsSkipVerify bool) *ElasticsearchOutput {
	if len(addresses) == 0 {
		addresses = []string{"http://localhost:9200"}
	}
	if index == "" {
		index = "snmp-events"
	}

	transport := &http.Transport{
		MaxIdleConns:        20,
		IdleConnTimeout:     30 * time.Second,
		MaxConnsPerHost:     10,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: tlsSkipVerify},
	}

	return &ElasticsearchOutput{
		log:       log.With().Str("component", "output-elasticsearch").Logger(),
		addresses: addresses,
		index:     index,
		username:  username,
		password:  password,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		jsonFmt: formatter.NewJSONFormatter(false),
	}
}

// Name returns the output name.
func (e *ElasticsearchOutput) Name() string {
	return fmt.Sprintf("elasticsearch-%s/%s", e.addresses[0], e.index)
}

// Write indexes an event into Elasticsearch.
func (e *ElasticsearchOutput) Write(ctx context.Context, event *pipeline.SNMPEvent) error {
	data, err := e.jsonFmt.Format(event)
	if err != nil {
		return fmt.Errorf("format event: %w", err)
	}

	// Build index name with date suffix: snmp-events-2026.03.11
	indexName := fmt.Sprintf("%s-%s", e.index, time.Now().Format("2006.01.02"))

	// Round-robin across addresses
	e.mu.Lock()
	addr := e.addresses[e.addrIdx%len(e.addresses)]
	e.addrIdx++
	e.mu.Unlock()

	url := fmt.Sprintf("%s/%s/_doc", addr, indexName)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if e.username != "" {
		req.SetBasicAuth(e.username, e.password)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		e.mu.Lock()
		e.errors++
		e.mu.Unlock()
		return fmt.Errorf("elasticsearch post: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		e.mu.Lock()
		e.errors++
		e.mu.Unlock()
		return fmt.Errorf("elasticsearch %d from %s", resp.StatusCode, url)
	}

	e.mu.Lock()
	e.sent++
	e.mu.Unlock()
	return nil
}

// Close cleans up the Elasticsearch client.
func (e *ElasticsearchOutput) Close() error {
	e.log.Info().
		Int64("sent", e.sent).
		Int64("errors", e.errors).
		Str("index", e.index).
		Msg("closing elasticsearch output")
	e.client.CloseIdleConnections()
	return nil
}

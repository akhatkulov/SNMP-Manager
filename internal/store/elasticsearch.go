package store

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// ElasticsearchStore queries events stored in Elasticsearch.
type ElasticsearchStore struct {
	log       zerolog.Logger
	addresses []string
	index     string
	username  string
	password  string
	client    *http.Client
}

// NewElasticsearchStore creates a queryable ES store.
func NewElasticsearchStore(log zerolog.Logger, addresses []string, index, username, password string, tlsSkipVerify bool) *ElasticsearchStore {
	if len(addresses) == 0 {
		addresses = []string{"http://localhost:9200"}
	}
	if index == "" {
		index = "snmp-events"
	}
	return &ElasticsearchStore{
		log:       log.With().Str("component", "es-store").Logger(),
		addresses: addresses,
		index:     index,
		username:  username,
		password:  password,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsSkipVerify},
			},
		},
	}
}

// SearchResult holds search response.
type SearchResult struct {
	Total  int64                    `json:"total"`
	Events []map[string]interface{} `json:"events"`
	Took   int                      `json:"took_ms"`
}

// SearchParams holds search criteria.
type SearchParams struct {
	Query     string `json:"query"`
	Severity  string `json:"severity"`
	DeviceIP  string `json:"device_ip"`
	EventType string `json:"event_type"`
	From      int    `json:"from"`
	Size      int    `json:"size"`
	TimeFrom  string `json:"time_from"` // ISO8601
	TimeTo    string `json:"time_to"`
	SortField string `json:"sort_field"`
	SortOrder string `json:"sort_order"`
}

// Search queries Elasticsearch for events.
func (s *ElasticsearchStore) Search(ctx context.Context, params SearchParams) (*SearchResult, error) {
	if params.Size <= 0 || params.Size > 500 {
		params.Size = 50
	}
	if params.SortField == "" {
		params.SortField = "timestamp"
	}
	if params.SortOrder == "" {
		params.SortOrder = "desc"
	}

	// Build ES query
	must := []map[string]interface{}{}

	if params.Query != "" {
		must = append(must, map[string]interface{}{
			"multi_match": map[string]interface{}{
				"query":  params.Query,
				"fields": []string{"device_name", "device_ip", "oid", "oid_name", "value", "event_type"},
				"type":   "best_fields",
			},
		})
	}
	if params.DeviceIP != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"device_ip": params.DeviceIP},
		})
	}
	if params.Severity != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"severity": params.Severity},
		})
	}
	if params.EventType != "" {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{"event_type": params.EventType},
		})
	}

	// Time range
	timeRange := map[string]interface{}{}
	if params.TimeFrom != "" {
		timeRange["gte"] = params.TimeFrom
	}
	if params.TimeTo != "" {
		timeRange["lte"] = params.TimeTo
	}
	if len(timeRange) > 0 {
		must = append(must, map[string]interface{}{
			"range": map[string]interface{}{"timestamp": timeRange},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{"must": must},
		},
		"sort": []map[string]interface{}{
			{params.SortField: map[string]string{"order": params.SortOrder}},
		},
		"from": params.From,
		"size": params.Size,
	}

	if len(must) == 0 {
		query["query"] = map[string]interface{}{"match_all": map[string]interface{}{}}
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	// Use index pattern with wildcard
	indexPattern := fmt.Sprintf("%s-*", s.index)
	url := fmt.Sprintf("%s/%s/_search", s.addresses[0], indexPattern)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("elasticsearch search: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("elasticsearch %d: %s", resp.StatusCode, string(respBody[:min(200, len(respBody))]))
	}

	var esResp struct {
		Took int `json:"took"`
		Hits struct {
			Total struct {
				Value int64 `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source map[string]interface{} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.Unmarshal(respBody, &esResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	events := make([]map[string]interface{}, 0, len(esResp.Hits.Hits))
	for _, hit := range esResp.Hits.Hits {
		events = append(events, hit.Source)
	}

	return &SearchResult{
		Total:  esResp.Hits.Total.Value,
		Events: events,
		Took:   esResp.Took,
	}, nil
}

// EventStats returns aggregated event statistics.
func (s *ElasticsearchStore) EventStats(ctx context.Context) (map[string]interface{}, error) {
	query := map[string]interface{}{
		"size": 0,
		"aggs": map[string]interface{}{
			"by_type": map[string]interface{}{
				"terms": map[string]interface{}{"field": "event_type", "size": 10},
			},
			"by_severity": map[string]interface{}{
				"terms": map[string]interface{}{"field": "severity", "size": 10},
			},
			"by_device": map[string]interface{}{
				"terms": map[string]interface{}{"field": "device_ip", "size": 50},
			},
			"events_over_time": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":             "timestamp",
					"fixed_interval":    "1h",
					"min_doc_count":     0,
					"extended_bounds": map[string]interface{}{
						"min": "now-24h",
						"max": "now",
					},
				},
			},
		},
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{"gte": "now-24h"},
			},
		},
	}

	body, _ := json.Marshal(query)
	indexPattern := fmt.Sprintf("%s-*", s.index)
	url := fmt.Sprintf("%s/%s/_search", s.addresses[0], indexPattern)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("elasticsearch %d: %s", resp.StatusCode, string(respBody[:min(200, len(respBody))]))
	}

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)
	return result, nil
}

// Healthy checks if Elasticsearch is reachable.
func (s *ElasticsearchStore) Healthy(ctx context.Context) bool {
	url := fmt.Sprintf("%s/_cluster/health", s.addresses[0])
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode < 400
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// IndicesInfo returns info about SNMP event indices.
func (s *ElasticsearchStore) IndicesInfo(ctx context.Context) ([]map[string]interface{}, error) {
	indexPattern := fmt.Sprintf("%s-*", s.index)
	url := fmt.Sprintf("%s/_cat/indices/%s?format=json&h=index,docs.count,store.size,creation.date.string", s.addresses[0], indexPattern)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("elasticsearch %d", resp.StatusCode)
	}

	var indices []map[string]interface{}
	json.Unmarshal(body, &indices)
	return indices, nil
}

// TimeSeriesPoint for chart data.
type TimeSeriesPoint struct {
	Timestamp string `json:"timestamp"`
	Count     int64  `json:"count"`
}

// GetTimeSeries returns event counts over time for charts.
func (s *ElasticsearchStore) GetTimeSeries(ctx context.Context, interval string, hours int) ([]TimeSeriesPoint, error) {
	if interval == "" {
		interval = "10m"
	}
	if hours <= 0 {
		hours = 6
	}

	query := map[string]interface{}{
		"size": 0,
		"aggs": map[string]interface{}{
			"over_time": map[string]interface{}{
				"date_histogram": map[string]interface{}{
					"field":          "timestamp",
					"fixed_interval": interval,
					"min_doc_count":  0,
					"extended_bounds": map[string]interface{}{
						"min": fmt.Sprintf("now-%dh", hours),
						"max": "now",
					},
				},
			},
		},
		"query": map[string]interface{}{
			"range": map[string]interface{}{
				"timestamp": map[string]interface{}{"gte": fmt.Sprintf("now-%dh", hours)},
			},
		},
	}

	body, _ := json.Marshal(query)
	indexPattern := fmt.Sprintf("%s-*", s.index)
	url := fmt.Sprintf("%s/%s/_search", s.addresses[0], indexPattern)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.username != "" {
		req.SetBasicAuth(s.username, s.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("elasticsearch %d", resp.StatusCode)
	}

	var esResp struct {
		Aggregations struct {
			OverTime struct {
				Buckets []struct {
					KeyAsString string `json:"key_as_string"`
					DocCount    int64  `json:"doc_count"`
				} `json:"buckets"`
			} `json:"over_time"`
		} `json:"aggregations"`
	}
	json.Unmarshal(respBody, &esResp)

	points := make([]TimeSeriesPoint, 0, len(esResp.Aggregations.OverTime.Buckets))
	for _, b := range esResp.Aggregations.OverTime.Buckets {
		ts := b.KeyAsString
		// Shorten timestamp for display
		if len(ts) > 16 {
			ts = ts[:16]
		}
		points = append(points, TimeSeriesPoint{
			Timestamp: ts,
			Count:     b.DocCount,
		})
	}
	return points, nil
}

// === In-memory stats history (for charts when ES not available) ===

// StatsSnapshot holds a point-in-time stats snapshot.
type StatsSnapshot struct {
	Timestamp  time.Time `json:"timestamp"`
	EventsIn   int64     `json:"events_in"`
	EventsOut  int64     `json:"events_out"`
	Goroutines int       `json:"goroutines"`
	MemoryMB   float64   `json:"memory_mb"`
	DevicesUp  int       `json:"devices_up"`
	DevicesErr int       `json:"devices_err"`
}

// StatsHistory is a ring buffer for stats snapshots.
type StatsHistory struct {
	points []StatsSnapshot
	cap    int
	pos    int
	count  int
}

// NewStatsHistory creates a ring buffer with given capacity.
func NewStatsHistory(capacity int) *StatsHistory {
	return &StatsHistory{
		points: make([]StatsSnapshot, capacity),
		cap:    capacity,
	}
}

// Push adds a new snapshot.
func (h *StatsHistory) Push(s StatsSnapshot) {
	h.points[h.pos] = s
	h.pos = (h.pos + 1) % h.cap
	if h.count < h.cap {
		h.count++
	}
}

// All returns all snapshots in chronological order.
func (h *StatsHistory) All() []StatsSnapshot {
	if h.count == 0 {
		return nil
	}
	result := make([]StatsSnapshot, 0, h.count)
	start := 0
	if h.count == h.cap {
		start = h.pos
	}
	for i := 0; i < h.count; i++ {
		idx := (start + i) % h.cap
		result = append(result, h.points[idx])
	}
	return result
}

// FormatForChart returns chart-ready data.
func (h *StatsHistory) FormatForChart() map[string]interface{} {
	all := h.All()
	labels := make([]string, len(all))
	eventsIn := make([]int64, len(all))
	eventsOut := make([]int64, len(all))
	memory := make([]float64, len(all))
	goroutines := make([]int, len(all))

	for i, s := range all {
		labels[i] = s.Timestamp.Format("15:04")
		eventsIn[i] = s.EventsIn
		eventsOut[i] = s.EventsOut
		memory[i] = s.MemoryMB
		goroutines[i] = s.Goroutines
	}
	return map[string]interface{}{
		"labels":     labels,
		"events_in":  eventsIn,
		"events_out": eventsOut,
		"memory_mb":  memory,
		"goroutines": goroutines,
	}
}

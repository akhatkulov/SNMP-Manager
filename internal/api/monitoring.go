package api

// monitoring.go — /api/v1/monitoring/* endpointlari
//
// Bu fayl qurilmalardan o'qilgan SNMP logg fayllarini real-vaqtda tahlil qilib,
// monitoring paneli uchun statistika va trend ma'lumotlarini qaytaradi.
//
// Per-device log fayllar: logs/devices/{ip}/events.jsonl
//
// Endpointlar:
//   GET /api/v1/monitoring/summary          — Umumiy overview barcha qurilmalar uchun
//   GET /api/v1/monitoring/device/{ip}      — Bitta qurilma analitikasi
//   GET /api/v1/monitoring/device/{ip}/metrics — OID bo'yicha so'nggi qiymatlar
//   GET /api/v1/monitoring/device/{ip}/chart  — Vaqt seriyasi (chart ma'lumotlari)
//   GET /api/v1/monitoring/alerts           — Kritik/high severity eventlar

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/me262/snmp-manager/internal/device"
	"github.com/me262/snmp-manager/internal/pipeline"
)

// ── Data structures ──────────────────────────────────────────────────────────

// MonitoringSummary — barcha qurilmalar uchun umumiy holat.
type MonitoringSummary struct {
	GeneratedAt   time.Time             `json:"generated_at"`
	TotalDevices  int                   `json:"total_devices"`
	DevicesUp     int                   `json:"devices_up"`
	DevicesDown   int                   `json:"devices_down"`
	TotalEvents   int64                 `json:"total_events_1h"`
	CriticalCount int                   `json:"critical_events_1h"`
	Devices       []DeviceMiniStat      `json:"devices"`
	TopOIDs       []OIDFrequency        `json:"top_oids"`
	SeverityDist  map[string]int        `json:"severity_distribution"`
	CategoryDist  map[string]int        `json:"category_distribution"`
}

// DeviceMiniStat — monitoring panelida qurilma mini kartocha uchun.
type DeviceMiniStat struct {
	Name          string        `json:"name"`
	IP            string        `json:"ip"`
	Status        string        `json:"status"`
	LastEvent     *time.Time    `json:"last_event,omitempty"`
	EventCount1h  int           `json:"event_count_1h"`
	CritCount     int           `json:"critical_count"`
	AvgSeverity   float64       `json:"avg_severity"`
	TopMetric     string        `json:"top_metric,omitempty"` // eng ko'p o'zgargan OID
	LogBytes      int64         `json:"log_bytes"`
}

// DeviceAnalytics — bitta qurilma uchun batafsil analitika.
type DeviceAnalytics struct {
	Device       *DeviceMiniStat    `json:"device"`
	RecentEvents []MonitoringEvent  `json:"recent_events"`
	OIDStats     []OIDStat          `json:"oid_stats"`
	SeverityDist map[string]int     `json:"severity_distribution"`
	CategoryDist map[string]int     `json:"category_distribution"`
	HourlyTrend  []HourBucket       `json:"hourly_trend"`
}

// MonitoringEvent — monitoring uchun qisqartirilgan event.
type MonitoringEvent struct {
	Time          time.Time `json:"time"`
	OIDName       string    `json:"oid_name"`
	ValueStr      string    `json:"value_str"`
	Severity      string    `json:"severity"`
	SeverityInt   int       `json:"severity_int"`
	Category      string    `json:"category"`
	FilterReason  string    `json:"filter_reason,omitempty"`
}

// OIDStat — bitta OID uchun statistika.
type OIDStat struct {
	OID         string   `json:"oid"`
	OIDName     string   `json:"oid_name"`
	Count       int      `json:"count"`
	LastValue   string   `json:"last_value"`
	MinVal      *float64 `json:"min_val,omitempty"`
	MaxVal      *float64 `json:"max_val,omitempty"`
	AvgVal      *float64 `json:"avg_val,omitempty"`
	Unit        string   `json:"unit,omitempty"`
	HasNumeric  bool     `json:"has_numeric"`
}

// OIDFrequency — OID qancha marta ko'rinishi.
type OIDFrequency struct {
	OIDName string `json:"oid_name"`
	Count   int    `json:"count"`
}

// ChartSeries — chart.js uchun vaqt seriyasi.
type ChartSeries struct {
	OIDName string          `json:"oid_name"`
	Unit    string          `json:"unit"`
	Points  []ChartDataPoint `json:"points"`
}

// ChartDataPoint — bitta vaqt nuqtasi.
type ChartDataPoint struct {
	T string  `json:"t"` // ISO8601
	V float64 `json:"v"`
}

// HourBucket — soatlik event hisobi (trend grafik uchun).
type HourBucket struct {
	Hour  string `json:"hour"`  // "2006-01-02T15"
	Count int    `json:"count"`
	Crit  int    `json:"critical"`
}

// Alert — kritik/high severity eventlar.
type Alert struct {
	Time      time.Time `json:"time"`
	DeviceIP  string    `json:"device_ip"`
	DeviceName string   `json:"device_name"`
	OIDName   string    `json:"oid_name"`
	ValueStr  string    `json:"value_str"`
	Severity  string    `json:"severity"`
	SevInt    int       `json:"severity_int"`
}

// ── Handler: Summary ─────────────────────────────────────────────────────────

func (s *Server) handleMonitoringSummary(w http.ResponseWriter, r *http.Request) {
	baseDir := s.deviceLogBaseDir()
	since := time.Now().Add(-1 * time.Hour)

	devList := s.registry.List()
	summary := &MonitoringSummary{
		GeneratedAt:  time.Now().UTC(),
		TotalDevices: len(devList),
		SeverityDist: make(map[string]int),
		CategoryDist: make(map[string]int),
	}
	oidFreq := make(map[string]int)

	for _, dev := range devList {
		clone := dev.Clone()
		mini := DeviceMiniStat{
			Name: clone.Name,
			IP:   clone.IP,
		}

		switch clone.Status {
		case device.StatusUp:
			mini.Status = "up"
			summary.DevicesUp++
		case device.StatusDown, device.StatusError:
			mini.Status = "down"
			summary.DevicesDown++
		default:
			mini.Status = "unknown"
		}

		// Per-device log fayl
		logFile := filepath.Join(baseDir, clone.IP, "events.jsonl")
		fi, err := os.Stat(logFile)
		if err == nil {
			mini.LogBytes = fi.Size()
		}

		events := readDeviceEvents(logFile, since, 0)
		mini.EventCount1h = len(events)
		summary.TotalEvents += int64(len(events))

		sevSum := 0
		for _, ev := range events {
			if ev.SeverityInt >= 7 {
				mini.CritCount++
				summary.CriticalCount++
			}
			sevSum += ev.SeverityInt
			summary.SeverityDist[ev.Severity]++
			summary.CategoryDist[ev.Category]++
			if ev.OIDName != "" {
				oidFreq[ev.OIDName]++
			}
		}
		if len(events) > 0 {
			mini.AvgSeverity = float64(sevSum) / float64(len(events))
			last := events[len(events)-1].Time
			mini.LastEvent = &last
		}

		// Top OID for this device
		for _, ev := range events {
			if ev.OIDName != "" {
				mini.TopMetric = ev.OIDName
				break
			}
		}

		summary.Devices = append(summary.Devices, mini)
	}

	// Build top OIDs
	type kv struct {
		k string
		v int
	}
	var pairs []kv
	for k, v := range oidFreq {
		pairs = append(pairs, kv{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].v > pairs[j].v })
	if len(pairs) > 10 {
		pairs = pairs[:10]
	}
	for _, p := range pairs {
		summary.TopOIDs = append(summary.TopOIDs, OIDFrequency{OIDName: p.k, Count: p.v})
	}

	// Sort devices: critical first, then by event count
	sort.Slice(summary.Devices, func(i, j int) bool {
		if summary.Devices[i].CritCount != summary.Devices[j].CritCount {
			return summary.Devices[i].CritCount > summary.Devices[j].CritCount
		}
		return summary.Devices[i].EventCount1h > summary.Devices[j].EventCount1h
	})

	s.writeJSON(w, http.StatusOK, summary)
}

// ── Handler: Device Analytics ─────────────────────────────────────────────────

func (s *Server) handleMonitoringDevice(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	baseDir := s.deviceLogBaseDir()

	// "hours" query param (default 1)
	hoursStr := r.URL.Query().Get("hours")
	hours := 1.0
	if h, err := strconv.ParseFloat(hoursStr, 64); err == nil && h > 0 && h <= 168 {
		hours = h
	}
	since := time.Now().Add(-time.Duration(hours * float64(time.Hour)))

	logFile := filepath.Join(baseDir, ip, "events.jsonl")
	events := readDeviceEvents(logFile, since, 500)

	mini := &DeviceMiniStat{IP: ip}
	if dev, ok := s.registry.GetByIP(ip); ok {
		clone := dev.Clone()
		mini.Name = clone.Name
		switch clone.Status {
		case device.StatusUp:
			mini.Status = "up"
		case device.StatusDown, device.StatusError:
			mini.Status = "down"
		default:
			mini.Status = "unknown"
		}
	}

	if fi, err := os.Stat(logFile); err == nil {
		mini.LogBytes = fi.Size()
	}

	analytics := &DeviceAnalytics{
		Device:       mini,
		SeverityDist: make(map[string]int),
		CategoryDist: make(map[string]int),
	}

	oidMap := make(map[string]*oidAccumulator)
	hourMap := make(map[string]*HourBucket)

	for _, ev := range events {
		analytics.SeverityDist[ev.Severity]++
		analytics.CategoryDist[ev.Category]++
		if ev.SeverityInt >= 7 {
			mini.CritCount++
		}
		mini.EventCount1h++

		// OID stats
		acc := oidMap[ev.OIDName]
		if acc == nil {
			acc = &oidAccumulator{oid: ev.OIDName, name: ev.OIDName}
			oidMap[ev.OIDName] = acc
		}
		acc.count++
		acc.lastValue = ev.ValueStr
		if ev.SeverityInt > acc.maxSev {
			acc.maxSev = ev.SeverityInt
		}

		// Hourly trend
		hourKey := ev.Time.UTC().Format("2006-01-02T15")
		bucket := hourMap[hourKey]
		if bucket == nil {
			bucket = &HourBucket{Hour: hourKey}
			hourMap[hourKey] = bucket
		}
		bucket.Count++
		if ev.SeverityInt >= 7 {
			bucket.Crit++
		}
	}

	if len(events) > 0 {
		mini.EventCount1h = len(events)
		last := events[len(events)-1].Time
		mini.LastEvent = &last

		// Recent events (last 50, newest first)
		limit := 50
		from := len(events) - limit
		if from < 0 {
			from = 0
		}
		slice := events[from:]
		for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
			slice[i], slice[j] = slice[j], slice[i]
		}
		analytics.RecentEvents = slice
	}

	// Build OID stats
	for _, acc := range oidMap {
		analytics.OIDStats = append(analytics.OIDStats, OIDStat{
			OIDName:   acc.name,
			OID:       acc.oid,
			Count:     acc.count,
			LastValue: acc.lastValue,
		})
	}
	sort.Slice(analytics.OIDStats, func(i, j int) bool {
		return analytics.OIDStats[i].Count > analytics.OIDStats[j].Count
	})
	if len(analytics.OIDStats) > 20 {
		analytics.OIDStats = analytics.OIDStats[:20]
	}

	// Hourly trend — last 24 hours sorted
	for _, b := range hourMap {
		analytics.HourlyTrend = append(analytics.HourlyTrend, *b)
	}
	sort.Slice(analytics.HourlyTrend, func(i, j int) bool {
		return analytics.HourlyTrend[i].Hour < analytics.HourlyTrend[j].Hour
	})

	s.writeJSON(w, http.StatusOK, analytics)
}

// ── Handler: Device Metrics (last value per OID) ──────────────────────────────

func (s *Server) handleMonitoringMetrics(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	baseDir := s.deviceLogBaseDir()
	logFile := filepath.Join(baseDir, ip, "events.jsonl")

	// Read last 6 hours to get latest value per OID
	since := time.Now().Add(-6 * time.Hour)
	events := readDeviceEvents(logFile, since, 5000)

	// Latest value per OID
	oidLatest := make(map[string]*pipeline.SNMPEvent)
	for i := range events {
		// MonitoringEvent → need raw; we call scanRawEvents separately
		_ = events[i]
	}

	rawEvents := readRawDeviceEvents(logFile, since, 5000)
	for i := range rawEvents {
		ev := &rawEvents[i]
		oidLatest[ev.OID] = ev
	}

	type MetricItem struct {
		OID         string   `json:"oid"`
		OIDName     string   `json:"oid_name"`
		OIDModule   string   `json:"oid_module,omitempty"`
		Value       any      `json:"value"`
		ValueStr    string   `json:"value_str"`
		ValueType   string   `json:"value_type"`
		MetricValue *float64 `json:"metric_value,omitempty"`
		Unit        string   `json:"unit,omitempty"`
		Severity    string   `json:"severity"`
		SeverityInt int      `json:"severity_int"`
		Category    string   `json:"category"`
		UpdatedAt   time.Time `json:"updated_at"`
	}

	items := make([]MetricItem, 0, len(oidLatest))
	for _, ev := range oidLatest {
		sev := int(ev.Severity)
		items = append(items, MetricItem{
			OID:         ev.OID,
			OIDName:     ev.OIDName,
			OIDModule:   ev.OIDModule,
			Value:       ev.Value,
			ValueStr:    ev.ValueStr,
			ValueType:   ev.ValueType,
			MetricValue: ev.MetricValue,
			Unit:        ev.MetricUnit,
			Severity:    ev.SeverityLabel,
			SeverityInt: sev,
			Category:    string(ev.Category),
			UpdatedAt:   ev.Timestamp,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].OIDName < items[j].OIDName
	})

	s.writeJSON(w, http.StatusOK, map[string]any{
		"device_ip": ip,
		"count":     len(items),
		"metrics":   items,
	})
}

// ── Handler: Device Chart (time series per OID) ───────────────────────────────

func (s *Server) handleMonitoringChart(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	oidFilter := r.URL.Query().Get("oid") // filtrlanajak OID nomi
	baseDir := s.deviceLogBaseDir()

	hoursStr := r.URL.Query().Get("hours")
	hours := 3.0
	if h, err := strconv.ParseFloat(hoursStr, 64); err == nil && h > 0 && h <= 168 {
		hours = h
	}
	since := time.Now().Add(-time.Duration(hours * float64(time.Hour)))

	logFile := filepath.Join(baseDir, ip, "events.jsonl")
	rawEvents := readRawDeviceEvents(logFile, since, 10000)

	// Group by OID, filter numeric-only
	type oidData struct {
		name   string
		unit   string
		points []ChartDataPoint
	}
	oidSeries := make(map[string]*oidData)

	for i := range rawEvents {
		ev := &rawEvents[i]
		if oidFilter != "" && ev.OIDName != oidFilter && ev.OID != oidFilter {
			continue
		}
		if ev.MetricValue == nil {
			continue // numeric olmagan qiymatlar chart da ko'rsatilmaydi
		}
		key := ev.OIDName
		if key == "" {
			key = ev.OID
		}
		d := oidSeries[key]
		if d == nil {
			d = &oidData{name: key, unit: ev.MetricUnit}
			oidSeries[key] = d
		}
		d.points = append(d.points, ChartDataPoint{
			T: ev.Timestamp.UTC().Format(time.RFC3339),
			V: roundFloat(*ev.MetricValue, 3),
		})
	}

	var series []ChartSeries
	for _, d := range oidSeries {
		if len(d.points) < 2 {
			continue // kam nuqta — grafikda ma'nosiz
		}
		series = append(series, ChartSeries{
			OIDName: d.name,
			Unit:    d.unit,
			Points:  d.points,
		})
	}
	sort.Slice(series, func(i, j int) bool { return len(series[i].Points) > len(series[j].Points) })

	// Max 8 grafik (UI chidamli)
	if len(series) > 8 {
		series = series[:8]
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"device_ip":    ip,
		"series_count": len(series),
		"since":        since.UTC().Format(time.RFC3339),
		"series":       series,
	})
}

// ── Handler: Alerts (kritik eventlar barcha qurilmalardan) ────────────────────

func (s *Server) handleMonitoringAlerts(w http.ResponseWriter, r *http.Request) {
	baseDir := s.deviceLogBaseDir()
	since := time.Now().Add(-3 * time.Hour)

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
		limit = l
	}

	devList := s.registry.List()
	devNames := make(map[string]string)
	for _, d := range devList {
		clone := d.Clone()
		devNames[clone.IP] = clone.Name
	}

	var alerts []Alert

	// Barcha device papkalarini skan
	entries, _ := os.ReadDir(baseDir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ip := e.Name()
		logFile := filepath.Join(baseDir, ip, "events.jsonl")
		events := readDeviceEvents(logFile, since, 500)

		for _, ev := range events {
			if ev.SeverityInt < 7 { // faqat high+critical
				continue
			}
			name := devNames[ip]
			if name == "" {
				name = ip
			}
			alerts = append(alerts, Alert{
				Time:       ev.Time,
				DeviceIP:   ip,
				DeviceName: name,
				OIDName:    ev.OIDName,
				ValueStr:   ev.ValueStr,
				Severity:   ev.Severity,
				SevInt:     ev.SeverityInt,
			})
		}
	}

	// Newest first
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].Time.After(alerts[j].Time) })
	if len(alerts) > limit {
		alerts = alerts[:limit]
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"count":  len(alerts),
		"since":  since.UTC().Format(time.RFC3339),
		"alerts": alerts,
	})
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// deviceLogBaseDir returns the base directory for per-device log files.
// It reads the "device_file" output config path if available.
func (s *Server) deviceLogBaseDir() string {
	for _, o := range s.outputConfigs {
		if o.Type == "device_file" && o.Enabled && o.Path != "" {
			return o.Path
		}
	}
	return "./logs/devices"
}

type oidAccumulator struct {
	oid       string
	name      string
	count     int
	lastValue string
	maxSev    int
}

// readDeviceEvents reads MonitoringEvent list from a JSONL log file.
func readDeviceEvents(logFile string, since time.Time, maxLines int) []MonitoringEvent {
	f, err := os.Open(logFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []MonitoringEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var ev pipeline.SNMPEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Timestamp.Before(since) {
			continue
		}
		me := MonitoringEvent{
			Time:         ev.Timestamp,
			OIDName:      ev.OIDName,
			ValueStr:     ev.ValueStr,
			Severity:     ev.SeverityLabel,
			SeverityInt:  int(ev.Severity),
			Category:     string(ev.Category),
			FilterReason: ev.FilterReason,
		}
		if me.Severity == "" {
			me.Severity = "info"
		}
		out = append(out, me)
	}

	if maxLines > 0 && len(out) > maxLines {
		out = out[len(out)-maxLines:]
	}
	return out
}

// readRawDeviceEvents reads full SNMPEvent structs from a JSONL log file.
func readRawDeviceEvents(logFile string, since time.Time, maxLines int) []pipeline.SNMPEvent {
	f, err := os.Open(logFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []pipeline.SNMPEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 512*1024), 512*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var ev pipeline.SNMPEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Timestamp.Before(since) {
			continue
		}
		out = append(out, ev)
	}

	if maxLines > 0 && len(out) > maxLines {
		out = out[len(out)-maxLines:]
	}
	return out
}

func roundFloat(v float64, decimals int) float64 {
	p := math.Pow(10, float64(decimals))
	return math.Round(v*p) / p
}

var _ = fmt.Sprintf // keep fmt import
var _ = strings.ToLower

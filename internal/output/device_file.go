// Package output — DeviceFileOutput
//
// Har bir qurilma (device) bo'yicha alohida log fayl yozadi:
//
//	logs/
//	  devices/
//	    10.10.11.53/
//	      events.jsonl          ← joriy fayl
//	      events.20260406-1200.jsonl  ← rotatsiya qilingan
//	    192.168.1.1/
//	      events.jsonl
//
// Foydalanish:
//
//	out := output.NewDeviceFileOutput(log, output.DeviceFileConfig{
//	    BaseDir:    "./logs/devices",
//	    MaxSizeMB:  50,
//	    MaxBackups: 5,
//	})
//
// Bu output pipeline.Output interfeysini to'liq implement qiladi,
// shuning uchun mavjud pipeline'ga to'g'ridan-to'g'ri ulanadi.
package output

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/pipeline"
)

// DeviceFileConfig — konfiguratsiya.
type DeviceFileConfig struct {
	// BaseDir: qurilma papkalari yaratiladi shu yerda.
	// Default: "./logs/devices"
	BaseDir string

	// MaxSizeMB: bir fayl shuncha MB ga yetganda rotatsiya qilinadi.
	// 0 = rotatsiya o'chirilgan. Default: 50 MB
	MaxSizeMB int

	// MaxBackups: qurilma papkasida saqlangan eski fayllar soni.
	// 0 = cheksiz. Default: 7
	MaxBackups int

	// FlushInterval: bufferdan diskka qancha vaqtda bir yozilsin.
	// Default: 2s
	FlushInterval time.Duration
}

// deviceWriter — bitta qurilma uchun ichki yozuvchi.
type deviceWriter struct {
	mu      sync.Mutex
	path    string // faol fayl yo'li
	fd      *os.File
	buf     *bufio.Writer
	written int64 // bayt hisoblagich
	events  int64
}

// DeviceFileOutput — barcha qurilmalar uchun markaziy yozuvchi.
// Har bir DeviceIP uchun bitta deviceWriter lazy-init qilinadi.
type DeviceFileOutput struct {
	log zerolog.Logger
	cfg DeviceFileConfig

	mu      sync.RWMutex
	writers map[string]*deviceWriter // device_ip → writer

	// Periodik flush uchun
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Statistika
	totalEvents int64
	mu2         sync.Mutex
}

// NewDeviceFileOutput yangi DeviceFileOutput yaratadi.
// baseDir papkasi avtomatik yaratiladi.
func NewDeviceFileOutput(log zerolog.Logger, cfg DeviceFileConfig) *DeviceFileOutput {
	if cfg.BaseDir == "" {
		cfg.BaseDir = "./logs/devices"
	}
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 50
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 7
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}

	if err := os.MkdirAll(cfg.BaseDir, 0o755); err != nil {
		log.Error().Err(err).Str("dir", cfg.BaseDir).Msg("device log base dir yaratib bo'lmadi")
	}

	ctx, cancel := context.WithCancel(context.Background())

	d := &DeviceFileOutput{
		log:     log.With().Str("component", "device-file-output").Logger(),
		cfg:     cfg,
		writers: make(map[string]*deviceWriter),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Periodik flush goroutine
	d.wg.Add(1)
	go d.flushLoop()

	d.log.Info().
		Str("base_dir", cfg.BaseDir).
		Int("max_size_mb", cfg.MaxSizeMB).
		Int("max_backups", cfg.MaxBackups).
		Dur("flush_interval", cfg.FlushInterval).
		Msg("device file output started — har qurilma uchun alohida log fayl")

	return d
}

// Name — pipeline.Output interfeysi uchun.
func (d *DeviceFileOutput) Name() string {
	return fmt.Sprintf("device-file(%s)", d.cfg.BaseDir)
}

// Write — eventni mos qurilma fayliga yozadi.
// Bu metod goroutine-safe: turli goroutinelardan bir vaqtda chaqirilishi mumkin.
func (d *DeviceFileOutput) Write(_ context.Context, event *pipeline.SNMPEvent) error {
	ip := event.DeviceIP
	if ip == "" {
		ip = "unknown"
	}

	w := d.getOrCreateWriter(ip)

	data, err := marshalEvent(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Rotatsiya kerakmi?
	if d.cfg.MaxSizeMB > 0 && w.written >= int64(d.cfg.MaxSizeMB)*1024*1024 {
		if err := d.rotate(w, ip); err != nil {
			d.log.Error().Err(err).Str("device", ip).Msg("fayl rotatsiyasi muvaffaqiyatsiz")
		}
	}

	// Fayl ochiq emasmi?
	if w.fd == nil {
		if err := d.openFile(w, ip); err != nil {
			return err
		}
	}

	n, err := w.buf.WriteString(data + "\n")
	if err != nil {
		return fmt.Errorf("device %s ga yozib bo'lmadi: %w", ip, err)
	}

	w.written += int64(n)
	w.events++

	d.mu2.Lock()
	d.totalEvents++
	d.mu2.Unlock()

	return nil
}

// Close — barcha ochiq fayllarni yopadi.
func (d *DeviceFileOutput) Close() error {
	d.cancel()
	d.wg.Wait()

	d.mu.Lock()
	defer d.mu.Unlock()

	var lastErr error
	for ip, w := range d.writers {
		w.mu.Lock()
		if w.buf != nil {
			w.buf.Flush()
		}
		if w.fd != nil {
			if err := w.fd.Close(); err != nil {
				lastErr = err
			}
			w.fd = nil
		}
		w.mu.Unlock()
		d.log.Info().
			Str("device", ip).
			Int64("events", w.events).
			Int64("bytes", w.written).
			Msg("device log fayli yopildi")
	}

	d.mu2.Lock()
	d.log.Info().Int64("total_events", d.totalEvents).Msg("device file output yopildi")
	d.mu2.Unlock()

	return lastErr
}

// Stats — dashboard uchun statistika.
func (d *DeviceFileOutput) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	devices := make([]map[string]interface{}, 0, len(d.writers))
	for ip, w := range d.writers {
		w.mu.Lock()
		devices = append(devices, map[string]interface{}{
			"device_ip":  ip,
			"file":       w.path,
			"events":     w.events,
			"bytes":      w.written,
		})
		w.mu.Unlock()
	}

	d.mu2.Lock()
	total := d.totalEvents
	d.mu2.Unlock()

	return map[string]interface{}{
		"total_events": total,
		"devices":      devices,
		"base_dir":     d.cfg.BaseDir,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ichki metodlar
// ─────────────────────────────────────────────────────────────────────────────

// getOrCreateWriter — IP uchun writer lazy-yaratadi.
func (d *DeviceFileOutput) getOrCreateWriter(ip string) *deviceWriter {
	// Read lock bilan tekshir
	d.mu.RLock()
	w, ok := d.writers[ip]
	d.mu.RUnlock()
	if ok {
		return w
	}

	// Yangi yaratish
	d.mu.Lock()
	defer d.mu.Unlock()

	// Double-checked locking
	if w, ok = d.writers[ip]; ok {
		return w
	}

	dir := filepath.Join(d.cfg.BaseDir, sanitizeIP(ip))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		d.log.Error().Err(err).Str("device", ip).Msg("device papkasi yaratib bo'lmadi")
	}

	w = &deviceWriter{
		path: filepath.Join(dir, "events.jsonl"),
	}
	d.writers[ip] = w

	d.log.Info().
		Str("device", ip).
		Str("path", w.path).
		Msg("yangi device log writer yaratildi")

	return w
}

// openFile — writer uchun fayl ochadi (mutex ichida chaqirilishi kerak).
func (d *DeviceFileOutput) openFile(w *deviceWriter, ip string) error {
	fd, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("device %s log faylini ochib bo'lmadi %s: %w", ip, w.path, err)
	}

	info, _ := fd.Stat()
	if info != nil {
		w.written = info.Size()
	}

	w.fd = fd
	w.buf = bufio.NewWriterSize(fd, 64*1024) // 64KB buffer
	return nil
}

// rotate — fayl hajmi limitga yetganda eski nomi bilan saqlaydi, yangi ochadi.
// (w.mu lock ostida chaqirilishi kerak)
func (d *DeviceFileOutput) rotate(w *deviceWriter, ip string) error {
	if w.buf != nil {
		w.buf.Flush()
	}
	if w.fd != nil {
		w.fd.Close()
		w.fd = nil
		w.buf = nil
	}

	// Eski fayl nomini timestamp bilan o'zgartir
	rotated := fmt.Sprintf("%s.%s", w.path, time.Now().Format("20060102-150405"))
	if err := os.Rename(w.path, rotated); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	d.log.Info().
		Str("device", ip).
		Str("rotated_to", rotated).
		Int64("bytes", w.written).
		Msg("device log rotatsiyasi bajarildi")

	w.written = 0

	// Eski backup fayllarni tozala
	d.cleanupBackups(w.path, ip)

	// Yangi fayl och
	return d.openFile(w, ip)
}

// cleanupBackups — papkadagi eski rotatsiyalangan fayllarni o'chiradi.
func (d *DeviceFileOutput) cleanupBackups(activePath, ip string) {
	if d.cfg.MaxBackups <= 0 {
		return
	}

	dir := filepath.Dir(activePath)
	base := filepath.Base(activePath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var backups []string
	for _, e := range entries {
		name := e.Name()
		if name != base && len(name) > len(base) && name[:len(base)] == base {
			backups = append(backups, filepath.Join(dir, name))
		}
	}

	removed := 0
	for len(backups) > d.cfg.MaxBackups {
		if err := os.Remove(backups[0]); err == nil {
			removed++
		}
		backups = backups[1:]
	}

	if removed > 0 {
		d.log.Debug().Str("device", ip).Int("removed", removed).Msg("eski backup fayllar o'chirildi")
	}
}

// flushLoop — barcha ochiq bufferlarni periodik ravishda diskka yozadi.
func (d *DeviceFileOutput) flushLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(d.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			d.flushAll()
			return
		case <-ticker.C:
			d.flushAll()
		}
	}
}

// flushAll — barcha writerlarni flush qiladi.
func (d *DeviceFileOutput) flushAll() {
	d.mu.RLock()
	writers := make([]*deviceWriter, 0, len(d.writers))
	for _, w := range d.writers {
		writers = append(writers, w)
	}
	d.mu.RUnlock()

	for _, w := range writers {
		w.mu.Lock()
		if w.buf != nil {
			w.buf.Flush()
		}
		w.mu.Unlock()
	}
}

// marshalEvent — eventni NDJSON ga aylantiradi.
func marshalEvent(event *pipeline.SNMPEvent) (string, error) {
	b, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// sanitizeIP — IP manzilini papka nomi uchun xavfsiz stringga aylantiradi.
// "10.10.11.53" → "10.10.11.53" (nuqtalar ruxsat)
// "::1"        → "__1"          (ikki nuqta o'rniga pastki chiziq)
func sanitizeIP(ip string) string {
	result := make([]byte, len(ip))
	for i := 0; i < len(ip); i++ {
		c := ip[i]
		if (c >= '0' && c <= '9') || c == '.' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' {
			result[i] = c
		} else {
			result[i] = '_'
		}
	}
	return string(result)
}

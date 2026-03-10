package output

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/formatter"
	"github.com/me262/snmp-manager/internal/pipeline"
)

// FileOutput writes events to a file with rotation.
type FileOutput struct {
	log        zerolog.Logger
	path       string
	maxSizeMB  int
	maxBackups int
	compress   bool

	jsonFmt *formatter.JSONFormatter
	mu      sync.Mutex
	file    *os.File
	written int64
	events  int64
}

// NewFileOutput creates a new file output.
func NewFileOutput(log zerolog.Logger, path string, maxSizeMB, maxBackups int, compress bool) *FileOutput {
	return &FileOutput{
		log:        log.With().Str("component", "output-file").Logger(),
		path:       path,
		maxSizeMB:  maxSizeMB,
		maxBackups: maxBackups,
		compress:   compress,
		jsonFmt:    formatter.NewJSONFormatter(false),
	}
}

// Name returns the output name.
func (f *FileOutput) Name() string {
	return fmt.Sprintf("file-%s", filepath.Base(f.path))
}

// Write formats and writes an event to the file.
func (f *FileOutput) Write(ctx context.Context, event *pipeline.SNMPEvent) error {
	data, err := f.jsonFmt.Format(event)
	if err != nil {
		return fmt.Errorf("format event: %w", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file == nil {
		if err := f.openFile(); err != nil {
			return err
		}
	}

	// Check if rotation is needed
	if f.maxSizeMB > 0 && f.written >= int64(f.maxSizeMB)*1024*1024 {
		if err := f.rotate(); err != nil {
			f.log.Error().Err(err).Msg("file rotation failed")
		}
	}

	n, err := f.file.WriteString(data + "\n")
	if err != nil {
		return fmt.Errorf("write to file: %w", err)
	}

	f.written += int64(n)
	f.events++
	return nil
}

// Close closes the output file.
func (f *FileOutput) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file != nil {
		f.log.Info().
			Int64("events", f.events).
			Int64("bytes", f.written).
			Msg("closing file output")
		err := f.file.Close()
		f.file = nil
		return err
	}
	return nil
}

func (f *FileOutput) openFile() error {
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}

	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open file %s: %w", f.path, err)
	}

	// Get current file size
	info, err := file.Stat()
	if err == nil {
		f.written = info.Size()
	}

	f.file = file
	f.log.Info().Str("path", f.path).Msg("file output opened")
	return nil
}

func (f *FileOutput) rotate() error {
	if f.file != nil {
		f.file.Close()
	}

	// Rename current file with timestamp
	rotated := fmt.Sprintf("%s.%s", f.path, time.Now().Format("20060102-150405"))
	if err := os.Rename(f.path, rotated); err != nil {
		return fmt.Errorf("rotate file: %w", err)
	}

	f.log.Info().Str("rotated", rotated).Msg("file rotated")

	// Cleanup old backups
	f.cleanupOldBackups()

	// Open new file
	f.written = 0
	return f.openFile()
}

func (f *FileOutput) cleanupOldBackups() {
	if f.maxBackups <= 0 {
		return
	}

	dir := filepath.Dir(f.path)
	base := filepath.Base(f.path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var backups []string
	for _, entry := range entries {
		name := entry.Name()
		if name != base && len(name) > len(base) && name[:len(base)] == base {
			backups = append(backups, filepath.Join(dir, name))
		}
	}

	// Remove oldest backups if exceeding max
	for len(backups) > f.maxBackups {
		oldest := backups[0]
		os.Remove(oldest)
		backups = backups[1:]
		f.log.Debug().Str("removed", oldest).Msg("old backup removed")
	}
}

// StdoutOutput writes formatted events to stdout (for debugging).
type StdoutOutput struct {
	log     zerolog.Logger
	jsonFmt *formatter.JSONFormatter
	events  int64
	mu      sync.Mutex
}

// NewStdoutOutput creates a new stdout output.
func NewStdoutOutput(log zerolog.Logger) *StdoutOutput {
	return &StdoutOutput{
		log:     log.With().Str("component", "output-stdout").Logger(),
		jsonFmt: formatter.NewJSONFormatter(true),
	}
}

// Name returns the output name.
func (s *StdoutOutput) Name() string { return "stdout" }

// Write formats and prints an event to stdout.
func (s *StdoutOutput) Write(ctx context.Context, event *pipeline.SNMPEvent) error {
	data, err := s.jsonFmt.Format(event)
	if err != nil {
		return err
	}
	fmt.Println(data)
	s.mu.Lock()
	s.events++
	s.mu.Unlock()
	return nil
}

// Close is a no-op for stdout.
func (s *StdoutOutput) Close() error {
	s.log.Info().Int64("events", s.events).Msg("stdout output closed")
	return nil
}

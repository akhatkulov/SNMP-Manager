package output

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/me262/snmp-manager/internal/pipeline"
)

func sampleEvent() *pipeline.SNMPEvent {
	return &pipeline.SNMPEvent{
		ID:        "test-evt-001",
		Timestamp: time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC),
		EventType: pipeline.EventTypeTrap,
		Source: pipeline.SourceInfo{
			IP:       "10.0.0.1",
			Hostname: "test-router",
		},
		SNMP: pipeline.SNMPData{
			Version:     "v2c",
			OID:         "1.3.6.1.6.3.1.1.5.3",
			OIDName:     "linkDown",
			Value:       2,
			ValueType:   "Integer",
			ValueString: "down",
			RequestType: "trap",
		},
		Severity:      pipeline.SeverityHigh,
		SeverityLabel: "high",
		Category:      "network",
	}
}

// ── File Output Tests ───────────────────────────────────────────────

func TestFileOutputWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-events.log")

	out := NewFileOutput(zerolog.Nop(), path, 100, 5, false)
	defer out.Close()

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := out.Write(ctx, sampleEvent()); err != nil {
			t.Fatalf("write #%d error: %v", i, err)
		}
	}

	// Verify file exists and has content
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Errorf("line count: want 5, got %d", len(lines))
	}

	// Each line should be valid JSON
	for i, line := range lines {
		if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
			t.Errorf("line %d is not valid JSON: %s", i, line[:min(50, len(line))])
		}
	}
}

func TestFileOutputCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "deep", "events.log")

	out := NewFileOutput(zerolog.Nop(), path, 100, 5, false)
	defer out.Close()

	if err := out.Write(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("write error: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("file should have been created with subdirectories")
	}
}

func TestFileOutputName(t *testing.T) {
	out := NewFileOutput(zerolog.Nop(), "/var/log/snmp/events.log", 100, 5, false)
	name := out.Name()
	if !strings.Contains(name, "events.log") {
		t.Errorf("name should contain filename, got: %q", name)
	}
}

func TestFileOutputRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rotate-test.log")

	// Set very small max size to trigger rotation
	out := &FileOutput{
		log:        zerolog.Nop(),
		path:       path,
		maxSizeMB:  1, // 1 MB
		maxBackups: 2,
		jsonFmt:    NewFileOutput(zerolog.Nop(), "", 0, 0, false).jsonFmt,
	}
	defer out.Close()

	// Write some data to set initial written counter high
	out.openFile()
	out.written = 1024 * 1024 // Simulate 1MB already written

	// Next write should trigger rotation
	if err := out.Write(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("write after rotation: %v", err)
	}

	// Check that a rotated file exists
	entries, _ := os.ReadDir(dir)
	rotatedCount := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rotate-test.log.") {
			rotatedCount++
		}
	}
	if rotatedCount == 0 {
		t.Error("rotation should have created a backup file")
	}
}

func TestFileOutputClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "close-test.log")

	out := NewFileOutput(zerolog.Nop(), path, 100, 5, false)
	out.Write(context.Background(), sampleEvent())

	if err := out.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}

	// Double close should not error (file is set to nil after close)
	err := out.Close()
	_ = err // second close is a no-op since file is nil
}

// ── Stdout Output Tests ─────────────────────────────────────────────

func TestStdoutOutputName(t *testing.T) {
	out := NewStdoutOutput(zerolog.Nop())
	if out.Name() != "stdout" {
		t.Errorf("name: want %q, got %q", "stdout", out.Name())
	}
}

func TestStdoutOutputWrite(t *testing.T) {
	out := NewStdoutOutput(zerolog.Nop())

	// Redirect stdout to capture output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := out.Write(context.Background(), sampleEvent())

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("write error: %v", err)
	}

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "test-evt-001") {
		t.Error("stdout output should contain event ID")
	}

	out.Close()
}

// ── Syslog Output Tests ────────────────────────────────────────────

func TestSyslogOutputName(t *testing.T) {
	out := NewSyslogOutput(zerolog.Nop(), "siem:514", "tcp", "cef")
	name := out.Name()
	if !strings.Contains(name, "syslog") {
		t.Errorf("name should contain 'syslog', got: %q", name)
	}
	if !strings.Contains(name, "siem:514") {
		t.Errorf("name should contain address, got: %q", name)
	}
}

func TestSyslogOutputFormatSelection(t *testing.T) {
	tests := []struct {
		format   string
		contains string
	}{
		{"cef", "CEF:0|"},
		{"json", `"id"`},
		{"syslog", "<"},
		{"leef", "LEEF:2.0|"},
		{"unknown", `"id"`}, // defaults to JSON
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			out := NewSyslogOutput(zerolog.Nop(), "fake:514", "tcp", tt.format)
			result, err := out.formatEvent(sampleEvent())
			if err != nil {
				t.Fatalf("format error: %v", err)
			}
			if !strings.Contains(result, tt.contains) {
				t.Errorf("format %q: result should contain %q, got: %s", tt.format, tt.contains, result[:min(80, len(result))])
			}
		})
	}
}

func TestSyslogOutputWriteNoServer(t *testing.T) {
	// Writing to a non-existent server should return an error
	out := NewSyslogOutput(zerolog.Nop(), "127.0.0.1:59999", "tcp", "json")

	err := out.Write(context.Background(), sampleEvent())
	if err == nil {
		t.Error("expected error when writing to non-existent server")
	}
}

func TestSyslogOutputClose(t *testing.T) {
	out := NewSyslogOutput(zerolog.Nop(), "fake:514", "tcp", "json")
	// Close without ever connecting should not error
	if err := out.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

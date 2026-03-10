package telemetry

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestSetupLoggerLevels(t *testing.T) {
	tests := []struct {
		level string
		want  zerolog.Level
	}{
		{"debug", zerolog.DebugLevel},
		{"info", zerolog.InfoLevel},
		{"warn", zerolog.WarnLevel},
		{"error", zerolog.ErrorLevel},
		{"invalid", zerolog.InfoLevel},
		{"DEBUG", zerolog.DebugLevel},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			_ = SetupLogger(tt.level, "json")
			if zerolog.GlobalLevel() != tt.want {
				t.Errorf("level %q: want %v, got %v", tt.level, tt.want, zerolog.GlobalLevel())
			}
		})
	}
}

func TestSetupLoggerFormats(t *testing.T) {
	// Should not panic for any format
	_ = SetupLogger("info", "json")
	_ = SetupLogger("info", "text")
	_ = SetupLogger("info", "console")
	_ = SetupLogger("info", "unknown")
}

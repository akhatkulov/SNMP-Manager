package telemetry

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// SetupLogger configures the global zerolog logger.
func SetupLogger(level, format string) zerolog.Logger {
	// Set log level
	switch strings.ToLower(level) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	var log zerolog.Logger

	switch strings.ToLower(format) {
	case "text", "console":
		log = zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}).With().Timestamp().Caller().Logger()
	default:
		// JSON format (default for production)
		log = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()
	}

	return log
}

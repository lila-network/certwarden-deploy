package logger

import (
	"log/slog"
	"os"
	"strconv"

	"gitlab.lila.network/lila-network/certwarden-deploy/internal/configuration"
)

// Initialize initializes a *slog.Logger with the right log level and options.
func Initialize() *slog.Logger {
	logLevel := slog.LevelInfo

	if configuration.VerboseLogging {
		logLevel = slog.LevelDebug
	}
	if configuration.QuietLogging {
		logLevel = slog.LevelError
	}
	if configuration.DryRun {
		logLevel = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	log := slog.New(handler)

	log.Debug("configuration.VerboseLogging is " + strconv.FormatBool(configuration.VerboseLogging))
	log.Debug("configuration.QuietLogging is " + strconv.FormatBool(configuration.QuietLogging))
	log.Debug("configuration.DryRun is " + strconv.FormatBool(configuration.DryRun))

	return log
}

package logger

import (
	"io"
	"log/slog"
	"os"
	"strconv"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
)

// Initialize initializes a *slog.Logger with the right log level and options.
func Initialize() *slog.Logger {
	return InitializeTo(os.Stdout)
}

// InitializeTo is Initialize with an explicit destination for the log records.
//
// It exists for the subcommands whose output is data rather than prose: `fetch
// certificate example.com` has to survive being piped into openssl, and a log
// record landing in the middle of that pipe would corrupt it. Those commands
// log to stderr and keep stdout for the material itself.
func InitializeTo(w io.Writer) *slog.Logger {
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

	handler := slog.NewTextHandler(w, opts)
	log := slog.New(handler)

	log.Debug("configuration.VerboseLogging is " + strconv.FormatBool(configuration.VerboseLogging))
	log.Debug("configuration.QuietLogging is " + strconv.FormatBool(configuration.QuietLogging))
	log.Debug("configuration.DryRun is " + strconv.FormatBool(configuration.DryRun))

	return log
}

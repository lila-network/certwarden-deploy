package logger

import (
	"log/slog"
	"os"

	"code.lila.network/adoralaura/certwarden-deploy/internal/config"
)

func InitializeLogger() {
	logLevel := slog.LevelInfo

	if config.VerboseLogging {
		logLevel = slog.LevelDebug
	}
	if config.QuietLogging {
		logLevel = slog.LevelError
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)

	slog.SetDefault(slog.New(handler))
}

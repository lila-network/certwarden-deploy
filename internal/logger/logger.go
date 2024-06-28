package logger

import (
	"log/slog"
	"os"
)

func InitializeLogger() {
	// TODO: Different Log levels

	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)

	slog.SetDefault(slog.New(handler))
}

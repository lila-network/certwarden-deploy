package errlog

import (
	"log/slog"

	"github.com/getsentry/sentry-go"
)

func SetupSentry(logger *slog.Logger, dsn string) error {
	if dsn == "" {
		return nil
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn: dsn,
		// Set TracesSampleRate to 1.0 to capture 100%
		// of transactions for performance monitoring.
		// We recommend adjusting this value in production,
		TracesSampleRate: 1.0,
	})
	if err != nil {
		logger.Error("failed to set up sentry")
	}
	// Flush buffered events before the program terminates.

	return nil
}

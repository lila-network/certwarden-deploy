package certificates

import (
	"log/slog"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
)

// summaryMessage is the message every run ends with. It is a stable string on
// purpose: it is what an operator greps for.
const summaryMessage = "run summary"

// Total returns the number of certificates the run attempted.
//
// Action outcomes are deliberately not part of it: a certificate with a failed
// action was still deployed and is already counted as new or changed.
func (r *RunResult) Total() int {
	return len(r.New) + len(r.Changed) + len(r.Unchanged) + len(r.Failed)
}

// LogSummary reports the outcome of a run in one greppable record, followed by
// one record per failure.
//
// The counts are always present, even when zero, so the field set does not
// change shape between runs and can be parsed or alerted on.
//
// Levels are chosen around --quiet: the summary is Info, so a normal run gets
// it once and a quiet run stays silent when everything worked, while failures
// are Error, so a quiet run still says what broke. A quiet run that failed
// also gets the summary repeated at Error, so the counts are never lost
// exactly when they matter.
func (r *RunResult) LogSummary(logger *slog.Logger) {
	message := summaryMessage
	if configuration.DryRun {
		message = "DRY-RUN: " + summaryMessage
	}

	args := []any{
		"new", len(r.New),
		"changed", len(r.Changed),
		"unchanged", len(r.Unchanged),
		"failed", len(r.Failed),
		"action_failed", len(r.ActionFailed),
		"action_skipped", len(r.ActionSkipped),
		"total", r.Total(),
	}

	logger.Info(message, args...)

	if r.HasFailures() {
		if configuration.QuietLogging {
			logger.Error(message, args...)
		}

		for _, failure := range r.Failed {
			logger.Error("certificate failed", "name", failure.Name, "file-type", failure.Type, "error", failure.Err)
		}

		for _, failure := range r.ActionFailed {
			logger.Error("action failed", "name", failure.Name, "error", failure.Err)
		}
	}
}

// HasFailures reports whether anything in the run went wrong.
//
// A suppressed action is not a failure, so ActionSkipped is not consulted.
func (r *RunResult) HasFailures() bool {
	return len(r.Failed) > 0 || len(r.ActionFailed) > 0
}

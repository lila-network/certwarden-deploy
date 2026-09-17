package certificates

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
)

// TestLogSummaryReportsMixedRun covers the shape of the record an operator
// actually reads: every count present, and one detail line per failure.
func TestLogSummaryReportsMixedRun(t *testing.T) {
	t.Cleanup(func() {
		configuration.QuietLogging = false
		configuration.DryRun = false
	})

	result := RunResult{
		New:           []string{"new-one.example.com", "new-two.example.com"},
		Unchanged:     []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"},
		Failed:        []CertFailure{{Name: "api.example.com", Type: KeyFile, Err: errors.New("API-Key invalid")}},
		ActionSkipped: []string{"skipped.example.com"},
	}

	var logs bytes.Buffer
	result.LogSummary(capturingLogger(&logs))

	summary := findLogLine(t, logs.String(), summaryMessage)

	for _, want := range []string{
		"level=INFO",
		"new=2",
		"changed=0",
		"unchanged=5",
		"failed=1",
		"action_failed=0",
		"action_skipped=1",
		"total=8",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected %q in the summary record, got: %s", want, summary)
		}
	}

	failure := findLogLine(t, logs.String(), "certificate failed")
	for _, want := range []string{
		"level=ERROR",
		"name=api.example.com",
		"file-type=key",
		`error="API-Key invalid"`,
	} {
		if !strings.Contains(failure, want) {
			t.Fatalf("expected %q in the failure record, got: %s", want, failure)
		}
	}
}

func TestLogSummaryReportsActionFailures(t *testing.T) {
	t.Cleanup(func() {
		configuration.QuietLogging = false
		configuration.DryRun = false
	})

	result := RunResult{
		Changed:      []string{"example.com"},
		ActionFailed: []ActionFailure{{Name: "example.com", Err: errors.New("exit status 7")}},
	}

	var logs bytes.Buffer
	result.LogSummary(capturingLogger(&logs))

	if summary := findLogLine(t, logs.String(), summaryMessage); !strings.Contains(summary, "action_failed=1") {
		t.Fatalf("expected action_failed=1 in the summary, got: %s", summary)
	}

	failure := findLogLine(t, logs.String(), "action failed")
	if !strings.Contains(failure, "level=ERROR") || !strings.Contains(failure, "name=example.com") {
		t.Fatalf("unexpected action failure record: %s", failure)
	}
}

// TestLogSummaryCountsZeroesExplicitly keeps the field set stable: a summary
// that drops its zeroes cannot be parsed or alerted on reliably.
func TestLogSummaryCountsZeroesExplicitly(t *testing.T) {
	t.Cleanup(func() {
		configuration.QuietLogging = false
		configuration.DryRun = false
	})

	var logs bytes.Buffer
	(&RunResult{}).LogSummary(capturingLogger(&logs))

	summary := findLogLine(t, logs.String(), summaryMessage)
	for _, want := range []string{
		"new=0", "changed=0", "unchanged=0", "failed=0",
		"action_failed=0", "action_skipped=0", "total=0",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("expected %q in an empty run summary, got: %s", want, summary)
		}
	}
}

func TestLogSummaryPrefixesDryRun(t *testing.T) {
	t.Cleanup(func() { configuration.DryRun = false })
	configuration.DryRun = true

	var logs bytes.Buffer
	(&RunResult{Unchanged: []string{"example.com"}}).LogSummary(capturingLogger(&logs))

	if !strings.Contains(logs.String(), "DRY-RUN: "+summaryMessage) {
		t.Fatalf("expected the summary to be marked as a dry run, got:\n%s", logs.String())
	}
}

// TestLogSummaryRepeatsSummaryAtErrorWhenQuietAndFailing is the --quiet
// contract: silent when everything worked, loud when it did not.
func TestLogSummaryRepeatsSummaryAtErrorWhenQuietAndFailing(t *testing.T) {
	t.Cleanup(func() { configuration.QuietLogging = false })
	configuration.QuietLogging = true

	failing := RunResult{
		Changed: []string{"example.com"},
		Failed:  []CertFailure{{Name: "broken.example.com", Type: CertificateFile, Err: errors.New("boom")}},
	}

	var logs bytes.Buffer
	failing.LogSummary(capturingLogger(&logs))

	var summaryLevels []string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "msg=\""+summaryMessage+"\"") {
			if strings.Contains(line, "level=ERROR") {
				summaryLevels = append(summaryLevels, "ERROR")
			}
			if strings.Contains(line, "level=INFO") {
				summaryLevels = append(summaryLevels, "INFO")
			}
		}
	}

	// Both records are emitted; the Info one is what a non-quiet handler shows
	// and the Error one is what survives --quiet.
	if len(summaryLevels) != 2 {
		t.Fatalf("expected the summary at both INFO and ERROR, got %v in:\n%s", summaryLevels, logs.String())
	}

	// A successful quiet run must not produce an Error record at all.
	logs.Reset()
	(&RunResult{Unchanged: []string{"example.com"}}).LogSummary(capturingLogger(&logs))

	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("expected no error records for a successful quiet run, got:\n%s", logs.String())
	}
}

func TestRunResultHasFailures(t *testing.T) {
	tests := []struct {
		name   string
		result RunResult
		want   bool
	}{
		{name: "empty", result: RunResult{}, want: false},
		{name: "successes only", result: RunResult{New: []string{"a"}, Unchanged: []string{"b"}}, want: false},
		{name: "skipped action is not a failure", result: RunResult{ActionSkipped: []string{"a"}}, want: false},
		{name: "certificate failure", result: RunResult{Failed: []CertFailure{{Name: "a"}}}, want: true},
		{name: "action failure", result: RunResult{ActionFailed: []ActionFailure{{Name: "a"}}}, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.result.HasFailures(); got != tc.want {
				t.Fatalf("HasFailures() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunResultTotalCountsCertificatesOnce(t *testing.T) {
	result := RunResult{
		New:          []string{"a"},
		Changed:      []string{"b"},
		Unchanged:    []string{"c", "d"},
		Failed:       []CertFailure{{Name: "e"}},
		ActionFailed: []ActionFailure{{Name: "b"}},
	}

	// b is changed and had a failing action, but it is still one certificate.
	if got := result.Total(); got != 5 {
		t.Fatalf("Total() = %d, want 5", got)
	}
}

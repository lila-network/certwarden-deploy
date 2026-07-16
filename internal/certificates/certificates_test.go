package certificates

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/lila-network/certwarden-deploy/internal/constants"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// capturingLogger returns a logger that writes every level down to Debug into buf.
func capturingLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// writeActionScript writes an executable /bin/sh script and returns its path.
func writeActionScript(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "action.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatalf("failed to write action script: %v", err)
	}

	return path
}

// findLogLine returns the first logged line containing substr.
func findLogLine(t *testing.T, logs string, substr string) string {
	t.Helper()

	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}

	t.Fatalf("no log line containing %q found in:\n%s", substr, logs)
	return ""
}

func TestWriteToDiskCreatesParentDirectories(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
	})
	configuration.DryRun = false

	target := filepath.Join(t.TempDir(), "nested", "cert.pem")
	cert := GenericCertificate{
		FilePath:    target,
		serverBytes: []byte("certificate-data"),
	}

	if err := cert.writeToDisk(testLogger()); err != nil {
		t.Fatalf("writeToDisk returned error: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	if string(data) != "certificate-data" {
		t.Fatalf("unexpected file contents: got %q", string(data))
	}
}

func TestWriteToDiskPreservesExistingPermissions(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
	})
	configuration.DryRun = false

	target := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(target, []byte("old-data"), 0600); err != nil {
		t.Fatalf("failed to seed file: %v", err)
	}

	cert := GenericCertificate{
		FilePath:    target,
		serverBytes: []byte("new-data"),
	}

	if err := cert.writeToDisk(testLogger()); err != nil {
		t.Fatalf("writeToDisk returned error: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("failed to stat written file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected file mode: got %o want %o", info.Mode().Perm(), 0600)
	}
}

func TestFetchFromServerUsesConfiguredEndpointAndHeader(t *testing.T) {
	logger := testLogger()
	var requestedPath string
	var apiKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		apiKey = r.Header.Get(constants.ApiKeyHeaderName)
		_, _ = w.Write([]byte("server-bytes"))
	}))
	defer server.Close()

	cert := GenericCertificate{
		Name:   "example.com",
		Secret: "top-secret",
		Type:   CertificateFile,
	}

	if err := cert.fetchFromServer(logger, server.URL, false); err != nil {
		t.Fatalf("fetchFromServer returned error: %v", err)
	}

	if requestedPath != constants.CertificateApiPath+"example.com" {
		t.Fatalf("unexpected request path: got %q", requestedPath)
	}

	if apiKey != "top-secret" {
		t.Fatalf("unexpected api key: got %q", apiKey)
	}

	if string(cert.serverBytes) != "server-bytes" {
		t.Fatalf("unexpected response body: got %q", string(cert.serverBytes))
	}
}

func TestFetchFromServerRejectsUnknownFileType(t *testing.T) {
	cert := GenericCertificate{
		Name: "example.com",
		Type: FileType(99),
	}

	if err := cert.fetchFromServer(testLogger(), "https://example.com", false); err == nil {
		t.Fatal("expected error for unsupported file type")
	}
}

func TestHandleCertificateActionIgnoresWhitespaceAndRunsCommand(t *testing.T) {
	target := filepath.Join(t.TempDir(), "action-ran")
	action := "   /usr/bin/touch   " + target + "   "

	if err := handleCertificateAction(testLogger(), action); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected action output file to exist: %v", err)
	}
}

func TestHandleCertificateActionWhitespaceOnlyIsNoop(t *testing.T) {
	if err := handleCertificateAction(testLogger(), "   "); err != nil {
		t.Fatalf("expected whitespace-only action to be ignored, got error: %v", err)
	}
}

func TestHandleCertificateActionLogsStderrAndExitCodeOnFailure(t *testing.T) {
	script := writeActionScript(t, "echo boom >&2\nexit 3\n")

	var buf bytes.Buffer
	if err := handleCertificateAction(capturingLogger(&buf), script); err == nil {
		t.Fatal("expected error for failing action")
	}

	logs := buf.String()

	stderrLine := findLogLine(t, logs, "stderr=boom")
	if !strings.Contains(stderrLine, "level=ERROR") {
		t.Fatalf("expected stderr to be logged at ERROR, got: %s", stderrLine)
	}

	failureLine := findLogLine(t, logs, "Post-rollout action failed")
	if !strings.Contains(failureLine, "exit-code=3") {
		t.Fatalf("expected exit-code field on failure, got: %s", failureLine)
	}
	if !strings.Contains(failureLine, "level=ERROR") {
		t.Fatalf("expected failure to be logged at ERROR, got: %s", failureLine)
	}

	if !strings.Contains(logs, "Executing post-rollout action") {
		t.Fatalf("expected the command to be logged before running, got:\n%s", logs)
	}
}

func TestHandleCertificateActionLogsStdoutAtDebugOnSuccess(t *testing.T) {
	script := writeActionScript(t, "echo reloaded\n")

	var buf bytes.Buffer
	if err := handleCertificateAction(capturingLogger(&buf), script); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	logs := buf.String()

	stdoutLine := findLogLine(t, logs, "stdout=reloaded")
	if !strings.Contains(stdoutLine, "level=DEBUG") {
		t.Fatalf("expected stdout to be logged at DEBUG, got: %s", stdoutLine)
	}

	if strings.Contains(logs, "level=ERROR") {
		t.Fatalf("expected no error logs for a successful action, got:\n%s", logs)
	}
}

func TestHandleCertificateActionLogsStderrOnSuccess(t *testing.T) {
	script := writeActionScript(t, "echo warning >&2\n")

	var buf bytes.Buffer
	if err := handleCertificateAction(capturingLogger(&buf), script); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	stderrLine := findLogLine(t, buf.String(), "stderr=warning")
	if !strings.Contains(stderrLine, "level=ERROR") {
		t.Fatalf("expected stderr on exit 0 to be logged at ERROR, got: %s", stderrLine)
	}
}

func TestHandleCertificateActionTruncatesOutputAtCap(t *testing.T) {
	payload := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(payload, bytes.Repeat([]byte("a"), maxActionOutputBytes+4096), 0644); err != nil {
		t.Fatalf("failed to write payload: %v", err)
	}

	script := writeActionScript(t, "cat "+payload+" >&2\nexit 1\n")

	var buf bytes.Buffer
	if err := handleCertificateAction(capturingLogger(&buf), script); err == nil {
		t.Fatal("expected error for failing action")
	}

	logs := buf.String()
	if !strings.Contains(logs, actionOutputTruncationMarker) {
		t.Fatal("expected captured stderr to be marked as truncated")
	}

	// the payload is the only long run of "a" in the logs, so the longest run is what got captured
	longestRun, currentRun := 0, 0
	for _, r := range logs {
		if r == 'a' {
			currentRun++
			if currentRun > longestRun {
				longestRun = currentRun
			}
			continue
		}
		currentRun = 0
	}

	if longestRun != maxActionOutputBytes {
		t.Fatalf("unexpected amount of captured stderr: got %d bytes want %d", longestRun, maxActionOutputBytes)
	}
}

func TestBoundedBufferStopsAtLimit(t *testing.T) {
	b := &boundedBuffer{limit: 4}

	n, err := b.Write([]byte("abc"))
	if err != nil || n != 3 {
		t.Fatalf("unexpected write result: n=%d err=%v", n, err)
	}

	// second write crosses the limit and must be reported as fully written
	n, err = b.Write([]byte("defg"))
	if err != nil || n != 4 {
		t.Fatalf("unexpected write result: n=%d err=%v", n, err)
	}

	// a write beyond the limit is dropped entirely
	if _, err := b.Write([]byte("hij")); err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	if got, want := b.String(), "abcd"+actionOutputTruncationMarker; got != want {
		t.Fatalf("unexpected buffer contents: got %q want %q", got, want)
	}
}

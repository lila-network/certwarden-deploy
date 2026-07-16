package certificates

import (
	"bytes"
	"errors"
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

func TestRunResultExitCodePrecedence(t *testing.T) {
	certErr := errors.New("cert boom")
	actionErr := errors.New("action boom")

	tests := []struct {
		name   string
		result RunResult
		want   int
	}{
		{
			name:   "empty run succeeds",
			result: RunResult{},
			want:   ExitSuccess,
		},
		{
			name: "only successes",
			result: RunResult{
				Changed:   []string{"example.com"},
				Unchanged: []string{"example.org"},
			},
			want: ExitSuccess,
		},
		{
			name: "certificate failure",
			result: RunResult{
				Changed: []string{"example.com"},
				Failed:  []CertFailure{{Name: "example.org", Type: KeyFile, Err: certErr}},
			},
			want: ExitCertificateFailure,
		},
		{
			name: "action failure only",
			result: RunResult{
				Changed:      []string{"example.com"},
				ActionFailed: []ActionFailure{{Name: "example.com", Err: actionErr}},
			},
			want: ExitActionFailure,
		},
		{
			name: "certificate failure outranks action failure",
			result: RunResult{
				Failed:       []CertFailure{{Name: "example.org", Type: CertificateFile, Err: certErr}},
				ActionFailed: []ActionFailure{{Name: "example.com", Err: actionErr}},
			},
			want: ExitCertificateFailure,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.result.ExitCode(); got != tc.want {
				t.Fatalf("unexpected exit code: got %d want %d", got, tc.want)
			}
		})
	}
}

func TestHandleCertificatesRecordsFailuresAndContinues(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "broken.example.com") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("body-" + filepath.Base(r.URL.Path)))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	config := &configuration.ConfigFileData{
		BaseURL: server.URL,
		Certificates: []configuration.CertificateData{
			{
				Name:              "broken.example.com",
				CertificateSecret: "secret",
				CertificatePath:   filepath.Join(tmpDir, "broken-cert.pem"),
			},
			{
				Name:              "good.example.com",
				CertificateSecret: "secret",
				CertificatePath:   filepath.Join(tmpDir, "good-cert.pem"),
			},
		},
	}

	result := HandleCertificates(testLogger(), config)

	if len(result.Failed) != 1 {
		t.Fatalf("unexpected failure count: got %d want 1 (%v)", len(result.Failed), result.Failed)
	}

	if result.Failed[0].Name != "broken.example.com" {
		t.Fatalf("unexpected failed certificate name: got %q", result.Failed[0].Name)
	}

	if result.Failed[0].Type != CertificateFile {
		t.Fatalf("unexpected failed file type: got %v", result.Failed[0].Type)
	}

	if result.Failed[0].Err == nil {
		t.Fatal("expected failure to carry an error")
	}

	// The broken certificate must not stop the healthy one behind it.
	if len(result.Changed) != 1 || result.Changed[0] != "good.example.com" {
		t.Fatalf("unexpected changed certificates: got %v", result.Changed)
	}

	if len(result.New) != 0 {
		t.Fatalf("New is expected to stay empty until #31: got %v", result.New)
	}

	if result.ExitCode() != ExitCertificateFailure {
		t.Fatalf("unexpected exit code: got %d want %d", result.ExitCode(), ExitCertificateFailure)
	}

	assertFileExists(t, config.Certificates[1].CertificatePath)
}

func TestHandleCertificatesReportsUnchangedOnSecondRun(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("stable-body"))
	}))
	defer server.Close()

	config := &configuration.ConfigFileData{
		BaseURL: server.URL,
		Certificates: []configuration.CertificateData{
			{
				Name:              "example.com",
				CertificateSecret: "secret",
				CertificatePath:   filepath.Join(t.TempDir(), "cert.pem"),
			},
		},
	}

	first := HandleCertificates(testLogger(), config)
	if len(first.Changed) != 1 {
		t.Fatalf("expected certificate to be reported as changed: got %v", first.Changed)
	}

	second := HandleCertificates(testLogger(), config)
	if len(second.Unchanged) != 1 || second.Unchanged[0] != "example.com" {
		t.Fatalf("expected certificate to be reported as unchanged: got %v", second.Unchanged)
	}

	if second.ExitCode() != ExitSuccess {
		t.Fatalf("unexpected exit code: got %d want %d", second.ExitCode(), ExitSuccess)
	}
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file %s to exist: %v", path, err)
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

func TestFetchFromServerSurfacesErrorBodyOnNonSuccess(t *testing.T) {
	var logs bytes.Buffer
	logger := capturingLogger(&logs)
	const responseBody = `{"error":"certificate not found: no such certificate name"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	cert := GenericCertificate{Name: "example.com", Type: CertificateFile}

	err := cert.fetchFromServer(logger, server.URL, false)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}

	if !strings.Contains(err.Error(), "certificate not found: no such certificate name") {
		t.Fatalf("expected server body in returned error, got %q", err.Error())
	}

	if !strings.Contains(logs.String(), "certificate not found: no such certificate name") {
		t.Fatalf("expected server body in log output, got %q", logs.String())
	}
}

func TestFetchFromServerSurfacesErrorBodyOnUnauthorized(t *testing.T) {
	var logs bytes.Buffer
	logger := capturingLogger(&logs)
	const responseBody = `{"error":"api key is expired"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	cert := GenericCertificate{Name: "example.com", Type: KeyFile}

	err := cert.fetchFromServer(logger, server.URL, false)
	if err == nil {
		t.Fatal("expected error for 401 response")
	}

	if !strings.Contains(err.Error(), "api key is expired") {
		t.Fatalf("expected server body in returned error, got %q", err.Error())
	}

	if !strings.Contains(logs.String(), "api key is expired") {
		t.Fatalf("expected server body in log output, got %q", logs.String())
	}
}

// TestFetchFromServerNeverLogsSuccessBody guards the security property that key
// material returned on a success response is never written to the log.
func TestFetchFromServerNeverLogsSuccessBody(t *testing.T) {
	var logs bytes.Buffer
	logger := capturingLogger(&logs)
	const privateKey = "-----BEGIN PRIVATE KEY-----\n" +
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQSUPERSECRETKEY\n" +
		"MATERIALMUSTNEVERAPPEARINTHEJOURNALZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n" +
		"-----END PRIVATE KEY-----\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(privateKey))
	}))
	defer server.Close()

	cert := GenericCertificate{Name: "example.com", Type: KeyFile}

	if err := cert.fetchFromServer(logger, server.URL, false); err != nil {
		t.Fatalf("fetchFromServer returned error: %v", err)
	}

	if string(cert.serverBytes) != privateKey {
		t.Fatalf("unexpected response body: got %q", string(cert.serverBytes))
	}

	for _, secret := range []string{
		"SUPERSECRETKEY",
		"MATERIALMUSTNEVERAPPEARINTHEJOURNAL",
		"BEGIN PRIVATE KEY",
	} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("success response body leaked into log output: %q", logs.String())
		}
	}
}

func TestFetchFromServerOmitsNonTextualErrorBody(t *testing.T) {
	var logs bytes.Buffer
	logger := capturingLogger(&logs)
	const responseBody = "binary-blob-should-not-be-logged"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	cert := GenericCertificate{Name: "example.com", Type: CertificateFile}

	err := cert.fetchFromServer(logger, server.URL, false)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	if strings.Contains(err.Error(), responseBody) {
		t.Fatalf("expected non-textual body to be omitted from error, got %q", err.Error())
	}

	if strings.Contains(logs.String(), responseBody) {
		t.Fatalf("expected non-textual body to be omitted from log output, got %q", logs.String())
	}

	if strings.Contains(logs.String(), "response-body") {
		t.Fatalf("expected response-body field to be omitted entirely, got %q", logs.String())
	}
}

func TestFetchFromServerTruncatesLargeErrorBody(t *testing.T) {
	var logs bytes.Buffer
	logger := capturingLogger(&logs)
	responseBody := strings.Repeat("A", maxLoggedBodyBytes+1000)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	cert := GenericCertificate{Name: "example.com", Type: CertificateFile}

	err := cert.fetchFromServer(logger, server.URL, false)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}

	if !strings.Contains(err.Error(), strings.Repeat("A", maxLoggedBodyBytes)) {
		t.Fatalf("expected body prefix up to the cap in error, got %q", err.Error())
	}

	if strings.Contains(err.Error(), strings.Repeat("A", maxLoggedBodyBytes+1)) {
		t.Fatal("expected body to be truncated at the cap")
	}

	if !strings.Contains(err.Error(), "[truncated]") {
		t.Fatalf("expected truncation marker in error, got %q", err.Error())
	}

	if !strings.Contains(logs.String(), "[truncated]") {
		t.Fatalf("expected truncation marker in log output, got %q", logs.String())
	}
}

// TestErrorBodyForLogCollapsesWhitespace ensures a multi-line upstream error
// cannot break the log record across several lines.
func TestErrorBodyForLogCollapsesWhitespace(t *testing.T) {
	var logs bytes.Buffer
	logger := capturingLogger(&logs)
	const responseBody = "certificate is not\n\tyet issued\r\n\nretry later\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	cert := GenericCertificate{Name: "example.com", Type: CertificateFile}

	err := cert.fetchFromServer(logger, server.URL, false)
	if err == nil {
		t.Fatal("expected error for 409 response")
	}

	if !strings.Contains(err.Error(), "certificate is not yet issued retry later") {
		t.Fatalf("expected collapsed body in error, got %q", err.Error())
	}

	// the whole body must sit on the single log record line, not spill over it
	var record string
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "failed to get data from server") {
			record = line
			break
		}
	}

	if record == "" {
		t.Fatalf("expected an error log record, got %q", logs.String())
	}

	if !strings.Contains(record, "certificate is not yet issued retry later") {
		t.Fatalf("expected collapsed body on a single log record line, got %q", record)
	}
}

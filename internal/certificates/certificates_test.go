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
	"slices"
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

func TestWriteTempFileCreatesParentDirectories(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
	})
	configuration.DryRun = false

	target := filepath.Join(t.TempDir(), "nested", "cert.pem")
	cert := GenericCertificate{
		FilePath:    target,
		serverBytes: []byte("certificate-data"),
	}

	if err := cert.writeTempFile(testLogger()); err != nil {
		t.Fatalf("writeTempFile returned error: %v", err)
	}

	if err := cert.Commit(testLogger()); err != nil {
		t.Fatalf("Commit returned error: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	if string(data) != "certificate-data" {
		t.Fatalf("unexpected file contents: got %q", string(data))
	}
}

func TestWriteTempFilePreservesExistingPermissions(t *testing.T) {
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

	if err := cert.writeTempFile(testLogger()); err != nil {
		t.Fatalf("writeTempFile returned error: %v", err)
	}

	if err := cert.Commit(testLogger()); err != nil {
		t.Fatalf("Commit returned error: %v", err)
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

	if err := handleCertificateAction(testLogger(), configuration.ShellAction(action)); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected action output file to exist: %v", err)
	}
}

func TestHandleCertificateActionWhitespaceOnlyIsNoop(t *testing.T) {
	if err := handleCertificateAction(testLogger(), configuration.ShellAction("   ")); err != nil {
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
	if err := handleCertificateAction(capturingLogger(&buf), configuration.ShellAction(script)); err == nil {
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
	if err := handleCertificateAction(capturingLogger(&buf), configuration.ShellAction(script)); err != nil {
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
	if err := handleCertificateAction(capturingLogger(&buf), configuration.ShellAction(script)); err != nil {
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
	if err := handleCertificateAction(capturingLogger(&buf), configuration.ShellAction(script)); err == nil {
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

// startArtefactServer serves one body per artefact type. A type missing from
// bodies is answered with 500, which is how a mid-sequence fetch failure is
// injected into an otherwise healthy certificate.
func startArtefactServer(t *testing.T, bodies map[FileType]string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var fileType FileType

		switch {
		case strings.HasPrefix(r.URL.Path, constants.CertificateApiPath):
			fileType = CertificateFile
		case strings.HasPrefix(r.URL.Path, constants.KeyApiPath):
			fileType = KeyFile
		case strings.HasPrefix(r.URL.Path, constants.CaCertificateApiPath):
			fileType = CaCertificateFile
		default:
			http.NotFound(w, r)
			return
		}

		body, ok := bodies[fileType]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return server
}

// seedFile writes a file that is already on disk when the run starts.
func seedFile(t *testing.T, path string, content string, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("failed to seed file %s: %v", path, err)
	}

	// WriteFile honours the umask, so force the mode we asked for
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("failed to chmod seeded file %s: %v", path, err)
	}
}

// assertFileContents compares a file byte for byte, which is the whole point of
// the #28 guards: "the file is still there" is not good enough, it has to be
// the same bytes as before the failed run.
func assertFileContents(t *testing.T, path string, want string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}

	if string(data) != want {
		t.Fatalf("unexpected contents of %s: got %q want %q", path, string(data), want)
	}
}

// assertNoTempFiles fails if an aborted rollout left staged files behind.
func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()

	leftovers, err := filepath.Glob(filepath.Join(dir, tempFilePattern))
	if err != nil {
		t.Fatalf("failed to glob for temporary files: %v", err)
	}

	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind in %s: %v", dir, leftovers)
	}
}

// assertSingleFailure checks that exactly one artefact of one certificate was
// recorded as failed, and that the run reports the certificate failure exit code.
func assertSingleFailure(t *testing.T, result RunResult, name string, fileType FileType) {
	t.Helper()

	if len(result.Failed) != 1 {
		t.Fatalf("unexpected failure count: got %d want 1 (%v)", len(result.Failed), result.Failed)
	}

	if result.Failed[0].Name != name {
		t.Fatalf("unexpected failed certificate name: got %q want %q", result.Failed[0].Name, name)
	}

	if result.Failed[0].Type != fileType {
		t.Fatalf("unexpected failed file type: got %v want %v", result.Failed[0].Type, fileType)
	}

	if result.Failed[0].Err == nil {
		t.Fatal("expected failure to carry an error")
	}

	if result.ExitCode() != ExitCertificateFailure {
		t.Fatalf("unexpected exit code: got %d want %d", result.ExitCode(), ExitCertificateFailure)
	}
}

// certConfig builds a config for a single certificate whose artefacts live in dir.
func certConfig(baseURL string, dir string, name string) *configuration.ConfigFileData {
	return &configuration.ConfigFileData{
		BaseURL: baseURL,
		Certificates: []configuration.CertificateData{
			{
				Name:              name,
				CertificateSecret: "cert-secret",
				CertificatePath:   filepath.Join(dir, "cert.pem"),
				KeySecret:         "key-secret",
				KeyPath:           filepath.Join(dir, "key.pem"),
				CaPath:            filepath.Join(dir, "ca.pem"),
			},
		},
	}
}

// TestHandleCertificatesKeepsOldCertificateWhenKeyFetchFails is the regression
// guard for #28.
//
// A certificate and its key only work as a pair. Rolling the certificate out on
// its own and then failing on the key used to leave the new certificate next to
// the old, non-matching key: nothing broke during that run, because nothing
// reloaded, but the next unrelated restart of the TLS server hours or days
// later picked up the mismatched pair and fell over.
//
// So when the key cannot be fetched, the certificate on disk must still be the
// old one, byte for byte.
func TestHandleCertificatesKeepsOldCertificateWhenKeyFetchFails(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})

	const oldCert = "old-cert-body"
	const oldKey = "old-key-body-matching-old-cert"

	// the key is missing from the served artefacts, so it answers 500
	server := startArtefactServer(t, map[FileType]string{
		CertificateFile:   "new-cert-body",
		CaCertificateFile: "new-ca-body",
	})

	dir := t.TempDir()
	config := certConfig(server.URL, dir, "example.com")
	certPath := config.Certificates[0].CertificatePath
	keyPath := config.Certificates[0].KeyPath

	seedFile(t, certPath, oldCert, 0644)
	seedFile(t, keyPath, oldKey, 0600)

	result := HandleCertificates(testLogger(), config)

	// the actual point of #28: the pair on disk is still the matching old one
	assertFileContents(t, certPath, oldCert)
	assertFileContents(t, keyPath, oldKey)

	if _, err := os.Stat(config.Certificates[0].CaPath); !os.IsNotExist(err) {
		t.Fatalf("expected CA to not be deployed either, got err=%v", err)
	}

	assertSingleFailure(t, result, "example.com", KeyFile)
	assertNoTempFiles(t, dir)

	if len(result.Changed) != 0 {
		t.Fatalf("expected no certificate to be reported as changed: got %v", result.Changed)
	}
}

// TestHandleCertificatesKeepsOldCertificateAndKeyWhenCaFetchFails generalises
// the guard above to a failure in the last artefact: the two that were fetched
// successfully before it must not be published either.
func TestHandleCertificatesKeepsOldCertificateAndKeyWhenCaFetchFails(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})

	const oldCert = "old-cert-body"
	const oldKey = "old-key-body"
	const oldCa = "old-ca-body"

	server := startArtefactServer(t, map[FileType]string{
		CertificateFile: "new-cert-body",
		KeyFile:         "new-key-body",
	})

	dir := t.TempDir()
	config := certConfig(server.URL, dir, "example.com")

	seedFile(t, config.Certificates[0].CertificatePath, oldCert, 0644)
	seedFile(t, config.Certificates[0].KeyPath, oldKey, 0600)
	seedFile(t, config.Certificates[0].CaPath, oldCa, 0644)

	result := HandleCertificates(testLogger(), config)

	assertFileContents(t, config.Certificates[0].CertificatePath, oldCert)
	assertFileContents(t, config.Certificates[0].KeyPath, oldKey)
	assertFileContents(t, config.Certificates[0].CaPath, oldCa)

	assertSingleFailure(t, result, "example.com", CaCertificateFile)
	assertNoTempFiles(t, dir)
}

// TestHandleCertificatesLeavesNoTemporaryFilesOnAbort makes sure an aborted
// rollout cleans up after itself: the certificate and CA were fully staged
// before the key failed, and both staged files have to be gone afterwards.
func TestHandleCertificatesLeavesNoTemporaryFilesOnAbort(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})

	server := startArtefactServer(t, map[FileType]string{
		CertificateFile:   "new-cert-body",
		CaCertificateFile: "new-ca-body",
	})

	dir := t.TempDir()
	config := certConfig(server.URL, dir, "example.com")

	result := HandleCertificates(testLogger(), config)

	assertSingleFailure(t, result, "example.com", KeyFile)
	assertNoTempFiles(t, dir)

	// nothing at all was published for this certificate
	for _, path := range []string{
		config.Certificates[0].CertificatePath,
		config.Certificates[0].KeyPath,
		config.Certificates[0].CaPath,
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be absent after an aborted rollout, got err=%v", path, err)
		}
	}
}

// TestHandleCertificatesFailedCertificateDoesNotBlockNextOne pins the "record,
// do not abort" behaviour to the two-phase rollout: a certificate that aborts
// must not keep the next one from being committed.
func TestHandleCertificatesFailedCertificateDoesNotBlockNextOne(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "broken.example.com") && strings.HasPrefix(r.URL.Path, constants.KeyApiPath) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("body-" + filepath.Base(r.URL.Path)))
	}))
	defer server.Close()

	brokenDir := t.TempDir()
	healthyDir := t.TempDir()

	broken := certConfig(server.URL, brokenDir, "broken.example.com")
	healthy := certConfig(server.URL, healthyDir, "healthy.example.com")
	config := &configuration.ConfigFileData{
		BaseURL:      server.URL,
		Certificates: []configuration.CertificateData{broken.Certificates[0], healthy.Certificates[0]},
	}

	result := HandleCertificates(testLogger(), config)

	assertSingleFailure(t, result, "broken.example.com", KeyFile)
	assertNoTempFiles(t, brokenDir)
	assertNoTempFiles(t, healthyDir)

	if len(result.Changed) != 1 || result.Changed[0] != "healthy.example.com" {
		t.Fatalf("unexpected changed certificates: got %v", result.Changed)
	}

	assertFileContents(t, healthy.Certificates[0].CertificatePath, "body-healthy.example.com")
	assertFileContents(t, healthy.Certificates[0].KeyPath, "body-healthy.example.com")
	assertFileContents(t, healthy.Certificates[0].CaPath, "body-healthy.example.com")
}

// TestHandleCertificatesDryRunStagesNothing checks that a dry run prepares and
// reports the rollout without touching the disk, and without leaving staged
// files behind.
func TestHandleCertificatesDryRunStagesNothing(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})
	configuration.DryRun = true

	const oldCert = "old-cert-body"

	server := startArtefactServer(t, map[FileType]string{
		CertificateFile:   "new-cert-body",
		KeyFile:           "new-key-body",
		CaCertificateFile: "new-ca-body",
	})

	dir := t.TempDir()
	config := certConfig(server.URL, dir, "example.com")
	seedFile(t, config.Certificates[0].CertificatePath, oldCert, 0644)

	result := HandleCertificates(testLogger(), config)

	assertFileContents(t, config.Certificates[0].CertificatePath, oldCert)
	assertNoTempFiles(t, dir)

	for _, path := range []string{config.Certificates[0].KeyPath, config.Certificates[0].CaPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be absent after a dry run, got err=%v", path, err)
		}
	}

	// a dry run still reports what it would have done
	if len(result.Changed) != 1 || result.Changed[0] != "example.com" {
		t.Fatalf("expected the dry run to report the certificate as changed: got %v", result.Changed)
	}

	if result.ExitCode() != ExitSuccess {
		t.Fatalf("unexpected exit code: got %d want %d", result.ExitCode(), ExitSuccess)
	}
}

// TestHandleCertificatesForceDeploysUnchangedCertificate checks that --force
// still commits identical content and still triggers the action.
func TestHandleCertificatesForceDeploysUnchangedCertificate(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})

	bodies := map[FileType]string{
		CertificateFile:   "stable-cert-body",
		KeyFile:           "stable-key-body",
		CaCertificateFile: "stable-ca-body",
	}
	server := startArtefactServer(t, bodies)

	dir := t.TempDir()
	config := certConfig(server.URL, dir, "example.com")

	// seed exactly what the server serves, so nothing needs a rollout
	seedFile(t, config.Certificates[0].CertificatePath, bodies[CertificateFile], 0644)
	seedFile(t, config.Certificates[0].KeyPath, bodies[KeyFile], 0600)
	seedFile(t, config.Certificates[0].CaPath, bodies[CaCertificateFile], 0644)

	marker := filepath.Join(t.TempDir(), "action-ran")
	config.Certificates[0].Action = configuration.ShellAction("/usr/bin/touch " + marker)

	withoutForce := HandleCertificates(testLogger(), config)
	if len(withoutForce.Unchanged) != 1 {
		t.Fatalf("expected the certificate to be reported as unchanged: got %v", withoutForce.Unchanged)
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("expected no action to run without --force, got err=%v", err)
	}

	configuration.Force = true
	forced := HandleCertificates(testLogger(), config)

	if len(forced.Changed) != 1 || forced.Changed[0] != "example.com" {
		t.Fatalf("expected --force to report the certificate as changed: got %v", forced.Changed)
	}

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected --force to run the action: %v", err)
	}

	assertFileContents(t, config.Certificates[0].CertificatePath, bodies[CertificateFile])
	assertFileContents(t, config.Certificates[0].KeyPath, bodies[KeyFile])
	assertNoTempFiles(t, dir)
}

// TestHandleCertificatesPreservesFileModeAcrossRollout guards that going
// through a temporary file does not widen the permissions of a private key.
func TestHandleCertificatesPreservesFileModeAcrossRollout(t *testing.T) {
	t.Cleanup(func() {
		configuration.DryRun = false
		configuration.Force = false
	})

	server := startArtefactServer(t, map[FileType]string{
		CertificateFile:   "new-cert-body",
		KeyFile:           "new-key-body",
		CaCertificateFile: "new-ca-body",
	})

	dir := t.TempDir()
	config := certConfig(server.URL, dir, "example.com")

	seedFile(t, config.Certificates[0].CertificatePath, "old-cert-body", 0644)
	seedFile(t, config.Certificates[0].KeyPath, "old-key-body", 0600)

	result := HandleCertificates(testLogger(), config)

	if len(result.Failed) != 0 {
		t.Fatalf("unexpected failures: %v", result.Failed)
	}

	assertFileContents(t, config.Certificates[0].KeyPath, "new-key-body")
	assertFileMode(t, config.Certificates[0].KeyPath, 0600)
	assertFileContents(t, config.Certificates[0].CertificatePath, "new-cert-body")
	assertFileMode(t, config.Certificates[0].CertificatePath, 0644)
	assertNoTempFiles(t, dir)
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat %s: %v", path, err)
	}

	if info.Mode().Perm() != want {
		t.Fatalf("unexpected mode of %s: got %o want %o", path, info.Mode().Perm(), want)
	}
}

// TestHandleCertificateActionStringFormRunsPlainCommand pins the form every
// pre-existing config uses: a single command with simple arguments must keep
// working exactly as before.
func TestHandleCertificateActionStringFormRunsPlainCommand(t *testing.T) {
	target := filepath.Join(t.TempDir(), "plain-command-ran")

	if err := handleCertificateAction(testLogger(), configuration.ShellAction("/usr/bin/touch "+target)); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	assertFileExists(t, target)
}

// TestHandleCertificateActionStringFormChainsCommands is the regression guard
// for #29: before the shell was involved, "a && b" ran a with "&&" and "b" as
// literal arguments, so b never executed at all.
func TestHandleCertificateActionStringFormChainsCommands(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "chain")
	first := writeActionScript(t, "printf 'first\n' >> "+marker+"\n")
	second := writeActionScript(t, "printf 'second\n' >> "+marker+"\n")

	action := configuration.ShellAction(first + " && " + second)
	if err := handleCertificateAction(testLogger(), action); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	// Both ran, and in order: without a shell only the first script would have
	// executed, with "&&" and the second path handed to it as arguments.
	assertFileContents(t, marker, "first\nsecond\n")
}

// TestHandleCertificateActionStringFormHonoursQuoting proves an argument with
// spaces survives as a single argument when it is quoted, which was
// inexpressible while the action was split on whitespace.
func TestHandleCertificateActionStringFormHonoursQuoting(t *testing.T) {
	out := filepath.Join(t.TempDir(), "args")
	script := writeActionScript(t, "printf '%s\\n' \"$#\" \"$1\" > "+out+"\n")

	action := configuration.ShellAction(script + " 'cert renewed'")
	if err := handleCertificateAction(testLogger(), action); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	assertFileContents(t, out, "1\ncert renewed\n")
}

// TestHandleCertificateActionListFormExecsWithoutShell pins the list form: no
// shell means no operator handling, no variable expansion, and arguments that
// arrive byte-for-byte as configured.
func TestHandleCertificateActionListFormExecsWithoutShell(t *testing.T) {
	out := filepath.Join(t.TempDir(), "args")
	script := writeActionScript(t, "for arg in \"$@\"; do printf '%s\\n' \"$arg\" >> "+out+"; done\n")

	action := configuration.ExecAction(script, "cert renewed", "$HOME", "&&", "/usr/bin/touch /tmp/should-not-exist")
	if err := handleCertificateAction(testLogger(), action); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	assertFileContents(t, out, "cert renewed\n$HOME\n&&\n/usr/bin/touch /tmp/should-not-exist\n")
}

func TestHandleCertificateActionEmptyListIsNoop(t *testing.T) {
	if err := handleCertificateAction(testLogger(), configuration.ExecAction()); err != nil {
		t.Fatalf("expected an empty action list to be ignored, got error: %v", err)
	}
}

func TestActionCommandPicksExecutionMode(t *testing.T) {
	shell, runnable := actionCommand(configuration.ShellAction("systemctl reload nginx"))
	if !runnable {
		t.Fatal("expected the string form to be runnable")
	}

	wantShellArgs := []string{configuration.ShellPath, "-c", "systemctl reload nginx"}
	if !slices.Equal(shell.Args, wantShellArgs) {
		t.Fatalf("string form built %v, want %v", shell.Args, wantShellArgs)
	}

	list, runnable := actionCommand(configuration.ExecAction("/usr/bin/systemctl", "reload", "nginx"))
	if !runnable {
		t.Fatal("expected the list form to be runnable")
	}

	wantListArgs := []string{"/usr/bin/systemctl", "reload", "nginx"}
	if !slices.Equal(list.Args, wantListArgs) {
		t.Fatalf("list form built %v, want %v", list.Args, wantListArgs)
	}

	if _, runnable := actionCommand(configuration.ShellAction("  ")); runnable {
		t.Fatal("expected a blank action to be reported as not runnable")
	}
}

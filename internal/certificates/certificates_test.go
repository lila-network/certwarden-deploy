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

// capturingLogger returns a logger that records everything down to Debug level
// into the returned buffer.
func capturingLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})

	return slog.New(handler), buf
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

	if err := handleCertificateAction(action); err != nil {
		t.Fatalf("handleCertificateAction returned error: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected action output file to exist: %v", err)
	}
}

func TestHandleCertificateActionWhitespaceOnlyIsNoop(t *testing.T) {
	if err := handleCertificateAction("   "); err != nil {
		t.Fatalf("expected whitespace-only action to be ignored, got error: %v", err)
	}
}

func TestFetchFromServerSurfacesErrorBodyOnNonSuccess(t *testing.T) {
	logger, logs := capturingLogger()
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
	logger, logs := capturingLogger()
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
	logger, logs := capturingLogger()
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
	logger, logs := capturingLogger()
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
	logger, logs := capturingLogger()
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
	logger, logs := capturingLogger()
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

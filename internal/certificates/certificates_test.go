package certificates

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lila-network/certwarden-deploy/internal/configuration"
	"github.com/lila-network/certwarden-deploy/internal/constants"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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

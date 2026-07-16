package certificates

import (
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
